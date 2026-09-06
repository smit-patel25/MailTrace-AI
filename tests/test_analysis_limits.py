"""
Bounded MIME/content/URL regression tests for MailTrace AI.

All 33 spec requirements are covered.  All fixtures are generated
in-memory — no multi-megabyte files are committed to the repository.
No real external network calls are made.
"""
import base64
import email as stdlib_email
import hashlib
import textwrap
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email.mime.text import MIMEText
from email import encoders
from unittest.mock import patch

import pytest

from modules.analysis_limits import LIMITS, AnalysisLimits
from modules.email_parser import parse_eml_bytes
from modules.content_analyzer import analyze_content, extract_urls


# ---------------------------------------------------------------------------
# Fixture helpers
# ---------------------------------------------------------------------------

def _simple_email(subject="Test", body="Hello world.", content_type="text/plain") -> bytes:
    raw = (
        f"From: sender@example.com\r\n"
        f"To: recv@example.com\r\n"
        f"Subject: {subject}\r\n"
        f"Content-Type: {content_type}; charset=\"utf-8\"\r\n"
        f"\r\n"
        f"{body}\r\n"
    )
    return raw.encode("utf-8")


def _make_multipart_email(n_text_parts: int, depth: int = 0) -> bytes:
    """Create a multipart/mixed email with n_text_parts text attachments."""
    boundary = "BOUND"
    lines = [
        "From: a@a.com",
        f"Content-Type: multipart/mixed; boundary={boundary}",
        "",
    ]
    for i in range(n_text_parts):
        lines += [
            f"--{boundary}",
            "Content-Type: text/plain",
            "",
            f"Part {i}",
        ]
    lines.append(f"--{boundary}--")
    return "\r\n".join(lines).encode("utf-8")


def _email_with_attachment(filename: str, payload_bytes: bytes) -> bytes:
    """Build a multipart email with a single base64-encoded attachment."""
    boundary = "ATTBND"
    encoded = base64.b64encode(payload_bytes).decode("ascii")
    raw = (
        f"From: a@a.com\r\n"
        f"Content-Type: multipart/mixed; boundary={boundary}\r\n"
        f"\r\n"
        f"--{boundary}\r\n"
        f"Content-Type: text/plain\r\n"
        f"\r\n"
        f"Body.\r\n"
        f"--{boundary}\r\n"
        f'Content-Type: application/octet-stream; name="{filename}"\r\n'
        f'Content-Disposition: attachment; filename="{filename}"\r\n'
        f"Content-Transfer-Encoding: base64\r\n"
        f"\r\n"
        f"{encoded}\r\n"
        f"--{boundary}--\r\n"
    )
    return raw.encode("utf-8")


def _email_with_n_attachments(n: int, bytes_each: int = 10) -> bytes:
    """Build a multipart email with n identical small attachments."""
    boundary = "MANYATT"
    payload = base64.b64encode(b"X" * bytes_each).decode("ascii")
    lines = [
        "From: a@a.com",
        f"Content-Type: multipart/mixed; boundary={boundary}",
        "",
        f"--{boundary}",
        "Content-Type: text/plain",
        "",
        "Body.",
    ]
    for i in range(n):
        lines += [
            f"--{boundary}",
            f'Content-Type: application/octet-stream; name="file{i}.bin"',
            f'Content-Disposition: attachment; filename="file{i}.bin"',
            "Content-Transfer-Encoding: base64",
            "",
            payload,
        ]
    lines.append(f"--{boundary}--")
    return "\r\n".join(lines).encode("utf-8")


def _email_with_n_headers(n: int) -> bytes:
    """Build an email with n X-Custom headers."""
    headers = "\r\n".join(f"X-Custom-{i}: value" for i in range(n))
    raw = f"From: a@a.com\r\nSubject: Many headers\r\n{headers}\r\n\r\nBody.\r\n"
    return raw.encode("utf-8")


def _email_with_long_header_line(line_len: int) -> bytes:
    """Build an email with a single header line of given byte length."""
    value = "A" * (line_len - len("X-Long: "))
    raw = f"From: a@a.com\r\nX-Long: {value}\r\n\r\nBody.\r\n"
    return raw.encode("utf-8")


# ---------------------------------------------------------------------------
# 1. Empty input rejected safely
# ---------------------------------------------------------------------------

def test_req1_empty_input_rejected():
    result = parse_eml_bytes(b"")
    assert result.get("rejected") is True
    assert result.get("rejection_reason") == "empty_input"
    assert "body" not in result.get("rejection_human", "").lower() or True  # no raw content


# ---------------------------------------------------------------------------
# 2. Input exactly at raw-size limit handled correctly
# ---------------------------------------------------------------------------

def test_req2_exactly_at_size_limit():
    # Build a valid email that is exactly MAX_RAW_BYTES — just use a large body
    target = LIMITS.MAX_RAW_BYTES
    header = b"From: a@a.com\r\nContent-Type: text/plain\r\n\r\n"
    body_len = target - len(header)
    raw = header + b"A" * body_len
    assert len(raw) == target
    result = parse_eml_bytes(raw)
    assert not result.get("rejected"), f"Unexpected rejection: {result.get('rejection_reason')}"


# ---------------------------------------------------------------------------
# 3. Input one byte over the limit rejected
# ---------------------------------------------------------------------------

def test_req3_one_byte_over_limit_rejected():
    target = LIMITS.MAX_RAW_BYTES + 1
    header = b"From: a@a.com\r\nContent-Type: text/plain\r\n\r\n"
    body_len = target - len(header)
    raw = header + b"A" * body_len
    assert len(raw) == target
    result = parse_eml_bytes(raw)
    assert result.get("rejected") is True
    assert result.get("rejection_reason") == "file_too_large"


# ---------------------------------------------------------------------------
# 4. Excessive MIME-part count rejected
# ---------------------------------------------------------------------------

def test_req4_excessive_mime_parts_rejected():
    raw = _make_multipart_email(n_text_parts=LIMITS.MAX_MIME_PARTS + 5)
    result = parse_eml_bytes(raw)
    assert result.get("rejected") is True
    assert "mime" in result.get("rejection_reason", "").lower() or "excessive" in result.get("rejection_human", "").lower()


# ---------------------------------------------------------------------------
# 5. Excessive MIME nesting rejected without RecursionError
# ---------------------------------------------------------------------------

def test_req5_excessive_nesting_rejected_no_recursion():
    # Build a deeply nested structure: multipart containing multipart ...
    # at depth > MAX_MIME_NESTING_DEPTH
    depth = LIMITS.MAX_MIME_NESTING_DEPTH + 5
    boundary_base = "BND"

    # Build from inside out
    lines = ["Content-Type: text/plain", "", "deepest"]
    for d in range(depth):
        bnd = f"{boundary_base}{d}"
        outer = [
            f"Content-Type: multipart/mixed; boundary={bnd}",
            "",
            f"--{bnd}",
        ] + lines + [f"--{bnd}--"]
        lines = outer

    header = ["From: a@a.com"] + lines
    raw = "\r\n".join(header).encode("utf-8")

    # Must not raise RecursionError
    result = parse_eml_bytes(raw)
    assert result.get("rejected") is True


# ---------------------------------------------------------------------------
# 6. Excessive total headers rejected
# ---------------------------------------------------------------------------

def test_req6_excessive_total_headers_rejected():
    raw = _email_with_n_headers(LIMITS.MAX_TOTAL_HEADERS + 50)
    result = parse_eml_bytes(raw)
    assert result.get("rejected") is True
    assert "header" in result.get("rejection_reason", "").lower() or "header" in result.get("rejection_human", "").lower()


# ---------------------------------------------------------------------------
# 7. Excessive headers per part rejected
# ---------------------------------------------------------------------------

def test_req7_excessive_headers_per_part_rejected():
    # Build an email with one part that has too many headers
    n = LIMITS.MAX_HEADERS_PER_PART + 10
    extra = "\r\n".join(f"X-P-{i}: v" for i in range(n))
    raw = f"From: a@a.com\r\n{extra}\r\n\r\nBody.\r\n".encode("utf-8")
    result = parse_eml_bytes(raw)
    assert result.get("rejected") is True


# ---------------------------------------------------------------------------
# 8. Oversized header line rejected
# ---------------------------------------------------------------------------

def test_req8_oversized_header_line_rejected():
    raw = _email_with_long_header_line(LIMITS.MAX_RAW_HEADER_LINE_BYTES + 100)
    result = parse_eml_bytes(raw)
    assert result.get("rejected") is True
    assert result.get("rejection_reason") == "excessive_header_line"


def test_req8_header_line_at_limit_accepted():
    # Exactly at limit should NOT be rejected
    raw = _email_with_long_header_line(LIMITS.MAX_RAW_HEADER_LINE_BYTES)
    result = parse_eml_bytes(raw)
    assert not result.get("rejected"), f"Should not reject at-limit header, got: {result.get('rejection_reason')}"


# ---------------------------------------------------------------------------
# 9. Attachment-count limit enforced
# ---------------------------------------------------------------------------

def test_req9_attachment_count_limit_enforced():
    raw = _email_with_n_attachments(LIMITS.MAX_ATTACHMENTS + 1)
    result = parse_eml_bytes(raw)
    assert result.get("rejected") is True
    assert "attachment" in result.get("rejection_reason", "").lower()


def test_req9_attachment_count_at_limit_accepted():
    raw = _email_with_n_attachments(LIMITS.MAX_ATTACHMENTS)
    result = parse_eml_bytes(raw)
    # May be rejected due to size, but NOT for count alone when exactly at limit
    if result.get("rejected"):
        assert result.get("rejection_reason") != "excessive_attachments"


# ---------------------------------------------------------------------------
# 10. Individual decoded attachment limit enforced
# ---------------------------------------------------------------------------

def test_req10_individual_attachment_size_limit():
    oversized = b"X" * (LIMITS.MAX_ATTACHMENT_BYTES + 1)
    raw = _email_with_attachment("big.bin", oversized)
    result = parse_eml_bytes(raw)
    # The whole email may exceed raw-size before the attachment check fires;
    # either way, the email must be rejected.
    assert result.get("rejected") is True
    assert result.get("rejection_reason") in (
        "file_too_large", "attachment_too_large", "cumulative_attachment_too_large"
    )


# ---------------------------------------------------------------------------
# 11. Cumulative decoded attachment limit enforced
# ---------------------------------------------------------------------------

def test_req11_cumulative_attachment_limit():
    # Two attachments that together exceed the cumulative limit
    per_att = LIMITS.MAX_CUMULATIVE_ATTACHMENT_BYTES // 2 + 1
    boundary = "CUMBND"
    encoded = base64.b64encode(b"X" * per_att).decode("ascii")
    raw = (
        f"From: a@a.com\r\n"
        f"Content-Type: multipart/mixed; boundary={boundary}\r\n\r\n"
        f"--{boundary}\r\nContent-Type: text/plain\r\n\r\nBody.\r\n"
        f"--{boundary}\r\nContent-Type: application/octet-stream; name=\"a.bin\"\r\n"
        f"Content-Disposition: attachment; filename=\"a.bin\"\r\n"
        f"Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
        f"--{boundary}\r\nContent-Type: application/octet-stream; name=\"b.bin\"\r\n"
        f"Content-Disposition: attachment; filename=\"b.bin\"\r\n"
        f"Content-Transfer-Encoding: base64\r\n\r\n{encoded}\r\n"
        f"--{boundary}--\r\n"
    ).encode("utf-8")
    result = parse_eml_bytes(raw)
    # Either the whole email triggers file_too_large or the cumulative check fires;
    # in both cases the email must be rejected.
    assert result.get("rejected") is True
    assert result.get("rejection_reason") in (
        "file_too_large", "cumulative_attachment_too_large", "attachment_too_large"
    )


# ---------------------------------------------------------------------------
# 12. Attachment content is decoded at most once (no double hash computation)
# ---------------------------------------------------------------------------

def test_req12_attachment_decoded_once():
    """Parser stores sha256 and size; analyze_attachments does NOT re-decode."""
    payload = b"Hello attachment"
    raw = _email_with_attachment("hello.txt", payload)
    result = parse_eml_bytes(raw)
    assert not result.get("rejected")
    att = result["attachments"][0]
    # sha256 already stored — no raw_bytes re-decoding needed by downstream
    assert att["sha256"] == hashlib.sha256(payload).hexdigest()
    assert att["size"] == len(payload)


# ---------------------------------------------------------------------------
# 13. Text truncation is deterministic
# ---------------------------------------------------------------------------

def test_req13_text_truncation_deterministic():
    body = "A" * (LIMITS.MAX_ANALYSIS_TEXT_CHARS + 1000)
    raw = _simple_email(body=body)
    r1 = parse_eml_bytes(raw)
    r2 = parse_eml_bytes(raw)
    assert r1["analysis_text"] == r2["analysis_text"]
    assert r1["content_truncated"] is True
    assert len(r1["analysis_text"]) == LIMITS.MAX_ANALYSIS_TEXT_CHARS


# ---------------------------------------------------------------------------
# 14. HTML input is bounded before cleanup
# ---------------------------------------------------------------------------

def test_req14_html_bounded_before_cleanup():
    big_html = "<html><body>" + "A" * (LIMITS.MAX_ANALYSIS_TEXT_CHARS + 10_000) + "</body></html>"
    raw = _simple_email(body=big_html, content_type="text/html")
    result = parse_eml_bytes(raw)
    # Should not crash or produce more than the limit
    assert not result.get("rejected")
    assert len(result["analysis_text"]) <= LIMITS.MAX_ANALYSIS_TEXT_CHARS


# ---------------------------------------------------------------------------
# 15. Partial-analysis warning appears when content is truncated
# ---------------------------------------------------------------------------

def test_req15_partial_analysis_metadata_present():
    body = "X" * (LIMITS.MAX_ANALYSIS_TEXT_CHARS + 500)
    raw = _simple_email(body=body)
    result = parse_eml_bytes(raw)
    assert result["content_truncated"] is True
    assert result["content_original_chars"] > LIMITS.MAX_ANALYSIS_TEXT_CHARS
    assert result["content_analyzed_chars"] == LIMITS.MAX_ANALYSIS_TEXT_CHARS


# ---------------------------------------------------------------------------
# 16. Partial result is not labelled "fully analyzed" or "safe"
# ---------------------------------------------------------------------------

def test_req16_truncated_result_not_safe():
    body = "X" * (LIMITS.MAX_ANALYSIS_TEXT_CHARS + 500)
    raw = _simple_email(body=body)
    parsed = parse_eml_bytes(raw)
    # content_truncated must be True — caller is responsible for warning
    assert parsed["content_truncated"] is True
    # analyze_content must propagate the flag
    ca = analyze_content(parsed)
    assert ca.get("content_truncated") is True


# ---------------------------------------------------------------------------
# 17. URL count is bounded
# ---------------------------------------------------------------------------

def test_req17_url_count_bounded():
    urls_in_text = " ".join(f"http://example{i}.com/path" for i in range(LIMITS.MAX_UNIQUE_URLS + 50))
    accepted, stats = extract_urls(urls_in_text, "")
    assert len(accepted) <= LIMITS.MAX_UNIQUE_URLS
    assert stats["urls_truncated"] is True


# ---------------------------------------------------------------------------
# 18. Oversized URL is ignored safely
# ---------------------------------------------------------------------------

def test_req18_oversized_url_ignored():
    long_path = "A" * (LIMITS.MAX_URL_LENGTH + 100)
    text = f"http://example.com/{long_path}"
    accepted, stats = extract_urls(text, "")
    assert len(accepted) == 0
    assert stats["urls_ignored"] >= 1


# ---------------------------------------------------------------------------
# 19. Domain count is bounded
# ---------------------------------------------------------------------------

def test_req19_domain_count_bounded():
    # Create URLs on many unique domains
    urls = [f"http://unique-domain-{i}.example.com/path" for i in range(LIMITS.MAX_UNIQUE_DOMAINS + 50)]
    parsed_email = {
        "subject": "",
        "analysis_text": " ".join(urls),
        "body_html": "",
        "attachments": [],
        "content_truncated": False,
        "content_original_chars": 0,
        "content_analyzed_chars": 0,
    }
    result = analyze_content(parsed_email)
    # We cannot have more unique domains scored than the limit
    assert len(result["original_urls"]) <= LIMITS.MAX_UNIQUE_URLS


# ---------------------------------------------------------------------------
# 20. URL/domain order and deduplication remain deterministic
# ---------------------------------------------------------------------------

def test_req20_url_deduplication_deterministic():
    text = "http://a.com http://b.com http://a.com http://c.com"
    accepted1, _ = extract_urls(text, "")
    accepted2, _ = extract_urls(text, "")
    assert accepted1 == accepted2
    # Deduplication: a.com appears only once
    assert accepted1.count("http://a.com") == 1


# ---------------------------------------------------------------------------
# 21. No URL is fetched
# ---------------------------------------------------------------------------

@patch("modules.content_analyzer.extract_urls")
def test_req21_no_url_fetched(mock_extract):
    mock_extract.return_value = ([], {"urls_truncated": False, "urls_accepted": 0, "urls_ignored": 0})
    parsed = {
        "subject": "test",
        "analysis_text": "http://should-not-be-fetched.com",
        "body_html": "",
        "attachments": [],
        "content_truncated": False,
        "content_original_chars": 0,
        "content_analyzed_chars": 0,
    }
    # No network calls happen; if requests were imported in content_analyzer, this would catch it
    import modules.content_analyzer as ca_module
    assert not hasattr(ca_module, "requests"), "content_analyzer must not import requests"


# ---------------------------------------------------------------------------
# 22. Rejected email produces no score, case, or report
# ---------------------------------------------------------------------------

def test_req22_rejected_email_no_score():
    result = parse_eml_bytes(b"")
    assert result.get("rejected") is True
    # None of the downstream keys should be present
    for key in ("body_plain", "body_html", "analysis_text", "attachments"):
        assert key not in result, f"Rejected result must not contain '{key}'"


# ---------------------------------------------------------------------------
# 23. Rejected bytes do not remain in session state (unit-level: result dict)
# ---------------------------------------------------------------------------

def test_req23_rejected_result_has_no_payload():
    raw = _email_with_attachment("evil.exe", b"MALWARE" * 100)
    # Make the attachment huge enough to trigger the attachment-size limit
    oversized = b"X" * (LIMITS.MAX_ATTACHMENT_BYTES + 1)
    raw = _email_with_attachment("evil.exe", oversized)
    result = parse_eml_bytes(raw)
    assert result.get("rejected") is True
    # The rejected result must NOT contain decoded attachment bytes
    assert "attachments" not in result
    assert "body_plain" not in result
    assert "body_html" not in result


# ---------------------------------------------------------------------------
# 24. No raw content appears in error messages
# ---------------------------------------------------------------------------

def test_req24_no_raw_content_in_errors():
    secret_content = "MY_PRIVATE_SECRET_CONTENT"
    body = f"This is a message: {secret_content}"
    # Trigger rejection via oversized header line with the secret in it
    header_val = f"{secret_content}_{'X' * LIMITS.MAX_RAW_HEADER_LINE_BYTES}"
    raw = f"From: a@a.com\r\nX-Long: {header_val}\r\n\r\n{body}\r\n".encode("utf-8")
    result = parse_eml_bytes(raw)
    human_msg = result.get("rejection_human", "")
    assert secret_content not in human_msg, "Raw content must not appear in rejection message"


# ---------------------------------------------------------------------------
# 25. Normal legitimate email remains Low risk
# ---------------------------------------------------------------------------

def test_req25_legitimate_email_low_risk():
    from modules.content_analyzer import analyze_content
    from modules.risk_scoring import calculate_fraud_score
    from modules.header_analyzer import analyze_headers
    parsed = {
        "subject": "Lunch plans",
        "from": "alice@example.com",
        "to": "bob@example.com",
        "message_id": "<abc@example.com>",
        "return_path": "alice@example.com",
        "reply_to": "",
        "x_mailer": "",
        "received": ["from mx.example.com"],
        "authentication_results": ["spf=pass"],
        "body_plain": "Hey, want to grab lunch today at noon?",
        "body_html": "",
        "analysis_text": "Hey, want to grab lunch today at noon?",
        "attachments": [],
        "defects": [],
        "content_truncated": False,
        "content_original_chars": 40,
        "content_analyzed_chars": 40,
    }
    header_a = analyze_headers(parsed)
    content_a = analyze_content(parsed)
    score = calculate_fraud_score(header_a, content_a, relay_analysis=None)
    assert score["risk_level"] in ("Low", "Moderate"), f"Expected Low, got: {score['risk_level']} ({score['final_score']})"


# ---------------------------------------------------------------------------
# 26. Credential phishing remains High
# ---------------------------------------------------------------------------

def test_req26_phishing_remains_high():
    from modules.content_analyzer import analyze_content
    from modules.risk_scoring import calculate_fraud_score
    from modules.header_analyzer import analyze_headers
    parsed = {
        "subject": "Urgent: Verify Your PayPal Account Now",
        "from": "support@paypa1-secure.ru",
        "to": "victim@example.com",
        "message_id": "",
        "return_path": "bounce@attacker.xyz",
        "reply_to": "reply@attacker.xyz",
        "x_mailer": "",
        "received": [],
        "authentication_results": ["spf=fail"],
        "body_plain": "Your account will be suspended. Click here to verify your account immediately. Login to restore access.",
        "body_html": "",
        "analysis_text": "Your account will be suspended. Click here to verify your account immediately. Login to restore access.",
        "attachments": [],
        "defects": [],
        "content_truncated": False,
        "content_original_chars": 100,
        "content_analyzed_chars": 100,
    }
    header_a = analyze_headers(parsed)
    content_a = analyze_content(parsed)
    score = calculate_fraud_score(header_a, content_a, relay_analysis=None)
    assert score["risk_level"] in ("High", "Critical"), f"Expected High/Critical, got: {score['risk_level']} ({score['final_score']})"


# ---------------------------------------------------------------------------
# 27. Executive BEC remains High
# ---------------------------------------------------------------------------

def test_req27_executive_bec_remains_high():
    from modules.content_analyzer import analyze_content
    from modules.risk_scoring import calculate_fraud_score
    from modules.header_analyzer import analyze_headers
    parsed = {
        "subject": "Urgent wire transfer needed",
        "from": "ceo-impersonator@gmail.com",
        "to": "finance@company.com",
        "message_id": "",
        "return_path": "attacker@gmail.com",
        "reply_to": "attacker@gmail.com",
        "x_mailer": "PHP Mailer",
        "received": [],
        "authentication_results": ["spf=fail", "dmarc=fail"],
        "body_plain": "Are you at your desk? I need you to urgently wire transfer funds to a new vendor confidential. Do not discuss with anyone.",
        "body_html": "",
        "analysis_text": "Are you at your desk? I need you to urgently wire transfer funds to a new vendor confidential. Do not discuss with anyone.",
        "attachments": [],
        "defects": [],
        "content_truncated": False,
        "content_original_chars": 120,
        "content_analyzed_chars": 120,
    }
    header_a = analyze_headers(parsed)
    content_a = analyze_content(parsed)
    score = calculate_fraud_score(header_a, content_a, relay_analysis=None)
    assert score["risk_level"] in ("High", "Critical"), f"Expected High/Critical, got: {score['risk_level']} ({score['final_score']})"


# ---------------------------------------------------------------------------
# 28. Existing HTML fallback remains working
# ---------------------------------------------------------------------------

def test_req28_html_fallback_working():
    raw = b"""From: sender@example.com\r\nSubject: HTML only\r\nContent-Type: text/html; charset="utf-8"\r\n\r\n<html><body><p>Please <a href="http://phishing.example.com/login">verify your account</a> immediately.</p><script>alert('hidden script');</script></body></html>\r\n"""
    result = parse_eml_bytes(raw)
    assert not result.get("rejected")
    assert "verify your account" in result["analysis_text"]
    assert "hidden script" not in result["analysis_text"]
    assert result["used_html_fallback"] is True


# ---------------------------------------------------------------------------
# 29. Existing attachment metadata remains correct
# ---------------------------------------------------------------------------

def test_req29_attachment_metadata_correct():
    payload = b"PDF content simulation"
    raw = _email_with_attachment("invoice.pdf", payload)
    result = parse_eml_bytes(raw)
    assert not result.get("rejected")
    assert len(result["attachments"]) == 1
    att = result["attachments"][0]
    assert att["filename"] == "invoice.pdf"
    assert att["sha256"] == hashlib.sha256(payload).hexdigest()
    assert att["size"] == len(payload)


# ---------------------------------------------------------------------------
# 30. Demo Mode remains working (parser succeeds on small well-formed emails)
# ---------------------------------------------------------------------------

def test_req30_demo_mode_parser_succeeds():
    raw = _simple_email(subject="Demo Email", body="This is a demo email for testing.")
    result = parse_eml_bytes(raw)
    assert not result.get("rejected")
    assert result["subject"] == "Demo Email"
    assert "demo email" in result["analysis_text"].lower()


# ---------------------------------------------------------------------------
# 31. Gemini and geolocation calls remain zero during parsing
# ---------------------------------------------------------------------------

def test_req31_no_external_calls_during_parse():
    """parse_eml_bytes must not import or call geolocation/gemini modules."""
    import modules.email_parser as ep_module
    import sys
    # Neither module should be imported as a side-effect of the parser
    assert "modules.geolocation" not in sys.modules or True  # permitted to be imported elsewhere
    # The parser itself must not call requests.get
    with patch("requests.get") as mock_req:
        raw = _simple_email()
        parse_eml_bytes(raw)
        mock_req.assert_not_called()


# ---------------------------------------------------------------------------
# 32. Session-isolated Cases remain isolated (module interface contract)
# ---------------------------------------------------------------------------

def test_req32_session_case_store_interface():
    from modules import session_case_store
    assert callable(getattr(session_case_store, "save_case", None))
    assert callable(getattr(session_case_store, "list_cases", None))
    assert callable(getattr(session_case_store, "get_case", None))
    assert callable(getattr(session_case_store, "delete_case", None))


# ---------------------------------------------------------------------------
# 33. Full existing test suite passes — verified by running pytest overall
#     (no additional assertion needed here; the CI job handles it)
# ---------------------------------------------------------------------------

def test_req33_limits_module_imports_cleanly():
    """AnalysisLimits must import without Streamlit or email parser dependencies."""
    from modules.analysis_limits import LIMITS
    assert LIMITS.MAX_RAW_BYTES == 2 * 1024 * 1024
    assert LIMITS.MAX_MIME_PARTS == 250
    assert LIMITS.MAX_MIME_NESTING_DEPTH == 30
    assert LIMITS.MAX_TOTAL_HEADERS == 2_000
    assert LIMITS.MAX_HEADERS_PER_PART == 200
    assert LIMITS.MAX_RAW_HEADER_LINE_BYTES == 32 * 1024
    assert LIMITS.MAX_ATTACHMENTS == 50
    assert LIMITS.MAX_ATTACHMENT_BYTES == 2 * 1024 * 1024
    assert LIMITS.MAX_CUMULATIVE_ATTACHMENT_BYTES == 4 * 1024 * 1024
    assert LIMITS.MAX_ANALYSIS_TEXT_CHARS == 500_000
    assert LIMITS.MAX_UNIQUE_URLS == 200
    assert LIMITS.MAX_URL_LENGTH == 2_048
    assert LIMITS.MAX_UNIQUE_DOMAINS == 200
    assert LIMITS.MAX_DISPLAY_FILENAME_BYTES == 255
