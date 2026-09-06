import pytest
from modules.email_parser import parse_eml_bytes

def test_basic_header_extraction():
    raw = b"""From: sender@example.com
To: receiver@example.com
Subject: Test email
Date: Wed, 02 Sep 2026 12:00:00 +0000

This is a test.
"""
    result = parse_eml_bytes(raw)
    assert result["from"] == "sender@example.com"
    assert result["to"] == "receiver@example.com"
    assert result["subject"] == "Test email"
    assert "This is a test." in result["body_plain"]

def test_multiple_received_headers():
    raw = b"""Received: from mx1.example.com
Received: from mx2.example.com
From: sender@example.com
Subject: Received test

Test.
"""
    result = parse_eml_bytes(raw)
    assert len(result["received"]) == 2
    assert result["received"][0] == "from mx1.example.com"
    assert result["received"][1] == "from mx2.example.com"

def test_multipart_body_extraction():
    raw = b"""From: sender@example.com
Subject: Multipart test
Content-Type: multipart/alternative; boundary="boundary-123"

--boundary-123
Content-Type: text/plain; charset="utf-8"

Plain text body
--boundary-123
Content-Type: text/html; charset="utf-8"

<p>HTML body</p>
--boundary-123--
"""
    result = parse_eml_bytes(raw)
    assert "Plain text body" in result["body_plain"]
    assert "<p>HTML body</p>" in result["body_html"]

def test_missing_headers():
    raw = b"""Subject: Missing headers

Body only with subject.
"""
    result = parse_eml_bytes(raw)
    assert result["subject"] == "Missing headers"
    assert result["from"] == ""
    assert result["to"] == ""
    assert "Body only with subject." in result["body_plain"]

def test_malformed_input():
    raw = b"Just some random garbage bytes \x00\xff that is not an email"
    result = parse_eml_bytes(raw)
    assert isinstance(result, dict)

def test_empty_email():
    raw = b""
    result = parse_eml_bytes(raw)
    # Empty input is now a hard rejection
    assert result.get("rejected") is True
    assert result.get("rejection_reason") == "empty_input"

def test_unknown_encoding():
    raw = b"""From: sender@example.com
Subject: Unknown encoding
Content-Type: text/plain; charset="fake-charset"

Hello
"""
    result = parse_eml_bytes(raw)
    assert result["subject"] == "Unknown encoding"
    # Python email parsing usually falls back to utf-8 or ascii if charset is unknown
    assert "Hello" in result["body_plain"]

def test_missing_body():
    raw = b"""From: test@example.com
Subject: No body
"""
    result = parse_eml_bytes(raw)
    assert result["subject"] == "No body"
    assert result["body_plain"] == ""
    assert result["body_html"] == ""

def test_html_only_fallback():
    raw = b"""From: sender@example.com
Subject: HTML only
Content-Type: text/html; charset="utf-8"

<html>
<head><style>body {color: red;}</style></head>
<body>
<p>Please <a href="http://phishing.example.com/login">verify your account</a> immediately.</p>
<script>alert('hidden script');</script>
</body>
</html>
"""
    result = parse_eml_bytes(raw)
    assert result["subject"] == "HTML only"
    # Verify visible phishing text successfully detected (no script/style)
    assert "verify your account" in result["analysis_text"]
    assert "immediately" in result["analysis_text"]
    assert "hidden script" not in result["analysis_text"]
    assert "color: red" not in result["analysis_text"]
    # Original html preserved
    assert "<script>alert('hidden script');</script>" in result["body_html"]

def test_malformed_html_fallback():
    raw = b"""From: sender@example.com
Subject: Malformed HTML
Content-Type: multipart/alternative; boundary="boundary-123"

--boundary-123
Content-Type: text/html; charset="utf-8"

<html<body<<p>Broken <b>HTML <a href="https://bad.com">link</a>
--boundary-123--
"""
    result = parse_eml_bytes(raw)
    assert "Broken" in result["analysis_text"]
    assert "HTML" in result["analysis_text"]
    assert "link" in result["analysis_text"]

def test_oversized_payload_stays_under_limit():
    # Build an email with a large body that stays under 2 MiB — the parser should
    # parse it normally and emit content_truncated metadata if the body is huge.
    large_body = "B" * 10_000   # Well within limits; just checks parser stability
    raw = f"""From: sender@example.com
Subject: Payload test
Content-Type: text/plain; charset="utf-8"

{large_body}
""".encode("utf-8")
    result = parse_eml_bytes(raw)
    assert not result.get("rejected")
    assert "B" in result["body_plain"]

def test_attachment_metadata_handled():
    raw = b"""From: sender@example.com
Subject: Attachment Test
Content-Type: multipart/mixed; boundary="boundary-123"

--boundary-123
Content-Type: text/plain; charset="utf-8"

Body text.
--boundary-123
Content-Type: application/pdf; name="invoice.pdf"
Content-Disposition: attachment; filename="invoice.pdf"
Content-Transfer-Encoding: base64

JVBERi0xLjQKJcOkw7zDtsOfCjIgMCBvYmoKPDwvTGVuZ3RoIDMgMCBSL0ZpbHRlci9GbGF0ZURl
--boundary-123--
"""
    result = parse_eml_bytes(raw)
    # The parser does not extract or execute attachments, but it shouldn't crash.
    assert "Body text." in result["body_plain"]

    if "attachments" in result and len(result["attachments"]) > 0:
        assert any(a.get("filename") == "invoice.pdf" for a in result["attachments"])
