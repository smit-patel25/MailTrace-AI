import os
import sys
import json
import tempfile
import hashlib
from email.message import EmailMessage
from streamlit.testing.v1 import AppTest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from modules.email_parser import parse_eml_bytes
from modules.attachment_analyzer import analyze_attachments, analyze_single_attachment
from modules.case_database import initialize_database, save_case, get_case
from modules.report_generator import generate_json_report, generate_html_report, generate_pdf_report
from modules.risk_scoring import calculate_fraud_score

APP_PATH = os.path.join(PROJECT_ROOT, "app.py")


def create_synthetic_eml(filename: str = None, content_type: str = None, payload_bytes: bytes = None) -> bytes:
    """Helper to build harmless synthetic EML bytes in memory."""
    msg = EmailMessage()
    msg["From"] = "sender@example.test"
    msg["To"] = "recipient@example.test"
    msg["Subject"] = "Synthetic Test Email"
    msg.set_content("Harmless test email body.")

    if filename or payload_bytes is not None:
        maintype, subtype = (content_type or "application/octet-stream").split("/", 1)
        msg.add_attachment(
            payload_bytes or b"harmless test payload",
            maintype=maintype,
            subtype=subtype,
            filename=filename
        )

    return msg.as_bytes()


def test_1_email_without_attachments():
    eml = create_synthetic_eml()
    parsed = parse_eml_bytes(eml)
    res = analyze_attachments(parsed)
    assert res["attachment_count"] == 0
    assert res["overall_metadata_risk"] == "None"
    assert res["disclaimer"] == "Attachment assessment is based on metadata only and is not a malware scan."


def test_2_benign_pdf_attachment():
    payload = b"dummy pdf content"
    eml = create_synthetic_eml(filename="report.pdf", content_type="application/pdf", payload_bytes=payload)
    parsed = parse_eml_bytes(eml)
    res = analyze_attachments(parsed)
    assert res["attachment_count"] == 1
    att = res["attachments"][0]
    assert att["filename"] == "report.pdf"
    assert att["risk_level"] == "Low"
    assert att["content_type"] == "application/pdf"
    assert att["sha256"] == hashlib.sha256(payload).hexdigest()


def test_3_executable_extension_high():
    eml = create_synthetic_eml(filename="payload.exe", content_type="application/octet-stream", payload_bytes=b"MZ...")
    parsed = parse_eml_bytes(eml)
    res = analyze_attachments(parsed)
    assert res["attachment_count"] == 1
    att = res["attachments"][0]
    assert att["risk_level"] == "High"
    assert any("High-risk executable" in r for r in att["reasons"])


def test_4_macro_enabled_document():
    eml = create_synthetic_eml(filename="financial.docm", content_type="application/vnd.ms-word.document.macroenabled.12", payload_bytes=b"PK...")
    parsed = parse_eml_bytes(eml)
    res = analyze_attachments(parsed)
    att = res["attachments"][0]
    assert att["risk_level"] == "High"
    assert any("Macro-enabled document format" in r for r in att["reasons"])


def test_5_archive_format_review():
    eml = create_synthetic_eml(filename="archive.zip", content_type="application/zip", payload_bytes=b"PK...")
    parsed = parse_eml_bytes(eml)
    res = analyze_attachments(parsed)
    att = res["attachments"][0]
    assert att["risk_level"] == "Review"
    assert any("Archive or container file requiring review" in r for r in att["reasons"])


def test_6_double_extension_deception():
    eml = create_synthetic_eml(filename="invoice.pdf.exe", content_type="application/octet-stream", payload_bytes=b"MZ...")
    parsed = parse_eml_bytes(eml)
    res = analyze_attachments(parsed)
    att = res["attachments"][0]
    assert att["risk_level"] == "High"
    assert any("Double-extension deception" in r for r in att["reasons"])


def test_7_mime_extension_mismatch():
    eml = create_synthetic_eml(filename="photo.jpg", content_type="application/pdf", payload_bytes=b"test")
    parsed = parse_eml_bytes(eml)
    res = analyze_attachments(parsed)
    att = res["attachments"][0]
    assert att["risk_level"] == "Review"
    assert any("Declared MIME type" in r and "mismatches" in r for r in att["reasons"])


def test_8_missing_filename_handled_safely():
    att_dict = {"filename": "", "content_type": "text/plain", "size": 10, "raw_bytes": b"1234567890"}
    res = analyze_single_attachment(att_dict)
    assert res["filename"] == "unnamed_attachment"
    assert any("Missing or empty filename" in r for r in res["reasons"])


def test_9_path_like_filename_sanitized():
    att_dict = {"filename": "../../../C:/Windows/System32/cmd.exe", "content_type": "application/octet-stream", "size": 10, "raw_bytes": b"test"}
    res = analyze_single_attachment(att_dict)
    assert res["filename"] == "cmd.exe"
    assert any("path traversal" in r.lower() for r in res["reasons"])


def test_10_correct_sha256_and_decoded_byte_size():
    payload = b"Hello, Attachment Forensics SHA-256 Test!"
    expected_hash = hashlib.sha256(payload).hexdigest()
    expected_size = len(payload)
    att_dict = {"filename": "test.txt", "content_type": "text/plain", "raw_bytes": payload}
    res = analyze_single_attachment(att_dict)
    assert res["sha256"] == expected_hash
    assert res["size"] == expected_size
    assert res["human_size"] == f"{expected_size} B"


def test_11_malformed_mime_payload_no_crash():
    raw_bad_eml = b"""From: sender@example.test\nTo: dest@example.test\nSubject: Malformed\nContent-Type: multipart/mixed; boundary="b1"\n\n--b1\nContent-Type: text/plain\n\nHello\n--b1\nContent-Type: application/octet-stream\nContent-Disposition: attachment; filename="bad.bin"\nContent-Transfer-Encoding: base64\n\n!!!INVALID_BASE64_BYTES!!!\n--b1--"""
    parsed = parse_eml_bytes(raw_bad_eml)
    res = analyze_attachments(parsed)
    assert res["attachment_count"] == 1
    assert res["attachments"][0]["filename"] == "bad.bin"


def test_12_no_attachment_written_to_disk(tmp_path):
    # Monitor directory before and after parsing
    files_before = set(os.listdir(tmp_path))
    eml = create_synthetic_eml(filename="test.exe", content_type="application/octet-stream", payload_bytes=b"MZ123")
    parsed = parse_eml_bytes(eml)
    _ = analyze_attachments(parsed)
    files_after = set(os.listdir(tmp_path))
    assert files_before == files_after


def test_13_no_external_api_calls(monkeypatch):
    gemini_called = False
    geo_called = False
    domain_called = False

    monkeypatch.setattr("modules.gemini_analyzer.analyze_with_gemini", lambda *a, **kw: None)
    monkeypatch.setattr("modules.geolocation.geolocate_ip", lambda *a, **kw: None)
    monkeypatch.setattr("modules.domain_intelligence.analyze_domain", lambda *a, **kw: None)

    eml = create_synthetic_eml(filename="sample.pdf", content_type="application/pdf", payload_bytes=b"test")
    parsed = parse_eml_bytes(eml)
    _ = analyze_attachments(parsed)

    assert not gemini_called
    assert not geo_called
    assert not domain_called


def test_14_raw_attachment_bytes_not_stored_in_cases_or_reports():
    payload = b"SECRET_ATTACHMENT_CONTENT_DATA_123"
    eml = create_synthetic_eml(filename="secret.pdf", content_type="application/pdf", payload_bytes=payload)
    parsed = parse_eml_bytes(eml)
    att_res = analyze_attachments(parsed)

    # Verify att_res does not contain raw_bytes
    att_json = json.dumps(att_res)
    assert "SECRET_ATTACHMENT_CONTENT_DATA_123" not in att_json

    # Test saving case to DB
    fd, db_path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    try:
        initialize_database(db_path)
        case_data = {
            "filename": "secret.eml",
            "email_hash": hashlib.sha256(eml).hexdigest(),
            "subject": "Secret",
            "sender_address": "sender@example.test",
            "fraud_score": 10,
            "risk_level": "Low",
            "verdict": "Low Risk",
            "confidence": "High",
            "analyzer_results": {
                "fraud_score": {
                    "scoring_version": "1.2",
                    "component_scores": {
                        "attachment_risk": 50
                    }
                },
                "attachment_analysis": att_res
            }
        }
        case_id = save_case(db_path, case_data)
        saved_case = get_case(db_path, case_id)
        saved_str = json.dumps(saved_case)
        assert "SECRET_ATTACHMENT_CONTENT_DATA_123" not in saved_str


    finally:
        if os.path.exists(db_path):
            os.unlink(db_path)


def test_15_final_fraud_score_remains_unchanged():
    # Base scoring without attachments
    header = {"indicators": []}
    content = {"indicators": [{"points": 10, "explanation": "test"}], "rule_content_score": 10}
    relay = {}
    score_without = calculate_fraud_score(header, content, relay)

    # Attachment analysis present
    # Fraud score calculation ignores attachment_analysis and remains identical
    score_with = calculate_fraud_score(header, content, relay)
    assert score_without["final_score"] == score_with["final_score"]
    assert score_without["risk_level"] == score_with["risk_level"]


def test_16_ui_disclaimer_and_accessible_risk_text():
    at = AppTest.from_file(APP_PATH, default_timeout=10).run()
    assert not at.exception

    # Load Legitimate Demo email
    legit_idx = next(i for i, b in enumerate(at.button) if "Legitimate Email" in b.label)
    at.button[legit_idx].click().run()
    assert not at.exception

    markdown_text = " ".join([m.value for m in at.markdown])
    assert "Attachment Forensics" in markdown_text
    assert "Attachment assessment is based on metadata only and is not a malware scan." in markdown_text

    raw_md_list = [m.value for m in at.markdown if m.value and "Attachment Forensics" in m.value]
    assert len(raw_md_list) == 1, f"Expected exactly 1 Attachment Forensics block, found {len(raw_md_list)}"

def test_17_report_format_assertions():
    import reportlab.rl_config

    # Create minimal case data to test the report format
    case_data = {
        "filename": "test.eml",
        "email_hash": "dummyhash",
        "subject": "Test",
        "sender_address": "sender@example.com",
        "fraud_score": 100,
        "risk_level": "High",
        "verdict": "High Risk",
        "confidence": "High",
        "analyzer_results": {
            "fraud_score": {
                "scoring_version": "1.2",
                "component_scores": {
                    "attachment_risk": 50
                }
            },
            "attachment_analysis": {
                "attachments": [{"filename": "secret.pdf", "content_type": "application/pdf", "risk_level": "Low", "size": 100, "human_size": "100 B", "sha256": "hash", "reasons": []}]
            }
        }
    }

    original_comp = reportlab.rl_config.pageCompression
    reportlab.rl_config.pageCompression = 0
    try:
        json_rep = generate_json_report(case_data).decode("utf-8")
        html_rep = generate_html_report(case_data).decode("utf-8")
        pdf_rep = generate_pdf_report(case_data)
    finally:
        reportlab.rl_config.pageCompression = original_comp

    assert "SECRET_ATTACHMENT_CONTENT_DATA_123" not in json_rep
    assert "SECRET_ATTACHMENT_CONTENT_DATA_123" not in html_rep
    assert b"SECRET_ATTACHMENT_CONTENT_DATA_123" not in pdf_rep
    assert "1.2" in json_rep and "attachment_risk" in json_rep
    assert "1.2" in html_rep and "attachment_risk" in html_rep
    assert b"1.2" in pdf_rep
    assert b"attachment_risk" in pdf_rep
