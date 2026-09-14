import json
import pytest
from modules.report_generator import generate_json_report, generate_html_report, generate_pdf_report

@pytest.fixture
def mock_case():
    return {
        "case_id": "CASE-123",
        "filename": "evil.eml",
        "email_hash": "deadbeef",
        "subject": "Update Account <script>alert(1)</script>",
        "sender_address": "bad@evil.com",
        "probable_origin_ip": "1.2.3.4",
        "fraud_score": 90,
        "risk_level": "Critical",
        "analyzer_results": {
            "header_analysis": {
                "indicators": [{"severity": "high", "explanation": "Failed SPF"}],
                "reported_auth_statuses": {"spf": "fail", "dkim": "none", "dmarc": "none"}
            },
            "content_analysis": {
                "defanged_urls": ["hxxp://evil[.]com/login"],
                "original_urls": ["http://evil.com/login"]
            }
        },
        "raw_email_bytes": b"SENSITIVE_RAW_DATA",
        "gemini_api_key": "SECRET_KEY"
    }

def test_generate_json_report(mock_case):
    report_bytes = generate_json_report(mock_case)
    report = json.loads(report_bytes)

    assert report["case_id"] == "CASE-123"
    assert report["fraud_score"] == 90
    assert "SENSITIVE" not in report_bytes.decode()
    assert "SECRET_KEY" not in report_bytes.decode()
    assert report["defanged_urls"] == ["hxxp://evil[.]com/login"]
    assert "http://evil.com/login" not in report_bytes.decode()

def test_generate_html_report(mock_case):
    html_bytes = generate_html_report(mock_case)
    html_str = html_bytes.decode()

    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html_str
    assert "<script>" not in html_str

    assert "hxxp://evil[.]com/login" in html_str
    assert "http://evil.com/login" not in html_str

    assert "estimated infrastructure location" in html_str

def test_generate_pdf_report(mock_case):
    pdf_bytes = generate_pdf_report(mock_case)

    assert pdf_bytes.startswith(b"%PDF-")

def test_missing_data_report():
    empty_case = {}
    json_bytes = generate_json_report(empty_case)
    report = json.loads(json_bytes)
    assert report["subject"] == "N/A"

    html_bytes = generate_html_report(empty_case)
    assert b"N/A" in html_bytes

    pdf_bytes = generate_pdf_report(empty_case)
    assert pdf_bytes.startswith(b"%PDF-")

def test_score_export_precedence():
    """Test nested-only scores, top-level-only scores, conflicting values, and nested zero."""
    from modules.report_generator import extract_safe_data

    # Top-level only (legacy)
    c1 = {"fraud_score": 75}
    assert extract_safe_data(c1, False)["fraud_score"] == 75

    # Nested only
    c2 = {"analyzer_results": {"fraud_score": {"final_score": 80}}}
    assert extract_safe_data(c2, False)["fraud_score"] == 80

    # Conflicting values (nested takes precedence)
    c3 = {"fraud_score": 10, "analyzer_results": {"fraud_score": {"final_score": 90}}}
    assert extract_safe_data(c3, False)["fraud_score"] == 90

    # Nested zero (must not fall back to top-level)
    c4 = {"fraud_score": 99, "analyzer_results": {"fraud_score": {"final_score": 0}}}
    assert extract_safe_data(c4, False)["fraud_score"] == 0

    # Masking variations
    assert extract_safe_data(c4, True)["fraud_score"] == 0
