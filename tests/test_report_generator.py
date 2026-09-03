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
