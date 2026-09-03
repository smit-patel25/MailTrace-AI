import pytest
from modules.header_analyzer import analyze_headers, extract_domain, is_aligned

def test_extract_domain():
    assert extract_domain("User <user@example.com>") == "example.com"
    assert extract_domain("user@test.org") == "test.org"
    assert extract_domain("") is None

def test_is_aligned():
    assert is_aligned("example.com", "example.com") is True
    assert is_aligned("sub.example.com", "example.com") is True
    assert is_aligned("example.com", "sub.example.com") is True
    assert is_aligned("example.com", "other.com") is False

def test_analyze_headers_clean():
    parsed = {
        "from": "user@example.com",
        "return_path": "bounce@example.com",
        "reply_to": "user@example.com",
        "message_id": "<123@example.com>",
        "received": ["from mx.example.com"],
        "authentication_results": ["spf=pass", "dkim=pass", "dmarc=pass"],
        "x_mailer": "Outlook"
    }
    result = analyze_headers(parsed)
    assert len(result["indicators"]) == 0
    assert result["reported_auth_statuses"]["spf"] == "pass"

def test_analyze_headers_mismatch_and_missing():
    parsed = {
        "from": "ceo@trusted.com",
        "return_path": "scammer@evil.com",
        "reply_to": "reply@evil.com",
        "message_id": "", # missing
        "received": [], # missing
        "authentication_results": ["spf=fail", "dmarc=fail"],
        "x_mailer": "PHPMailer"
    }
    result = analyze_headers(parsed)
    inds = result["indicators"]
    assert any("Return-Path domain" in i["explanation"] for i in inds)
    assert any("Reply-To domain" in i["explanation"] for i in inds)
    assert any("Missing Message-ID" in i["explanation"] for i in inds)
    assert any("Missing Received" in i["explanation"] for i in inds)
    assert any("Suspicious X-Mailer" in i["explanation"] for i in inds)
    assert any("Reported SPF status is fail" in i["explanation"] for i in inds)
    assert result["reported_auth_statuses"]["dmarc"] == "fail"
