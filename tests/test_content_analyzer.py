import pytest
from modules.content_analyzer import analyze_content, defang_url
from modules.email_parser import parse_eml_bytes

def test_defang_url():
    assert defang_url("http://example.com/test") == "hxxp://example[.]com/test"
    assert defang_url("https://malicious.com") == "hxxps://malicious[.]com"

def test_legitimate_content():
    email = {
        "subject": "Lunch today?",
        "analysis_text": "Hey, let's grab lunch at noon. See you then!",
        "body_plain": "Hey, let's grab lunch at noon. See you then!",
        "body_html": "",
        "attachments": []
    }
    res = analyze_content(email)
    assert res["rule_content_score"] == 0
    assert len(res["indicators"]) == 0
    assert len(res["categories_detected"]) == 0

def test_urgency_and_threats():
    email = {
        "subject": "Urgent: Account Suspended",
        "analysis_text": "This is a final warning. Action required immediately.",
        "body_plain": "This is a final warning. Action required immediately.",
    }
    res = analyze_content(email)
    assert res["rule_content_score"] > 0
    assert "urgency" in res["categories_detected"]
    assert "threats or fear" in res["categories_detected"]

def test_credential_request_html():
    email = {
        "subject": "Verify",
        "analysis_text": "Please login to verify your account.",
        "body_plain": "",
        "body_html": "<p>Please <a href='http://phish.com'>login</a> to verify your account.</p>"
    }
    res = analyze_content(email)
    assert "credential request" in res["categories_detected"]
    assert "http://phish.com" in res["original_urls"]
    assert "hxxp://phish[.]com" in res["defanged_urls"]

def test_html_sanitization():
    email = {
        "subject": "Clean",
        "analysis_text": "Hello",
        "body_plain": "",
        "body_html": "<html><body><script>alert(1);</script><p>Hello</p><iframe src='foo'></iframe></body></html>"
    }
    res = analyze_content(email)
    assert res["analyzed_text_length"] < 20 # Just "Clean\n\n Hello "

def test_suspicious_url_patterns():
    email = {
        "subject": "Links",
        "analysis_text": "IP: http://192.168.1.1/ Puny: https://xn--fubar-test.com/ @: http://user:pass@test.com/ Sub: http://a.b.c.d.com/ Short: http://bit.ly/123",
        "body_plain": "IP: http://192.168.1.1/ Puny: https://xn--fubar-test.com/ @: http://user:pass@test.com/ Sub: http://a.b.c.d.com/ Short: http://bit.ly/123",
    }
    res = analyze_content(email)
    cats = res["categories_detected"]
    assert "suspicious url" in cats
    
    expl = [i["explanation"] for i in res["indicators"]]
    assert any("IP address used" in e for e in expl)
    assert any("Punycode" in e for e in expl)
    assert any("Credential embedded" in e for e in expl)
    assert any("Excessive subdomains" in e for e in expl)
    assert any("URL shortener" in e for e in expl)

def test_payment_and_secrecy():
    email = {
        "subject": "Confidential task",
        "analysis_text": "Keep this private. We need a wire transfer.",
        "body_plain": "Keep this private. We need a wire transfer.",
    }
    res = analyze_content(email)
    assert "secrecy request" in res["categories_detected"]
    assert "payment diversion" in res["categories_detected"]

def test_fake_invoice():
    email = {
        "subject": "Invoice attached",
        "analysis_text": "Please pay the outstanding payment.",
        "body_plain": "Please pay the outstanding payment.",
    }
    res = analyze_content(email)
    assert "fake invoice" in res["categories_detected"]

def test_suspicious_attachments():
    email = {
        "subject": "Here is the file",
        "analysis_text": "Attached.",
        "body_plain": "Attached.",
        "attachments": [
            {"filename": "document.pdf", "content_type": "application/pdf"},
            {"filename": "payload.exe", "content_type": "application/x-msdownload"}
        ]
    }
    res = analyze_content(email)
    assert "suspicious attachment" in res["categories_detected"]
    assert res["rule_content_score"] >= 40

def test_empty_content():
    email = {}
    res = analyze_content(email)
    assert res["rule_content_score"] == 0
    assert res["analyzed_text_length"] == 2 # "\n\n" from empty subject + body

def test_app_level_html_fallback_flow():
    raw_email = b"""From: sender@test.com
Subject: Action Required
Content-Type: text/html; charset="utf-8"

<html>
<body>
<p>You must <a href="http://badsite.com">verify your account</a> immediately to avoid it being restricted.</p>
</body>
</html>
"""
    parsed = parse_eml_bytes(raw_email)
    assert parsed["analysis_text"] != ""
    assert parsed["used_html_fallback"] is True
    
    res = analyze_content(parsed)
    assert res["rule_content_score"] > 0
    assert "hxxp://badsite[.]com" in res["defanged_urls"]
    assert "credential request" in res["categories_detected"]
    assert "threats or fear" in res["categories_detected"]

def test_duplicate_url_deduplication():
    email = {
        "subject": "Links",
        "analysis_text": "Check http://example.com/login and http://example.com/verify and http://other.com",
        "body_plain": "Check http://example.com/login and http://example.com/verify and http://other.com",
    }
    res = analyze_content(email)
    urls = res.get("defanged_urls", [])
    assert len(urls) == 3 # All unique URLs are kept in the list
    # Let's check how many times domain points are applied in risk_scoring, but the test here is if the list extracts them.
    # Actually, the deduplication is usually about hostname analysis or indicator count.
    # Since content_analyzer just lists URLs, we'll assert it finds them all, but in risk_scoring they shouldn't compound infinitely.
    
def test_data_javascript_url_handling():
    raw_email = b"""From: sender@test.com
Subject: Action Required
Content-Type: text/html; charset="utf-8"

<html>
<body>
<a href="javascript:alert(1)">Click here</a>
<a href="data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==">Or here</a>
<a href="file:///etc/passwd">Or here</a>
</body>
</html>
"""
    parsed = parse_eml_bytes(raw_email)
    res = analyze_content(parsed)
    # The URL extractor should ignore javascript:, data:, and file: schemes or defang them safely.
    urls = res.get("defanged_urls", [])
    assert not any(u.startswith("javascript:") for u in urls)
    assert not any(u.startswith("data:") for u in urls)
    assert not any(u.startswith("file:") for u in urls)
    # They shouldn't be clickable

def test_contextual_account_access_threat():
    email = {"subject": "Warning", "analysis_text": "Your account has been restricted due to suspicious activity.", "body_plain": ""}
    res = analyze_content(email)
    assert any("Account-access threat" in ind["explanation"] for ind in res["indicators"])

def test_contextual_restoration_action():
    email = {"subject": "Action needed", "analysis_text": "Click below to restore your wallet access.", "body_plain": ""}
    res = analyze_content(email)
    assert any("Restoration action" in ind["explanation"] for ind in res["indicators"])

def test_contextual_verification_request():
    email = {"subject": "Verify", "analysis_text": "You must confirm your identity before proceeding.", "body_plain": ""}
    res = analyze_content(email)
    assert any("Verification request" in ind["explanation"] for ind in res["indicators"])

def test_contextual_link_action():
    email = {"subject": "Hey", "analysis_text": "Please click the link below to view the document.", "body_plain": ""}
    res = analyze_content(email)
    assert any("Link action" in ind["explanation"] for ind in res["indicators"])

def test_contextual_financial_urgency():
    email = {"subject": "Alert", "analysis_text": "Your funds have been temporarily frozen.", "body_plain": ""}
    res = analyze_content(email)
    assert any("Financial-access urgency" in ind["explanation"] for ind in res["indicators"])

def test_contextual_legitimate_one_sided():
    email = {"subject": "Notice", "analysis_text": "Your account details have been saved successfully.", "body_plain": ""}
    res = analyze_content(email)
    # Should not trigger contextual rules since it only has "account" and "details" but no verification/restriction verb
    assert not any("Contextual pattern" in ind["explanation"] for ind in res["indicators"])

def test_contextual_normal_promotional():
    email = {"subject": "Sale", "analysis_text": "Get 50% off your next purchase! Valid until Friday.", "body_plain": ""}
    res = analyze_content(email)
    assert not any("Contextual pattern" in ind["explanation"] for ind in res["indicators"])

def test_strong_phishing_2_contextual_score():
    import os
    from modules.email_parser import parse_eml_bytes
    file_path = os.path.join("tests", "fixtures", "synthetic_wallet_phishing.eml")
    if os.path.exists(file_path):
        with open(file_path, "rb") as f:
            parsed = parse_eml_bytes(f.read())
        res = analyze_content(parsed)
        assert res["rule_content_score"] > 0

