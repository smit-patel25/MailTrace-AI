import pytest
from modules.risk_scoring import calculate_fraud_score

def test_legitimate_email():
    res = calculate_fraud_score(
        header_analysis={"indicators": []},
        content_analysis={"indicators": []},
        relay_analysis={"probable_origin_ip": "1.2.3.4"}
    )
    assert res["final_score"] == 0
    assert res["risk_level"] == "Low"
    assert res["verdict"] == "Low Risk"

def test_header_spoofing():
    res = calculate_fraud_score(
        header_analysis={"indicators": [
            {"severity": "high", "explanation": "SPF fail"},
            {"severity": "high", "explanation": "Domain mismatch"}
        ]},
        content_analysis={"indicators": []},
        relay_analysis={}
    )
    assert res["component_scores"]["header_risk"] == 30
    assert "SPF fail" in res["top_reasons"]

def test_bec_content():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [
            {"points": 30, "explanation": "wire transfer"}
        ]},
        relay_analysis={}
    )
    assert res["component_scores"]["content_risk"] > 0

def test_proxy_hosting_infrastructure():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={},
        relay_analysis={},
        geolocation_result={"available": True, "proxy": True, "hosting": True}
    )
    assert res["component_scores"]["infrastructure_risk"] == 20

def test_recognized_infra_google():
    # Legitimate cases
    cases = [
        "from google.com (google.com [1.1.1.1])", # original fixture
        "from google.com [1.1.1.1]",
        "from mail-sor.google.com [1.1.1.1]",
        "from MAIL.GOOGLE.COM [1.1.1.1]",
        "from googlemail.com. [1.1.1.1]",
        "from mail.google.com (relay [1.1.1.1]) by mx.example.test", # proper association
        "from google.com (relay.by.example [1.1.1.1]) by mx.example.test", # 'by' inside parens
        r"from google.com (relay \(nested\) [1.1.1.1]) by mx.example.test", # legitimate escaped comment
        "from google.com\r\n\t([1.1.1.1]) by mx.example.test", # folded header
    ]
    for case in cases:
        res = calculate_fraud_score(
            header_analysis={}, content_analysis={},
            relay_analysis={"probable_origin_ip": "1.1.1.1", "original_received_headers": [case]},
            geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Google LLC"}}
        )
        assert res["component_scores"]["infrastructure_risk"] == 0, f"Failed legit case: {case}"
        assert any("Recognized email delivery infrastructure" in r for r in res["top_reasons"])

def test_recognized_infra_ipv6():
    res = calculate_fraud_score(
        header_analysis={}, content_analysis={},
        relay_analysis={"probable_origin_ip": "2001:db8::1", "original_received_headers": ["from google.com [2001:0db8:0000:0000:0000:0000:0000:0001]"]},
        geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Google LLC"}}
    )
    assert res["component_scores"]["infrastructure_risk"] == 0

def test_recognized_infra_microsoft():
    res = calculate_fraud_score(
        header_analysis={}, content_analysis={},
        relay_analysis={"probable_origin_ip": "1.1.1.1", "original_received_headers": ["from mail.protection.outlook.com [1.1.1.1]"]},
        geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Microsoft Corporation"}}
    )
    assert res["component_scores"]["infrastructure_risk"] == 0

def test_recognized_infra_amazon():
    res = calculate_fraud_score(
        header_analysis={}, content_analysis={},
        relay_analysis={"probable_origin_ip": "1.1.1.1", "original_received_headers": ["from a1-2.smtp-out.amazonses.com [1.1.1.1]"]},
        geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Amazon.com"}}
    )
    assert res["component_scores"]["infrastructure_risk"] == 0

def test_recognized_infra_deceptive_hostname():
    # Deceptive cases (should NOT be recognized)
    cases = [
        "from google.com.attacker.test [1.1.1.1]",
        "from googlemail.com.attacker.test [1.1.1.1]",
        "from outlook.com.attacker.test [1.1.1.1]",
        "from amazonses.com.attacker.test [1.1.1.1]",
        "from attacker-google.com [1.1.1.1]",
        "from google.com@attacker.test [1.1.1.1]",
        "from attacker.test/google.com [1.1.1.1]",
        "from attacker.test (google.com [1.1.1.1])",
        "from attacker.test [1.1.1.1] google.com", # Trusted text elsewhere
        "from google.com [11.1.1.10]", # Probable IP is 1.1.1.1, header has 11.1.1.10
        "from ---.com [1.1.1.1]", # Malformed hostname
        "from [1.1.1.1]", # Missing hostname
        "from google.com [8.8.8.8] by mx.attacker.test [1.1.1.1]", # IP only in 'by' clause
        "from google.com by mx.attacker.test [1.1.1.1]", # IP appears after 'by' clause
        "(from google.com [1.1.1.1]) by mx.attacker.test",
        "from google.com (relay) by mx.example.test ; [1.1.1.1]", # IP after top-level semicolon
        r"from google.com \by mx.attacker.test [1.1.1.1]", # backslash before by at top level
        "from google.com (relay)by mx.attacker.test [1.1.1.1]", # by immediately after closing paren
        "from google.com (relay); [1.1.1.1]", # IP only after top-level semicolon (no by)
    ]
    for case in cases:
        res = calculate_fraud_score(
            header_analysis={}, content_analysis={},
            relay_analysis={"probable_origin_ip": "1.1.1.1", "original_received_headers": [case]},
            geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Google LLC"}}
        )
        assert res["component_scores"]["infrastructure_risk"] == 20, f"Failed deceptive case: {case}"

def test_recognized_infra_invalid_ip_and_headers():
    invalid_ips = ["invalid-ip", None, [], {}, b"1.1.1.1"]
    for invalid_ip in invalid_ips:
        res = calculate_fraud_score(
            header_analysis={}, content_analysis={},
            relay_analysis={"probable_origin_ip": invalid_ip, "original_received_headers": ["from google.com [1.1.1.1]"]},
            geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Google LLC"}}
        )
        assert res["component_scores"]["infrastructure_risk"] == 20

    # Specifically test integer 123
    res = calculate_fraud_score(
        header_analysis={}, content_analysis={},
        relay_analysis={"probable_origin_ip": 123, "original_received_headers": ["from google.com [0.0.0.123]"]},
        geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Google LLC"}}
    )
    assert res["component_scores"]["infrastructure_risk"] == 20

    invalid_headers = [None, 123, b"from google.com [1.1.1.1]", "", []]
    for invalid_header in invalid_headers:
        res = calculate_fraud_score(
            header_analysis={}, content_analysis={},
            relay_analysis={"probable_origin_ip": "1.1.1.1", "original_received_headers": [invalid_header]},
            geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Google LLC"}}
        )
        assert res["component_scores"]["infrastructure_risk"] == 20

def test_recognized_infra_provider_specific_deception():
    # Microsoft Corp + deceptive outlook hostname
    res = calculate_fraud_score(
        header_analysis={}, content_analysis={},
        relay_analysis={"probable_origin_ip": "1.1.1.1", "original_received_headers": ["from outlook.com.attacker.test [1.1.1.1]"]},
        geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Microsoft Corporation"}}
    )
    assert res["component_scores"]["infrastructure_risk"] == 20

    # Amazon.com + deceptive amazonses hostname
    res = calculate_fraud_score(
        header_analysis={}, content_analysis={},
        relay_analysis={"probable_origin_ip": "1.1.1.1", "original_received_headers": ["from amazonses.com.attacker.test [1.1.1.1]"]},
        geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Amazon.com"}}
    )
    assert res["component_scores"]["infrastructure_risk"] == 20

    # Google LLC + deceptive google hostname
    res = calculate_fraud_score(
        header_analysis={}, content_analysis={},
        relay_analysis={"probable_origin_ip": "1.1.1.1", "original_received_headers": ["from google.com.attacker.test [1.1.1.1]"]},
        geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Google LLC"}}
    )
    assert res["component_scores"]["infrastructure_risk"] == 20

def test_recognized_infra_forged_hostname():
    # Hostname says google.com, but org is EvilHost
    res = calculate_fraud_score(
        header_analysis={}, content_analysis={},
        relay_analysis={"probable_origin_ip": "1.1.1.1", "original_received_headers": ["from google.com [1.1.1.1]"]},
        geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "EvilHost"}}
    )
    assert res["component_scores"]["infrastructure_risk"] == 20
    assert not any("Recognized email delivery infrastructure" in r for r in res["top_reasons"])

def test_recognized_infra_still_receives_content_risk():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [{"points": 100, "explanation": "Phishing link"}]},
        relay_analysis={"probable_origin_ip": "1.1.1.1", "original_received_headers": ["from google.com [1.1.1.1]"]},
        geolocation_result={"available": True, "proxy": True, "hosting": True, "location": {"org": "Google LLC"}}
    )
    assert res["component_scores"]["infrastructure_risk"] == 0
    assert res["component_scores"]["content_risk"] == 25


def test_new_domain():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={},
        relay_analysis={},
        domain_result={"available": True, "domain_age_days": 5}
    )
    assert res["component_scores"]["domain_risk"] == 15

def test_suspicious_url():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [
            {"points": 20, "explanation": "URL has excessive subdomains"}
        ]},
        relay_analysis={}
    )
    assert res["component_scores"]["domain_risk"] == 10  # 20 * 0.5
    assert res["component_scores"]["content_risk"] == 0

def test_gemini_available():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": []},
        relay_analysis={},
        gemini_result={"available": True, "nlp_risk_score": 100, "threat_category": "Phishing"}
    )
    assert res["component_scores"]["content_risk"] == 12  # (0 + 100)/2 = 50 -> 50% of 25 = 12
    assert "AI classified content as Phishing." in res["top_reasons"]

def test_gemini_unavailable():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [{"points": 100, "explanation": "Bad"}]},
        relay_analysis={},
        gemini_result={"available": False, "error": "Timeout"}
    )
    assert res["component_scores"]["content_risk"] == 25
    assert "Gemini Analysis" in res["unavailable_sources"]

def test_all_optional_unavailable():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={},
        relay_analysis={},
        geolocation_result={"available": False},
        domain_result={"available": False},
        gemini_result={"available": False}
    )
    assert res["final_score"] == 0
    assert len(res["unavailable_sources"]) == 3
    assert res["confidence"] == "Low"

def test_score_boundaries():
    res1 = calculate_fraud_score(
        header_analysis={"indicators": [{"severity": "high"}] * 10},
        content_analysis={"indicators": [{"points": 200, "explanation": "Very bad"}, {"points": 10, "explanation": "URL has excessive subdomains"}]},
        relay_analysis={},
        geolocation_result={"available": True, "proxy": True, "hosting": True},
        domain_result={"available": True, "domain_age_days": 1}
    )
    assert res1["final_score"] <= 100
    assert res1["risk_level"] == "Critical"
    assert res1["component_scores"]["header_risk"] == 35
    assert res1["component_scores"]["content_risk"] == 25
    assert res1["component_scores"]["infrastructure_risk"] == 20
    assert res1["component_scores"]["domain_risk"] == 20
    assert res1["final_score"] == 100

def test_corroboration_bonus_applied():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [{"points": 40, "explanation": "bad"}]},
        relay_analysis={},
        gemini_result={"available": True, "nlp_risk_score": 80, "threat_category": "Phishing"}
    )
    assert res["corroboration_bonus"] == 30
    assert "Independent AI and rule-based analysis strongly corroborate a severe email threat." in res["top_reasons"]
    assert res["final_score"] == 45

def test_corroboration_bonus_gemini_threshold_missed():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [{"points": 40, "explanation": "bad"}]},
        relay_analysis={},
        gemini_result={"available": True, "nlp_risk_score": 79, "threat_category": "Phishing"}
    )
    assert res["corroboration_bonus"] == 0

def test_corroboration_bonus_rule_threshold_missed():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [{"points": 39, "explanation": "bad"}]},
        relay_analysis={},
        gemini_result={"available": True, "nlp_risk_score": 80, "threat_category": "Phishing"}
    )
    assert res["corroboration_bonus"] == 0

def test_corroboration_bonus_benign_category():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [{"points": 40, "explanation": "bad"}]},
        relay_analysis={},
        gemini_result={"available": True, "nlp_risk_score": 80, "threat_category": "Spam"}
    )
    assert res["corroboration_bonus"] == 0

def test_gemini_alone_cannot_force_high():
    res = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": []}, # 0 points
        relay_analysis={},
        gemini_result={"available": True, "nlp_risk_score": 100, "threat_category": "Phishing"}
    )
    assert res["corroboration_bonus"] == 0
    assert res["final_score"] < 50
    assert res["risk_level"] in ["Low", "Moderate"]

def test_corroboration_bonus_cap_at_100():
    res = calculate_fraud_score(
        header_analysis={"indicators": [{"severity": "high"}] * 10},
        content_analysis={"indicators": [{"points": 100, "explanation": "Very bad"}]},
        relay_analysis={},
        geolocation_result={"available": True, "proxy": True, "hosting": True},
        domain_result={"available": True, "domain_age_days": 1},
        gemini_result={"available": True, "nlp_risk_score": 100, "threat_category": "Phishing"}
    )
    assert res["corroboration_bonus"] == 30
    assert res["final_score"] == 100
