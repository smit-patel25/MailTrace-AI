import os
import re
import sys
import pytest
from streamlit.testing.v1 import AppTest

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app import DEMO_SAMPLES, get_demo_file_data
from modules.email_parser import parse_eml_bytes
from modules.header_analyzer import analyze_headers
from modules.content_analyzer import analyze_content
from modules.relay_analyzer import analyze_relay_chain
from modules.risk_scoring import calculate_fraud_score

APP_PATH = os.path.join(PROJECT_ROOT, "app.py")
FIXTURE_VALID = os.path.join(PROJECT_ROOT, "tests", "fixtures", "valid_plain.eml")


def test_demo_allowlist_structure_and_paths():
    """Requirement 10: Fixed allowlist mapping exists and prevents arbitrary paths."""
    assert len(DEMO_SAMPLES) == 3
    expected_keys = {"legitimate_team_update", "credential_phishing", "executive_bec_request"}
    assert set(DEMO_SAMPLES.keys()) == expected_keys

    for key, sample in DEMO_SAMPLES.items():
        assert os.path.exists(sample["path"])
        assert sample["filename"].endswith(".eml")

    with pytest.raises(ValueError, match="Invalid demo identifier"):
        get_demo_file_data("non_existent_key")

    with pytest.raises(ValueError, match="Invalid demo identifier"):
        get_demo_file_data("../../../etc/passwd")


def test_demo_fixtures_safety_synthetic_domains_and_defanged_urls():
    """Requirements 11 & 12: Synthetic identities, .example/.test domains, no active http/https URLs."""
    for key, sample in DEMO_SAMPLES.items():
        content, _ = get_demo_file_data(key)
        text_content = content.decode("utf-8", errors="ignore")

        # Check for active http:// or https:// URLs
        active_urls = re.findall(r'https?://[^\s"<>\']+', text_content, flags=re.IGNORECASE)
        assert len(active_urls) == 0, f"Found active URL in {key}: {active_urls}"

        # Verify only synthetic domains used
        domains_found = re.findall(r'@([\w.-]+)', text_content)
        for domain in domains_found:
            clean_d = domain.lower().strip('>').rstrip(';')
            assert clean_d.endswith(".example") or clean_d.endswith(".test"), f"Non-synthetic domain in {key}: {clean_d}"


def test_all_demo_samples_load_parse_and_score():
    """Requirements 1, 2, 3, 4, 5, 6: Load, parse through production pipeline, and verify risk scores."""
    # Legitimate Email
    legit_bytes, _ = get_demo_file_data("legitimate_team_update")
    legit_parsed = parse_eml_bytes(legit_bytes)
    assert len(legit_parsed.get("defects", [])) == 0
    legit_header = analyze_headers(legit_parsed)
    legit_content = analyze_content(legit_parsed)
    legit_relay = analyze_relay_chain(legit_parsed)
    legit_score = calculate_fraud_score(legit_header, legit_content, legit_relay)
    assert legit_score["risk_level"] == "Low"
    assert legit_score["final_score"] <= 24

    # Credential Phishing
    phish_bytes, _ = get_demo_file_data("credential_phishing")
    phish_parsed = parse_eml_bytes(phish_bytes)
    assert len(phish_parsed.get("defects", [])) == 0
    phish_header = analyze_headers(phish_parsed)
    phish_content = analyze_content(phish_parsed)
    phish_relay = analyze_relay_chain(phish_parsed)
    phish_score = calculate_fraud_score(phish_header, phish_content, phish_relay)
    assert phish_score["risk_level"] in ["High", "Severe"]
    assert phish_score["final_score"] >= 50

    # Executive BEC Scam
    bec_bytes, _ = get_demo_file_data("executive_bec_request")
    bec_parsed = parse_eml_bytes(bec_bytes)
    assert len(bec_parsed.get("defects", [])) == 0
    bec_header = analyze_headers(bec_parsed)
    bec_content = analyze_content(bec_parsed)
    bec_relay = analyze_relay_chain(bec_parsed)
    bec_score = calculate_fraud_score(bec_header, bec_content, bec_relay)
    assert bec_score["risk_level"] in ["High", "Severe"]
    assert bec_score["final_score"] >= 50


def test_app_demo_mode_ui_and_no_external_api_calls(monkeypatch):
    """Requirements 7 & 13: Demo options load offline without triggering external APIs; controls have labels."""
    gemini_called = False
    geo_called = False
    domain_called = False

    def mock_gemini(*args, **kwargs):
        nonlocal gemini_called
        gemini_called = True
        return {"available": False}

    def mock_geo(*args, **kwargs):
        nonlocal geo_called
        geo_called = True
        return {"available": False}

    def mock_domain(*args, **kwargs):
        nonlocal domain_called
        domain_called = True
        return {"available": False}

    monkeypatch.setattr("modules.gemini_analyzer.analyze_with_gemini", mock_gemini)
    monkeypatch.setattr("modules.geolocation.geolocate_ip", mock_geo)
    monkeypatch.setattr("modules.domain_intelligence.analyze_domain", mock_domain)

    at = AppTest.from_file(APP_PATH, default_timeout=10).run()
    assert not at.exception

    # Accessible labels check
    button_labels = [b.label for b in at.button]
    assert any("Legitimate Email" in label for label in button_labels)
    assert any("Credential Phishing" in label for label in button_labels)
    assert any("Executive BEC Scam" in label for label in button_labels)

    # Click Legitimate Email demo button
    legit_button_idx = next(i for i, b in enumerate(at.button) if "Legitimate Email" in b.label)
    at.button[legit_button_idx].click().run()

    assert not at.exception
    markdown_text = " ".join([m.value for m in at.markdown])
    assert "Demo sample" in markdown_text
    assert "Offline analysis — no external services called" in markdown_text
    assert "Legitimate Email" in markdown_text

    # Verify 0 external calls occurred automatically
    assert not gemini_called
    assert not geo_called
    assert not domain_called


def test_app_demo_sample_switching_and_state_isolation():
    """Requirements 9 & 10: Switching demo samples resets email-specific state without clearing global state."""
    at = AppTest.from_file(APP_PATH, default_timeout=10).run()

    # Load Legitimate Demo
    legit_idx = next(i for i, b in enumerate(at.button) if "Legitimate Email" in b.label)
    at.button[legit_idx].click().run()
    assert not at.exception

    # Simulate email-specific cached result
    at.session_state["geo_result"] = {"fake": "geo"}
    at.session_state["gemini_abc123"] = {"fake": "gemini"}
    at.session_state["custom_global_var"] = "preserve_me"

    # Switch to Phishing Demo
    phish_idx = next(i for i, b in enumerate(at.button) if "Credential Phishing" in b.label)
    at.button[phish_idx].click().run()
    assert not at.exception

    # Email-specific state should be cleared
    assert "geo_result" not in at.session_state
    assert "gemini_abc123" not in at.session_state
    # Unrelated state preserved
    assert "custom_global_var" in at.session_state
    assert at.session_state["custom_global_var"] == "preserve_me"

    markdown_text = " ".join([m.value for m in at.markdown])
    assert "Credential Phishing" in markdown_text


def test_upload_and_demo_coexistence():
    """Requirement 8 & 11: Normal upload workflow still works and switches cleanly with demo mode."""
    at = AppTest.from_file(APP_PATH, default_timeout=10).run()

    # 1. Test normal file upload first
    with open(FIXTURE_VALID, "rb") as f:
        at.file_uploader[0].set_value(("valid_plain.eml", f.read(), "message/rfc822"))
    at.run()
    assert not at.exception
    assert any("Email parsed successfully!" in s.value for s in at.success)

    # 2. Switch to demo mode
    bec_idx = next(i for i, b in enumerate(at.button) if "Executive BEC Scam" in b.label)
    at.button[bec_idx].click().run()
    assert not at.exception

    markdown_text = " ".join([m.value for m in at.markdown])
    assert "Executive BEC Scam" in markdown_text
    assert "Demo sample" in markdown_text


def test_demo_button_animation_css_and_keys():
    """Requirement 8: Verify stable button keys, scoped CSS animations, and prefers-reduced-motion."""
    at = AppTest.from_file(APP_PATH, default_timeout=10).run()
    assert not at.exception

    # 1. Check stable keys
    button_keys = [b.key for b in at.button if b.key]
    assert "demo_legitimate" in button_keys
    assert "demo_credential_phishing" in button_keys
    assert "demo_executive_bec" in button_keys

    # 2. Check UI theme source for scoped animation rules
    import inspect
    from modules.ui_theme import apply_theme
    theme_code = inspect.getsource(apply_theme)

    assert "st-key-demo_legitimate" in theme_code
    assert "st-key-demo_credential_phishing" in theme_code
    assert "st-key-demo_executive_bec" in theme_code
    assert "translateY(-2px)" in theme_code
    assert "prefers-reduced-motion: reduce" in theme_code


def test_gemini_privacy_consent_safeguard(monkeypatch):
    """Verify Gemini privacy consent checkbox, guidance text, disabled state, manual click requirement, and consent reset on email change."""
    calls = []
    def mock_gemini(*args, **kwargs):
        calls.append(args)
        return {"available": True, "nlp_risk_score": 75, "threat_category": "BEC"}

    monkeypatch.setattr("modules.gemini_analyzer.analyze_with_gemini", mock_gemini)

    at = AppTest.from_file(APP_PATH, default_timeout=10).run()

    # Load Legitimate Demo email
    legit_idx = next(i for i, b in enumerate(at.button) if "Legitimate Email" in b.label)
    at.button[legit_idx].click().run()

    # 1. Verify privacy guidance panel & note present
    markdown_text = " ".join([m.value for m in at.markdown])
    assert "Gemini AI Privacy & Data Handling" in markdown_text
    assert "Offline analysis does not send email content externally" in markdown_text
    assert "Privacy Note:" in markdown_text

    # 2. Verify checkbox present
    assert len(at.checkbox) > 0
    consent_box = at.checkbox[0]
    assert "I understand that email content will be sent to Google Gemini" in consent_box.label

    # 3. Gemini button disabled initially without consent
    gemini_btn = next(b for b in at.button if b.label in ["Run optional AI content analysis", "Try AI analysis again"])
    assert gemini_btn.disabled is True

    # 4. Checking consent alone makes 0 Gemini calls
    consent_box.set_value(True).run()
    assert len(calls) == 0

    # Re-query button state after rerun with consent checked
    gemini_btn = next(b for b in at.button if b.label in ["Run optional AI content analysis", "Try AI analysis again"])
    assert gemini_btn.disabled is False

    # 5. One manual click calls Gemini exactly once
    gemini_btn.click().run()
    assert len(calls) == 1

    # 6. Ordinary rerun preserves consent
    at.run()
    assert len(calls) == 1

    # 7. Switching emails resets consent
    phish_idx = next(i for i, b in enumerate(at.button) if "Credential Phishing" in b.label)
    at.button[phish_idx].click().run()

    # Re-query checkbox for new email
    if len(at.checkbox) > 0:
        new_consent_box = at.checkbox[0]
        assert new_consent_box.value is False
