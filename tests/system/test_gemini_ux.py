"""
tests/system/test_gemini_ux.py
Tests for MailTrace AI's Gemini request experience and protection.
"""
import os
import sys
import time
import tempfile
import pytest
from streamlit.testing.v1 import AppTest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, PROJECT_ROOT)
from modules.case_database import initialize_database

APP_PATH = os.path.join(PROJECT_ROOT, "app.py")
FIXTURE_VALID = os.path.join(PROJECT_ROOT, "tests", "fixtures", "valid_plain.eml")

@pytest.fixture(scope="module")
def temp_db():
    fd, path = tempfile.mkstemp(suffix=".sqlite3")
    os.close(fd)
    yield path
    os.unlink(path)

@pytest.fixture(scope="function")
def isolate_env(temp_db):
    os.environ["DB_PATH"] = temp_db
    initialize_database(temp_db)
    yield
    if "DB_PATH" in os.environ:
        del os.environ["DB_PATH"]


def test_gemini_success_flow(isolate_env, monkeypatch):
    calls = []
    def mock_gemini(*a, **kw):
        calls.append(a)
        return {
            "available": True,
            "nlp_risk_score": 85,
            "threat_category": "Phishing",
            "urgency_cues": True,
            "financial_request": False,
            "credential_request": True,
            "impersonation_language": False,
            "secrecy_request": False,
            "explanation": "Test explanation"
        }
    monkeypatch.setattr("modules.gemini_analyzer.analyze_with_gemini", mock_gemini)

    at = AppTest.from_file(APP_PATH, default_timeout=10).run()
    with open(FIXTURE_VALID, "rb") as f:
        at.file_uploader[0].set_value(("valid_plain.eml", f.read(), "message/rfc822"))
    at.run()

    assert len(calls) == 0

    # Check consent checkbox
    at.checkbox[0].set_value(True).run()

    # Click the button
    btn = next(b for b in at.button if b.label == "Run optional AI content analysis")
    btn.click().run()
    assert len(calls) == 1

    # Rerender produces zero requests
    at.run()
    assert len(calls) == 1

    # Check successful result is cached (it's displayed)
    metrics = [m.value for m in at.metric if m.label and "Gemini content-risk score" in m.label]
    assert len(metrics) > 0
    assert "85 / 100" in metrics[0]

    # Request counters are updated internally, but the button/caption area might be hidden on success.


def test_gemini_failures_cooldown(isolate_env, monkeypatch):
    monkeypatch.setenv("GEMINI_SESSION_DAILY_LIMIT", "10")
    calls = []
    error_to_return = "503 Service Unavailable"

    def mock_gemini(*a, **kw):
        calls.append(a)
        return {
            "available": False,
            "error": error_to_return
        }
    monkeypatch.setattr("modules.gemini_analyzer.analyze_with_gemini", mock_gemini)

    at = AppTest.from_file(APP_PATH, default_timeout=10).run()
    with open(FIXTURE_VALID, "rb") as f:
        at.file_uploader[0].set_value(("valid_plain.eml", f.read(), "message/rfc822"))
    at.run()

    # Initial offline score is intact
    assert len(at.metric) == 1  # Only Rule-based initially (or something else, just check score later)

    # Enable consent checkbox
    at.checkbox[0].set_value(True).run()

    # 503 error
    btn = next(b for b in at.button if b.label == "Run optional AI content analysis")
    btn.click().run()
    assert len(calls) == 1
    toasts = [t.value for t in at.toast]
    assert any("Gemini is temporarily busy" in t for t in toasts)

    # Check "Try AI analysis again" button is shown
    btn_labels = [b.label for b in at.button]
    assert "Try AI analysis again" in btn_labels

    # Raw API error is hidden initially inside expander
    html = "\n".join([m.value for m in at.markdown if hasattr(m, 'value')])
    assert "503 Service Unavailable" not in html

    # Cooldown click produces zero requests
    btn = next(b for b in at.button if b.label == "Try AI analysis again")
    btn.click().run()
    assert len(calls) == 1
    toasts = [t.value for t in at.toast]
    assert any("AI analysis is currently busy" in t for t in toasts)

    # Fast forward time to test manual retry
    monkeypatch.setattr("time.monotonic", lambda: time.time() + 20)

    # 429 error on retry
    error_to_return = "429 Too Many Requests"
    btn = next(b for b in at.button if b.label == "Try AI analysis again")
    btn.click().run()
    assert len(calls) == 2
    toasts = [t.value for t in at.toast]
    assert any("Gemini’s free request limit" in t for t in toasts)

    # Request counters accurate
    captions = [c.value for c in at.caption]
    assert any("This session: 2 attempted" in c and "0 successful" in c for c in captions)

    # Offline results survive failure
    # Ensure Threat Assessment section is still there
    assert "Threat Assessment" in html
    assert "What this result means" in html

    # Fast forward time again to bypass the 30s cooldown set by the 429 error
    monkeypatch.setattr("time.monotonic", lambda: time.time() + 100)

    # 404 error
    error_to_return = "404 Not Found"
    btn = next(b for b in at.button if b.label == "Try AI analysis again")
    btn.click().run()
    toasts = [t.value for t in at.toast]
    assert any("configured Gemini model is unavailable" in t for t in toasts)

    # Fast forward time again to bypass the cooldown set by the 404 error
    monkeypatch.setattr("time.monotonic", lambda: time.time() + 150)

    # Timeout error
    error_to_return = "Timeout"
    btn = next(b for b in at.button if b.label == "Try AI analysis again")
    btn.click().run()
    toasts = [t.value for t in at.toast]
    assert any("Gemini could not be reached" in t for t in toasts)

    # Failed Gemini does not apply the bonus
    html_after = "\n".join([m.value for m in at.markdown if hasattr(m, 'value')])
    assert "Cross-Signal Corroboration Bonus" not in html_after
