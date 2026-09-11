import os
import re
import pytest
from unittest.mock import patch, MagicMock
from modules.risk_scoring import calculate_fraud_score
import hashlib

_APP_PY = os.path.join(os.path.dirname(__file__), "..", "app.py")


def test_attachment_forensics_rendered_exactly_once():
    """UI regression: app.py must call section_header("Attachment Forensics", ...)
    exactly once so the section is never duplicated on the Analyze Email page,
    regardless of whether the email has attachments or not.
    """
    with open(_APP_PY, encoding="utf-8") as fh:
        source = fh.read()

    # Count non-comment occurrences of the section_header call for Attachment Forensics.
    # Strip single-line comments first to avoid matching commented-out dead code.
    non_comment_lines = [
        line for line in source.splitlines()
        if not line.lstrip().startswith("#")
    ]
    source_no_comments = "\n".join(non_comment_lines)

    occurrences = re.findall(
        r'section_header\s*\(\s*["\']Attachment Forensics["\']',
        source_no_comments,
    )
    assert len(occurrences) == 1, (
        f"Expected exactly 1 section_header('Attachment Forensics', ...) call in app.py, "
        f"found {len(occurrences)}: {occurrences}"
    )



def get_hash(content):
    return hashlib.sha256(content).hexdigest()

def test_gemini_changes_final_score():
    # Base scenario
    res_base = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [{"points": 30, "explanation": "bad"}]},
        relay_analysis={},
        gemini_result=None
    )
    score_base = res_base["final_score"]
    
    # With Gemini 92/100
    res_gemini = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [{"points": 30, "explanation": "bad"}]},
        relay_analysis={},
        gemini_result={"available": True, "nlp_risk_score": 92, "threat_category": "Phishing"}
    )
    score_gemini = res_gemini["final_score"]
    
    # Prove score changes
    assert score_base != score_gemini
    assert score_gemini > score_base # Since 92 brings the average up
    assert res_gemini["component_scores"]["content_risk"] == min(25, int(((30 + 92)/2.0/100)*25))

def test_gemini_failure_preserves_offline_scoring():
    res_base = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [{"points": 30, "explanation": "bad"}]},
        relay_analysis={},
        gemini_result=None
    )
    
    res_fail = calculate_fraud_score(
        header_analysis={},
        content_analysis={"indicators": [{"points": 30, "explanation": "bad"}]},
        relay_analysis={},
        gemini_result={"available": False, "error": "API Error"}
    )
    
    assert res_base["final_score"] == res_fail["final_score"]
    assert "Gemini Analysis" in res_fail["unavailable_sources"]

def test_result_isolation_and_rerun():
    # Simulating the session state logic in app.py
    session_state = {}
    
    email_A = b"email A content"
    hash_A = get_hash(email_A)
    
    email_B = b"email B content"
    hash_B = get_hash(email_B)
    
    # Simulate Gemini running for A
    gemini_key_A = f"gemini_{hash_A}"
    
    api_calls = 0
    def mock_analyze_with_gemini(*args):
        nonlocal api_calls
        api_calls += 1
        return {"available": True, "nlp_risk_score": 92}
        
    def simulate_button_click_app_flow(email_bytes, button_clicked):
        h = get_hash(email_bytes)
        g_key = f"gemini_{h}"
        
        rerun_called = False
        
        if button_clicked:
            if g_key not in session_state:
                res = mock_analyze_with_gemini()
                session_state[g_key] = res
                rerun_called = True
                
        return session_state.get(g_key), rerun_called
        
    # Email A - First run, button clicked
    res_A, rerun_A = simulate_button_click_app_flow(email_A, True)
    assert rerun_A is True
    assert api_calls == 1
    assert res_A == {"available": True, "nlp_risk_score": 92}
    
    # Email A - Rerun simulated (button is typically false or true, but key is in state)
    res_A_rerun, rerun_A_rerun = simulate_button_click_app_flow(email_A, True)
    assert rerun_A_rerun is False
    assert api_calls == 1 # API NOT CALLED AGAIN
    assert res_A_rerun == {"available": True, "nlp_risk_score": 92}
    
    # Email B - Uploaded, button not clicked yet
    res_B, rerun_B = simulate_button_click_app_flow(email_B, False)
    assert res_B is None # Email B does NOT use A's result
    assert rerun_B is False
    assert api_calls == 1
