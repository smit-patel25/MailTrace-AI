from streamlit.testing.v1 import AppTest
import os
import plotly.graph_objs as go
from modules.ui_theme import apply_chart_theme

def test_apply_chart_theme_empty_title():
    # If the chart has NO title text, it should explicitly serialize to text="" to avoid 'undefined' in frontend.
    fig = go.Figure(go.Pie(values=[1,2], labels=["A", "B"]))
    # Originally fig has no title

    fig = apply_chart_theme(fig)
    d = fig.to_dict()
    assert "title" in d["layout"]
    assert d["layout"]["title"].get("text") == ""

    # But if it has a title, it shouldn't overwrite it
    fig2 = go.Figure(go.Pie(values=[1,2], labels=["A", "B"]))
    fig2.update_layout(title_text="My Chart")
    fig2 = apply_chart_theme(fig2)
    d2 = fig2.to_dict()
    assert d2["layout"]["title"]["text"] == "My Chart"

def test_cases_origin_ip_rendering():
    cases = [
        {"case_id": "C-1", "email_hash": "h1", "created_at": "2026-09-15", "subject": "Test", "sender_address": "a@b.com", "risk_level": "High", "fraud_score": 60, "probable_origin_ip": "1.2.3.4", "verdict": "Malicious"},
        {"case_id": "C-2", "email_hash": "h2", "created_at": "2026-09-15", "subject": "Test", "sender_address": "a@b.com", "risk_level": "High", "fraud_score": 60, "probable_origin_ip": None, "verdict": "Malicious"},
        {"case_id": "C-3", "email_hash": "h3", "created_at": "2026-09-15", "subject": "Test", "sender_address": "a@b.com", "risk_level": "High", "fraud_score": 60, "probable_origin_ip": "", "verdict": "Malicious"},
        {"case_id": "C-4", "email_hash": "h4", "created_at": "2026-09-15", "subject": "Test", "sender_address": "a@b.com", "risk_level": "High", "fraud_score": 60, "probable_origin_ip": "N/A", "verdict": "Malicious"},
        {"case_id": "C-5", "email_hash": "h5", "created_at": "2026-09-15", "subject": "Test", "sender_address": "a@b.com", "risk_level": "High", "fraud_score": 60, "probable_origin_ip": "2001:0db8::ff00:42:8329", "verdict": "Malicious"},
        {"case_id": "C-6", "email_hash": "h6", "created_at": "2026-09-15", "subject": "Test", "sender_address": "a@b.com", "risk_level": "High", "fraud_score": 60, "verdict": "Malicious"} # Missing key
    ]

    app_path = os.path.join(os.path.dirname(__file__), "..", "..", "app.py")

    for case in cases:
        case_id = case["case_id"]
        if case_id == "C-1":
            expected_ip = "1.2.3.4"
        elif case_id == "C-5":
            expected_ip = "2001:0db8::ff00:42:8329"
        else:
            expected_ip = "Unavailable"

        at = AppTest.from_file(app_path, default_timeout=10)
        at.session_state["_cases"] = [case]
        at.run()
        at.switch_page("pages/1_Cases.py")
        at.run()

        # Check UI rendering
        rendered = False
        for md in at.markdown:
            if "**Origin IP:** " in md.value:
                assert md.value == f"**Origin IP:** {expected_ip}"
                rendered = True
                break

        assert rendered, f"Origin IP markdown not found for {case_id}"

        # Ensure the record was not modified in the background state
        saved_case = at.session_state["_cases"][0]
        if case_id == "C-6":
            assert "probable_origin_ip" not in saved_case
        else:
            assert saved_case["probable_origin_ip"] == case["probable_origin_ip"]
