"""
tests/system/test_sidebar_navigation.py
Tests for MailTrace AI's sidebar navigation and structural integrity.
"""
import os
import re
import sys
import tempfile
import pytest
from streamlit.testing.v1 import AppTest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, PROJECT_ROOT)

APP_PATH = os.path.join(PROJECT_ROOT, "app.py")
CASES_PATH = os.path.join(PROJECT_ROOT, "pages", "1_Cases.py")
CAMPAIGNS_PATH = os.path.join(PROJECT_ROOT, "pages", "2_Campaigns.py")
DASHBOARD_PATH = os.path.join(PROJECT_ROOT, "pages", "3_Dashboard.py")
THEME_PATH = os.path.join(PROJECT_ROOT, "modules", "ui_theme.py")
CONFIG_PATH = os.path.join(PROJECT_ROOT, ".streamlit", "config.toml")


def test_sidebar_navigation_called_all_pages():
    for p in [APP_PATH, CASES_PATH, CAMPAIGNS_PATH, DASHBOARD_PATH]:
        with open(p, "r", encoding="utf-8") as f:
            content = f.read()
            assert "sidebar_navigation()" in content, f"sidebar_navigation() not called in {p}"


def test_sidebar_navigation_function_uses_sidebar():
    with open(THEME_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # Check that sidebar_navigation uses `with st.sidebar:`
    block = re.search(r'def sidebar_navigation\(\):.*?with st\.sidebar:', content, re.DOTALL)
    assert block is not None, "sidebar_navigation() must use `with st.sidebar:`"

    # Check all four links exist
    assert 'st.page_link("app.py"' in content
    assert 'st.page_link("pages/1_Cases.py"' in content
    assert 'st.page_link("pages/2_Campaigns.py"' in content
    assert 'st.page_link("pages/3_Dashboard.py"' in content


def test_show_sidebar_navigation_false_configured():
    with open(CONFIG_PATH, "r", encoding="utf-8") as f:
        content = f.read()
    assert "showSidebarNavigation = false" in content


def test_initial_sidebar_state_expanded():
    for p in [APP_PATH, CASES_PATH, CAMPAIGNS_PATH, DASHBOARD_PATH]:
        with open(p, "r", encoding="utf-8") as f:
            content = f.read()
            assert 'initial_sidebar_state="expanded"' in content, f"initial_sidebar_state not expanded in {p}"


def test_no_css_hides_sidebar_controls():
    with open(THEME_PATH, "r", encoding="utf-8") as f:
        content = f.read()

    # Check that we don't hide or forcefully reposition the sidebar controls
    # Look for [data-testid="stSidebarCollapsedControl"]
    assert "stSidebarCollapsedControl" not in content, "Do not target native collapse controls in CSS"
    assert "stSidebarCollapseButton" not in content, "Do not target native collapse controls in CSS"
    assert '[data-testid="stHeader"]' not in content, "Do not target stHeader in CSS"


def test_navigation_zero_external_api_calls(monkeypatch):
    calls = []
    def _no_call(*a, **kw): calls.append(a)
    monkeypatch.setattr("modules.gemini_analyzer.analyze_with_gemini", _no_call, raising=False)
    monkeypatch.setattr("modules.geolocation.geolocate_ip",           _no_call, raising=False)
    monkeypatch.setattr("modules.domain_intelligence.analyze_domain", _no_call, raising=False)

    at = AppTest.from_file(APP_PATH, default_timeout=10).run()
    assert not at.exception
    assert len(calls) == 0, "Navigation/App load must produce zero external API calls"
