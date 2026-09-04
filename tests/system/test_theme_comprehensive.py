"""
tests/system/test_theme_comprehensive.py
Comprehensive regression tests for the MailTrace AI theme system.
All tests are read-only with respect to analysis, scoring, and external APIs.
"""
import os
import sys
import re
import tempfile
import pytest
from streamlit.testing.v1 import AppTest

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, PROJECT_ROOT)

from modules.case_database import initialize_database
from modules import ui_theme as _theme_mod

APP_PATH       = os.path.join(PROJECT_ROOT, "app.py")
CASES_PATH     = os.path.join(PROJECT_ROOT, "pages", "1_Cases.py")
CAMPAIGNS_PATH = os.path.join(PROJECT_ROOT, "pages", "2_Campaigns.py")
DASHBOARD_PATH = os.path.join(PROJECT_ROOT, "pages", "3_Dashboard.py")
THEME_PATH     = os.path.join(PROJECT_ROOT, "modules", "ui_theme.py")
FIXTURE_VALID  = os.path.join(PROJECT_ROOT, "tests", "fixtures", "valid_plain.eml")


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


# ── 1. Source-code structural checks (no Streamlit runtime needed) ───────────

def _theme_source() -> str:
    with open(THEME_PATH, encoding="utf-8") as f:
        return f.read()

def _read(path) -> str:
    with open(path, encoding="utf-8") as f:
        return f.read()


def test_theme_source_has_apply_theme():
    assert "def apply_theme()" in _theme_source()


def test_theme_source_has_style_plotly_figure():
    assert "def style_plotly_figure(" in _theme_source()


def test_reduced_motion_css_present():
    src = _theme_source()
    assert "prefers-reduced-motion: reduce" in src
    assert "transition: none !important" in src


def test_no_emotion_class_selectors():
    """No generated Emotion class names like css-xxxxx or st-xxxxx (other than known stable ones)."""
    src = _theme_source()
    # Must not contain patterns like .css-1abc, .st-abc123 (random hashes)
    emotion = re.findall(r'\.(css-[a-z0-9]{4,}|st-[a-z0-9]{5,})\b', src)
    assert emotion == [], f"Found Emotion class selectors: {emotion}"


def test_no_hardcoded_black_white_color():
    """No raw #000000 or #FFFFFF background-color in component rules."""
    src = _theme_source()
    bg_black = re.findall(r'background-color:\s*#000000', src)
    bg_white = re.findall(r'background-color:\s*#FFFFFF', src)
    assert bg_black == []
    assert bg_white == []


def test_dark_palette_vars_defined():
    src = _theme_source()
    required = [
        "--app-bg", "--surface-primary", "--surface-secondary", "--surface-elevated",
        "--text-primary", "--text-secondary", "--text-muted", "--border-primary",
        "--accent-primary", "--success", "--warning", "--danger", "--focus-ring",
    ]
    for var in required:
        assert var in src, f"Missing CSS variable: {var}"


def test_input_disabled_webkit_fill_color():
    """Disabled inputs must use -webkit-text-fill-color to override Safari opacity."""
    src = _theme_source()
    assert "-webkit-text-fill-color" in src


def test_input_disabled_opacity_one():
    src = _theme_source()
    # opacity: 1 for disabled fields
    assert "opacity:                 1" in src or "opacity: 1 !important" in src


def test_code_block_vars_present():
    src = _theme_source()
    assert "--code-bg:" in src
    assert "--code-text:" in src


def test_uploader_vars_present():
    src = _theme_source()
    assert "background-color: transparent !important" in src
    assert "stFileUploaderDropzone" in src


def test_table_vars_present():
    src = _theme_source()
    assert "--table-header-bg:" in src
    assert "--table-body-bg:" in src
    assert "--table-border:" in src


def test_card_vars_present():
    src = _theme_source()
    assert "--card-bg:" in src
    assert "--card-heading:" in src


def test_plotly_helper_covers_legend():
    src = _theme_source()
    assert "legend_color" in src
    assert "legend=" in src


def test_plotly_helper_covers_hoverlabel():
    src = _theme_source()
    assert "hoverlabel" in src


def test_plotly_helper_covers_grid():
    src = _theme_source()
    assert "gridcolor" in src


def test_plotly_helper_transparent_backgrounds():
    src = _theme_source()
    assert "rgba(0,0,0,0)" in src


def test_apply_chart_theme_alias_exists():
    """apply_chart_theme must still exist for backward compatibility."""
    assert hasattr(_theme_mod, "apply_chart_theme")


def test_style_plotly_figure_callable():
    assert callable(getattr(_theme_mod, "style_plotly_figure", None))


def test_tab_accent_not_danger_color():
    src = _theme_source()
    assert "var(--accent-primary)" in src, "accent-primary variable not found in theme"
    lines = src.split("\n")
    tab_lines = [l for l in lines if "stTabs" in l or "aria-selected" in l]
    for line in tab_lines:
        assert "var(--danger)" not in line, f"Danger color in tab selector: {line.strip()}"


def test_uploader_outer_bg_is_transparent():
    """The outer stFileUploader wrapper must be transparent, not a filled surface."""
    src = _theme_source()
    assert "background-color: transparent !important" in src


# ── 2. Runtime / AppTest checks ──────────────────────────────────────────────

def test_dashboard_renders_without_exception(isolate_env):
    at = AppTest.from_file(APP_PATH, default_timeout=10).run()
    at.switch_page("pages/3_Dashboard.py")
    at.run()
    assert not at.exception


def test_campaigns_renders_without_exception(isolate_env):
    at = AppTest.from_file(APP_PATH, default_timeout=10).run()
    at.switch_page("pages/2_Campaigns.py")
    at.run()
    assert not at.exception


def test_cases_renders_without_exception(isolate_env):
    at = AppTest.from_file(APP_PATH, default_timeout=10).run()
    at.switch_page("pages/1_Cases.py")
    at.run()
    assert not at.exception


# ── 3. WCAG contrast spot-checks (calculated, not browser-measured) ──────────

def _relative_luminance(hex_color: str) -> float:
    """Calculate relative luminance per WCAG 2.1."""
    hex_color = hex_color.lstrip("#")
    r, g, b = (int(hex_color[i:i+2], 16) / 255.0 for i in (0, 2, 4))
    def linearize(c):
        return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4
    return 0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b)


def _contrast(fg: str, bg: str) -> float:
    L1 = _relative_luminance(fg)
    L2 = _relative_luminance(bg)
    lighter, darker = max(L1, L2), min(L1, L2)
    return (lighter + 0.05) / (darker + 0.05)


@pytest.mark.parametrize("fg,bg,label", [
    ("#F1F5F9", "#050E17",  "dark text-primary on app-bg"),
    ("#F1F5F9", "#0B1928",  "dark text-primary on surface-primary"),
    ("#F1F5F9", "#101F30",  "dark text-primary on surface-secondary"),
    ("#CBD5E1", "#101F30",  "dark text-secondary on surface-secondary"),
    ("#CBD5E1", "#0B1928",  "dark text-secondary on sidebar-bg"),
    ("#F1F5F9", "#101F30",  "dark input-text on input-bg"),
    ("#CBD5E1", "#101F30",  "dark input-text-disabled on input-bg-disabled"),
    ("#D6E4FF", "#152638",  "dark code-text on code-bg"),
    ("#F1F5F9", "#152638",  "dark table-header-text on table-header-bg"),
    ("#CBD5E1", "#101F30",  "dark table-body-text on table-body-bg"),
])
def test_wcag_contrast_4_5(fg, bg, label):
    ratio = _contrast(fg, bg)
    assert ratio >= 4.5, f"WCAG AA fail ({ratio:.2f}:1) — {label}"


@pytest.mark.parametrize("fg,bg,label", [
    ("#19C3E6", "#050E17",  "dark accent-primary on app-bg (large text)"),
    ("#2DBE8C", "#101F30",  "dark success badge on card"),
])
def test_wcag_contrast_3_1_large(fg, bg, label):
    ratio = _contrast(fg, bg)
    assert ratio >= 3.0, f"WCAG AA Large fail ({ratio:.2f}:1) — {label}"


# ── 4. Spacing / padding token checks ────────────────────────────────────────

def test_shared_padding_tokens_defined():
    src = _theme_source()
    assert "--card-padding:" in src
    assert "--input-pad-x:" in src
    assert "--cell-pad-x:" in src
    assert "--radius-md:" in src


def test_no_negative_margins_in_theme():
    src = _theme_source()
    neg = re.findall(r'margin[^:]*:\s*-\d', src)
    assert neg == [], f"Negative margin found: {neg}"
