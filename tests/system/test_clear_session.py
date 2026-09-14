"""
tests/system/test_clear_session.py

Behavioral regression tests for the Clear Session Data privacy control.
"""
import socket
import pytest
import streamlit as st

from modules.session_case_store import (
    _init_store,
    clear_all_session_data,
    save_case,
    list_cases,
    get_campaigns,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_case(email_hash="abc123"):
    return {
        "email_hash": email_hash,
        "subject": "Test",
        "sender_address": "a@b.com",
        "sender_domain": "b.com",
        "filename": "test.eml",
        "fraud_score": 10,
        "risk_level": "Low",
        "verdict": "Likely Safe",
        "probable_origin_ip": "1.2.3.4",
        "analyzer_results": {},
    }


def _populate_sensitive(session):
    session["_cases"] = [{"case_id": "C1"}]
    session["_campaigns"] = [{"campaign_id": "CAMP1"}]
    session["active_source"] = "upload"
    session["active_demo_key"] = "credential_phishing"
    session["last_uploaded_name"] = "evil.eml"
    session["current_file_name"] = "evil.eml"
    session["geo_result"] = {"lat": 1.0, "lon": 2.0}
    session["domain_result"] = {"registrar": "shady"}
    session["view_campaign"] = "CAMP1"
    session["gemini_abc123"] = {"available": True}
    session["gemini_lock_abc123"] = False
    session["gemini_cooldown_abc123"] = 0
    session["gemini_consent_abc123"] = True
    session["evidence_manifest_abc123"] = {"manifest_version": "1.0"}
    session["gemini_attempts"] = 5
    session["gemini_successes"] = 3
    session["gemini_failures"] = 2


# ---------------------------------------------------------------------------
# Unit-level tests
# ---------------------------------------------------------------------------

class TestClearAllSessionData:

    def setup_method(self):
        st.session_state.clear()
        _init_store()

    def test_confirm_clears_cases(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert st.session_state["_cases"] == []

    def test_confirm_clears_campaigns(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert st.session_state["_campaigns"] == []

    def test_confirm_clears_active_source(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "active_source" not in st.session_state

    def test_confirm_clears_active_demo_key(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "active_demo_key" not in st.session_state

    def test_confirm_clears_last_uploaded_name(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "last_uploaded_name" not in st.session_state

    def test_confirm_clears_current_file_name(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "current_file_name" not in st.session_state

    def test_confirm_clears_geo_result(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "geo_result" not in st.session_state

    def test_confirm_clears_domain_result(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "domain_result" not in st.session_state

    def test_confirm_clears_view_campaign(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "view_campaign" not in st.session_state

    def test_confirm_clears_gemini_result(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "gemini_abc123" not in st.session_state

    def test_confirm_preserves_gemini_lock(self):
        """Abuse-prevention locks must survive clearing."""
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "gemini_lock_abc123" in st.session_state

    def test_confirm_preserves_gemini_cooldown(self):
        """Abuse-prevention cooldowns must survive clearing."""
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "gemini_cooldown_abc123" in st.session_state

    def test_confirm_clears_gemini_consent(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "gemini_consent_abc123" not in st.session_state

    def test_confirm_clears_evidence_manifest(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert "evidence_manifest_abc123" not in st.session_state

    def test_quota_counters_preserved_after_clear(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert st.session_state.get("gemini_attempts") == 5
        assert st.session_state.get("gemini_successes") == 3
        assert st.session_state.get("gemini_failures") == 2

    def test_uploader_key_bumped_after_clear(self):
        st.session_state["_uploader_key"] = 7
        clear_all_session_data()
        assert st.session_state.get("_uploader_key") == 8

    def test_uploader_key_initialized_if_absent(self):
        assert "_uploader_key" not in st.session_state
        clear_all_session_data()
        assert "_uploader_key" in st.session_state
        assert isinstance(st.session_state["_uploader_key"], int)

    def test_repeated_clear_is_safe(self):
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        clear_all_session_data()
        clear_all_session_data()
        assert st.session_state["_cases"] == []
        assert st.session_state.get("gemini_attempts") == 5

    def test_clear_on_empty_state_is_safe(self):
        clear_all_session_data()
        assert st.session_state["_cases"] == []

    def test_session_a_does_not_affect_session_b(self):
        state_a = {}
        _populate_sensitive(state_a)
        import copy
        state_b = copy.deepcopy(state_a)
        st.session_state.update(state_a)
        clear_all_session_data()
        assert state_b["_cases"] == [{"case_id": "C1"}]
        assert state_b.get("active_source") == "upload"
        assert state_b.get("geo_result") is not None

    def test_clear_triggers_no_network(self, monkeypatch):
        def _block(*args, **kwargs):
            raise AssertionError("clear_all_session_data made a network call")
        monkeypatch.setattr(socket, "create_connection", _block)
        monkeypatch.setattr(socket, "getaddrinfo", _block)
        monkeypatch.setattr(socket.socket, "connect", _block)
        _populate_sensitive(st.session_state)
        clear_all_session_data()
        assert st.session_state["_cases"] == []

    def test_save_case_then_clear(self):
        save_case(_make_case("hash001"))
        assert len(list_cases()) == 1
        clear_all_session_data()
        assert list_cases() == []

    def test_multiple_manifests_all_cleared(self):
        for h in ["aaa", "bbb", "ccc"]:
            st.session_state[f"evidence_manifest_{h}"] = {"manifest_version": "1.0"}
            st.session_state[f"gemini_{h}"] = {"available": True}
            st.session_state[f"gemini_consent_{h}"] = True
        clear_all_session_data()
        for h in ["aaa", "bbb", "ccc"]:
            assert f"evidence_manifest_{h}" not in st.session_state
            assert f"gemini_{h}" not in st.session_state
            assert f"gemini_consent_{h}" not in st.session_state


# ---------------------------------------------------------------------------
# AppTest-level tests
# ---------------------------------------------------------------------------

import os
import sys
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
sys.path.insert(0, PROJECT_ROOT)
APP_PATH = os.path.join(PROJECT_ROOT, "app.py")


class TestClearSessionAppTest:

    def test_clear_button_present_in_sidebar(self):
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(APP_PATH, default_timeout=10).run()
        assert not at.exception
        button_labels = [b.label for b in at.button]
        assert any("Clear session data" in lbl for lbl in button_labels)

    def test_cancel_preserves_state(self):
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(APP_PATH, default_timeout=10).run()
        assert not at.exception

        at.session_state["_cases"] = [{"case_id": "SENTINEL"}]
        at.session_state["geo_result"] = {"lat": 9.9}

        clear_btn = next(
            (b for b in at.button if "Clear session data" in b.label), None
        )
        assert clear_btn is not None, "Clear session data button not found"
        clear_btn.click().run()
        assert not at.exception

        cancel_btn = next(
            (b for b in at.button if "Cancel" in b.label), None
        )
        assert cancel_btn is not None, "Cancel button not found after entering confirm state"
        cancel_btn.click().run()
        assert not at.exception

        assert "_cases" in at.session_state and at.session_state["_cases"] == [{"case_id": "SENTINEL"}]
        assert "geo_result" in at.session_state and at.session_state["geo_result"] == {"lat": 9.9}
        assert "_clear_confirm" not in at.session_state or not at.session_state["_clear_confirm"]

    def test_confirm_clears_state_via_apptest(self):
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(APP_PATH, default_timeout=10).run()
        assert not at.exception

        at.session_state["_cases"] = [{"case_id": "SHOULDBEGONE"}]
        at.session_state["geo_result"] = {"lat": 1.0}
        at.session_state["gemini_attempts"] = 7

        clear_btn = next(
            (b for b in at.button if "Clear session data" in b.label), None
        )
        assert clear_btn is not None
        clear_btn.click().run()
        assert not at.exception

        confirm_btn = next(
            (b for b in at.button if "Confirm" in b.label), None
        )
        assert confirm_btn is not None
        confirm_btn.click().run()
        assert not at.exception

        assert "_cases" not in at.session_state or at.session_state["_cases"] == []
        assert "geo_result" not in at.session_state
        assert "gemini_attempts" in at.session_state and at.session_state["gemini_attempts"] == 7
        assert "_clear_confirm" not in at.session_state or not at.session_state["_clear_confirm"]

    def test_cases_page_handles_empty_state_after_clear(self):
        """Cases page must render without error when the store is empty."""
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(APP_PATH, default_timeout=10).run()
        assert not at.exception
        at.switch_page("pages/1_Cases.py")
        at.run()
        assert not at.exception
        assert any("No cases found" in m.value for m in at.info)

    def test_campaigns_page_handles_empty_state_after_clear(self):
        """Campaigns page must render without error when the store is empty."""
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(APP_PATH, default_timeout=10).run()
        assert not at.exception
        at.switch_page("pages/2_Campaigns.py")
        at.run()
        assert not at.exception
        infos = [m.value for m in at.info]
        assert any("No cases available" in i or "No active campaigns" in i for i in infos)

    def test_dashboard_handles_empty_state_after_clear(self):
        """Dashboard page must render without error when the store is empty."""
        from streamlit.testing.v1 import AppTest
        at = AppTest.from_file(APP_PATH, default_timeout=10).run()
        assert not at.exception
        at.switch_page("pages/3_Dashboard.py")
        at.run()
        assert not at.exception
        assert any("No cases found" in m.value for m in at.info)
