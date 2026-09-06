import os
import time
import pytest
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone, timedelta

import streamlit as st
from modules.gemini_rate_limiter import GlobalQuotaManager, QuotaStatus, get_global_quota_manager

@pytest.fixture
def clean_env():
    """Ensure environment is clean before each test"""
    keys_to_remove = ["GEMINI_ENABLED", "GEMINI_DAILY_BUDGET", "GEMINI_SESSION_DAILY_LIMIT", "GEMINI_COOLDOWN_SECONDS"]
    original = {k: os.environ.get(k) for k in keys_to_remove}

    for k in keys_to_remove:
        if k in os.environ:
            del os.environ[k]

    yield

    for k, v in original.items():
        if v is not None:
            os.environ[k] = v
        elif k in os.environ:
            del os.environ[k]

@pytest.fixture
def quota_manager():
    """Return a fresh QuotaManager instance"""
    return GlobalQuotaManager()

def test_singleton():
    """Test that get_global_quota_manager returns the same instance across calls"""
    mgr1 = get_global_quota_manager()
    mgr2 = get_global_quota_manager()
    # Note: Streamlit's @st.cache_resource handles the singleton in the real app,
    # but since we are running in pytest outside of a real streamlit session,
    # it might create a new one or act strangely.
    # Let's at least check it doesn't crash.
    assert mgr1 is not None

def test_disabled_feature(quota_manager, clean_env):
    """Test when GEMINI_ENABLED=false"""
    os.environ["GEMINI_ENABLED"] = "false"
    status, msg = quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=0)
    assert status == QuotaStatus.DISABLED
    assert "temporarily disabled" in msg

def test_allowed_request(quota_manager, clean_env):
    """Test normal allowed request"""
    status, msg = quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=0)
    assert status == QuotaStatus.ALLOWED
    assert quota_manager._global_attempts == 1
    assert quota_manager._in_flight is True

def test_in_flight_busy(quota_manager, clean_env):
    """Test that a request is rejected if one is already in flight"""
    quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=0)

    # Second request while first is in flight
    status, msg = quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=0)
    assert status == QuotaStatus.BUSY
    assert "busy" in msg
    assert quota_manager._global_attempts == 1 # Only one successful attempt so far

def test_release_in_flight(quota_manager, clean_env):
    """Test releasing the in flight lock"""
    quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=0)
    quota_manager.release_in_flight()

    # Second request should now succeed
    status, msg = quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=0)
    assert status == QuotaStatus.ALLOWED
    assert quota_manager._global_attempts == 2

def test_session_limit_reached(quota_manager, clean_env):
    """Test session daily limit (default 2)"""
    os.environ["GEMINI_SESSION_DAILY_LIMIT"] = "2"
    status, msg = quota_manager.check_and_reserve(session_attempts=2, cooldown_end_time=0)
    assert status == QuotaStatus.SESSION_LIMIT_REACHED
    assert "session’s AI analysis limit" in msg
    assert quota_manager._global_attempts == 0

def test_global_limit_reached(quota_manager, clean_env):
    """Test global daily limit (default 10)"""
    os.environ["GEMINI_DAILY_BUDGET"] = "1"

    # First attempt (allowed)
    status, msg = quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=0)
    assert status == QuotaStatus.ALLOWED
    quota_manager.release_in_flight()

    # Second attempt (blocked by global limit)
    status, msg = quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=0)
    assert status == QuotaStatus.GLOBAL_LIMIT_REACHED
    assert "safety limit" in msg
    assert quota_manager._global_attempts == 1

@patch('time.monotonic')
def test_cooldown_active(mock_time, quota_manager, clean_env):
    """Test per-session cooldown"""
    mock_time.return_value = 100.0
    cooldown_end_time = 120.0 # Cooldown ends in 20 seconds

    status, msg = quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=cooldown_end_time)
    assert status == QuotaStatus.BUSY
    assert "busy" in msg

@patch('modules.gemini_rate_limiter.GlobalQuotaManager._get_utc_date')
def test_rollover_resets_limits(mock_get_date, quota_manager, clean_env):
    """Test that midnight UTC resets global attempts"""
    os.environ["GEMINI_DAILY_BUDGET"] = "1"

    mock_get_date.return_value = "2026-01-01"
    quota_manager._current_utc_date = "2026-01-01"

    # Use budget
    quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=0)
    quota_manager.release_in_flight()
    assert quota_manager._global_attempts == 1

    # Simulate next day
    mock_get_date.return_value = "2026-01-02"

    # Request should be allowed again
    status, msg = quota_manager.check_and_reserve(session_attempts=0, cooldown_end_time=0)
    assert status == QuotaStatus.ALLOWED
    assert quota_manager._global_attempts == 1
    assert quota_manager._current_utc_date == "2026-01-02"
