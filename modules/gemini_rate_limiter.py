import os
import threading
from datetime import datetime, timezone
import streamlit as st

class QuotaStatus:
    ALLOWED = "ALLOWED"
    DISABLED = "DISABLED"
    GLOBAL_LIMIT_REACHED = "GLOBAL_LIMIT_REACHED"
    SESSION_LIMIT_REACHED = "SESSION_LIMIT_REACHED"
    BUSY = "BUSY"

class GlobalQuotaManager:
    def __init__(self):
        self._lock = threading.Lock()
        self._current_utc_date = self._get_utc_date()
        self._global_attempts = 0
        self._in_flight = False

    def _get_utc_date(self):
        """Returns the current UTC date string. Can be mocked in tests."""
        return datetime.now(timezone.utc).date().isoformat()

    def _check_rollover(self):
        """Internal helper to reset counters on a new UTC day. Assumes lock is held."""
        today = self._get_utc_date()
        if today != self._current_utc_date:
            self._current_utc_date = today
            self._global_attempts = 0
            # in_flight is not reset across days just in case a request is active during midnight

    def check_and_reserve(self, session_attempts, cooldown_end_time):
        """
        Check quota limits in the correct order and reserve an attempt if allowed.
        Returns (status_enum, message)
        """
        # 1. Gemini feature enabled?
        enabled = os.environ.get("GEMINI_ENABLED", "true").lower() == "true"
        if not enabled:
            return QuotaStatus.DISABLED, "AI analysis is temporarily disabled. Offline forensic results remain available."

        # Parse configs with safe defaults and boundaries
        try:
            daily_budget = int(os.environ.get("GEMINI_DAILY_BUDGET", "10"))
            daily_budget = max(0, daily_budget)
        except ValueError:
            daily_budget = 10

        try:
            session_limit = int(os.environ.get("GEMINI_SESSION_DAILY_LIMIT", "2"))
            session_limit = max(0, session_limit)
        except ValueError:
            session_limit = 2

        with self._lock:
            self._check_rollover()

            # 4. Per-session daily limit
            if session_attempts >= session_limit:
                return QuotaStatus.SESSION_LIMIT_REACHED, "You have reached this session’s AI analysis limit. Offline results remain available."

            # 5. Per-session cooldown
            import time
            if time.monotonic() < cooldown_end_time:
                return QuotaStatus.BUSY, "AI analysis is currently busy. Please try again shortly."

            # 6. Process-wide daily budget
            if self._global_attempts >= daily_budget:
                return QuotaStatus.GLOBAL_LIMIT_REACHED, "The public AI demo has reached today’s safety limit. Please use the offline analysis or try again tomorrow."

            # 7. No Gemini request currently in flight.
            if self._in_flight:
                return QuotaStatus.BUSY, "AI analysis is currently busy. Please try again shortly."

            # Allow and reserve attempt
            self._in_flight = True
            self._global_attempts += 1

            return QuotaStatus.ALLOWED, "Request allowed."

    def release_in_flight(self):
        """Releases the in-flight lock after the API call completes."""
        with self._lock:
            self._in_flight = False

@st.cache_resource
def get_global_quota_manager():
    """Returns a process-wide singleton for the QuotaManager."""
    return GlobalQuotaManager()
