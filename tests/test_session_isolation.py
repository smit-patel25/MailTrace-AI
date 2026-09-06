import pytest
import streamlit as st
from unittest.mock import patch
from modules.session_case_store import save_case, list_cases, get_case, delete_case, get_cases_for_correlation, _init_store, _sanitize_data

@pytest.fixture(autouse=True)
def clear_session_state():
    """Clear session state before each test to simulate a fresh session."""
    st.session_state.clear()
    yield

def test_session_starts_empty():
    _init_store()
    assert len(st.session_state["_cases"]) == 0
    assert len(st.session_state["_campaigns"]) == 0

def test_save_and_view_case_session_a():
    case_data = {
        "email_hash": "hash1",
        "subject": "Test 1",
        "fraud_score": 50
    }
    case_id = save_case(case_data)
    assert case_id is not None

    cases = list_cases()
    assert len(cases) == 1
    assert cases[0]["case_id"] == case_id

    retrieved = get_case(case_id)
    assert retrieved is not None
    assert retrieved["subject"] == "Test 1"

def test_session_isolation():
    # Session A
    case_data_a = {"email_hash": "hash_a", "subject": "Session A"}
    case_id_a = save_case(case_data_a)

    assert len(list_cases()) == 1

    # Simulate a new session (Session B)
    st.session_state.clear()

    # Session B starts with zero cases
    assert len(list_cases()) == 0

    # Session B cannot retrieve Session A's case
    assert get_case(case_id_a) is None

    # Session B deletes Session A's case? (should do nothing)
    delete_case(case_id_a)
    assert len(list_cases()) == 0

def test_data_minimization_byte_removal():
    case_data = {
        "email_hash": "hash_bytes",
        "subject": "Bytes test",
        "raw_bytes": b"somedata",
        "nested": {
            "arr": bytearray(b"arraydata"),
            "valid": "string"
        },
        "list_of_bytes": [b"b1", "valid_string"]
    }

    case_id = save_case(case_data)
    saved = get_case(case_id)

    # Assert bytes are removed
    assert "raw_bytes" not in saved or saved["raw_bytes"] is None
    assert "arr" not in saved["nested"] or saved["nested"]["arr"] is None
    assert saved["nested"]["valid"] == "string"
    assert b"b1" not in saved["list_of_bytes"]
    assert "valid_string" in saved["list_of_bytes"]

def test_saving_does_not_mutate_original_data():
    case_data = {
        "email_hash": "hash_mut",
        "subject": "Mutate test",
        "results": {"score": 10}
    }

    case_id = save_case(case_data)

    # Mutate original
    case_data["results"]["score"] = 99

    # Retrieve saved
    saved = get_case(case_id)
    assert saved["results"]["score"] == 10

def test_zero_sqlite_reads_writes():
    with patch("sqlite3.connect") as mock_connect:
        case_data = {"email_hash": "hash_sql"}
        save_case(case_data)
        list_cases()

        mock_connect.assert_not_called()

def test_delete_affects_current_session_only():
    case_data = {"email_hash": "hash_del"}
    case_id = save_case(case_data)

    assert len(list_cases()) == 1
    delete_case(case_id)
    assert len(list_cases()) == 0
