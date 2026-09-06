import pytest
import streamlit as st
from modules.session_case_store import save_case, _init_store
from modules.campaign_correlator import correlate_case, list_campaigns, get_campaign_cases

@pytest.fixture(autouse=True)
def clear_session():
    st.session_state.clear()
    _init_store()
    yield

# Dummy parameter to replace temp_db everywhere
@pytest.fixture
def temp_db():
    return None

def test_same_origin_ip_match(temp_db):

    id1 = save_case({"email_hash": "1", "probable_origin_ip": "1.2.3.4"})
    id2 = save_case({"email_hash": "2", "probable_origin_ip": "1.2.3.4"})

    res = correlate_case(None, id2)
    assert res["status"] == "created_campaign"
    assert res["correlation_confidence"] == "medium"
    assert "Shared Origin IP: 1.2.3.4" in res["matched_indicators"]

    camps = list_campaigns()
    assert len(camps) == 1
    assert camps[0]["case_count"] == 2

    cases = get_campaign_cases(None, camps[0]["campaign_id"])
    assert len(cases) == 2

def test_same_url_hostname_match(temp_db):

    id1 = save_case({"email_hash": "1", "extracted_urls": ["http://badguy.com/path"]})
    id2 = save_case({"email_hash": "2", "extracted_urls": ["https://badguy.com/other"]})

    res = correlate_case(None, id2)
    assert res["status"] == "created_campaign"
    assert "Shared URL Hostname: badguy.com" in res["matched_indicators"]

def test_two_weak_matches(temp_db):

    id1 = save_case({"email_hash": "1", "sender_domain": "evil.com", "reply_to_domain": "evil.com"})
    id2 = save_case({"email_hash": "2", "sender_domain": "evil.com", "reply_to_domain": "evil.com"})

    res = correlate_case(None, id2)
    assert res["status"] == "created_campaign"
    assert res["correlation_confidence"] == "low"

def test_one_weak_match_does_not_group(temp_db):

    id1 = save_case({"email_hash": "1", "sender_domain": "evil.com"})
    id2 = save_case({"email_hash": "2", "sender_domain": "evil.com"})

    res = correlate_case(None, id2)
    assert res["status"] == "no_correlation"

def test_common_provider_domains_do_not_group(temp_db):

    id1 = save_case({"email_hash": "1", "sender_domain": "gmail.com", "reply_to_domain": "yahoo.com"})
    id2 = save_case({"email_hash": "2", "sender_domain": "gmail.com", "reply_to_domain": "yahoo.com"})

    res = correlate_case(None, id2)
    assert res["status"] == "no_correlation"

def test_missing_indicators_do_not_group(temp_db):

    id1 = save_case({"email_hash": "1"})
    id2 = save_case({"email_hash": "2"})

    res = correlate_case(None, id2)
    assert res["status"] == "no_correlation"

def test_join_existing_campaign(temp_db):

    id1 = save_case({"email_hash": "1", "probable_origin_ip": "1.2.3.4"})
    id2 = save_case({"email_hash": "2", "probable_origin_ip": "1.2.3.4"})
    res1 = correlate_case(None, id2)

    id3 = save_case({"email_hash": "3", "probable_origin_ip": "1.2.3.4"})
    res2 = correlate_case(None, id3)

    assert res2["status"] == "joined_campaign"
    assert res2["campaign_id"] == res1["campaign_id"]

    camps = list_campaigns()
    assert len(camps) == 1
    assert camps[0]["case_count"] == 3
