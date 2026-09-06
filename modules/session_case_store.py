import streamlit as st
import uuid
import copy
from datetime import datetime, timezone

def _sanitize_data(data):
    """Recursively removes byte-like values to minimize stored data."""
    if isinstance(data, dict):
        return {k: _sanitize_data(v) for k, v in data.items() if not isinstance(v, (bytes, bytearray, memoryview))}
    elif isinstance(data, list):
        return [_sanitize_data(item) for item in data if not isinstance(item, (bytes, bytearray, memoryview))]
    elif isinstance(data, (bytes, bytearray, memoryview)):
        return None
    return data

def _init_store():
    if "_cases" not in st.session_state:
        st.session_state["_cases"] = []
    if "_campaigns" not in st.session_state:
        st.session_state["_campaigns"] = []

def save_case(case_data: dict) -> str:
    _init_store()

    email_hash = case_data.get('email_hash')
    if not email_hash:
        raise ValueError("email_hash is required to save a case")

    for c in st.session_state["_cases"]:
        if c.get("email_hash") == email_hash:
            return c["case_id"]

    # Deep copy and sanitize to isolate from further mutations
    clean_data = copy.deepcopy(_sanitize_data(case_data))

    case_id = datetime.now(timezone.utc).strftime("CASE-%Y%m%d-") + uuid.uuid4().hex[:4].upper()
    clean_data["case_id"] = case_id
    clean_data["created_at"] = datetime.now(timezone.utc).isoformat()
    clean_data["campaign_id"] = None

    st.session_state["_cases"].append(clean_data)
    return case_id

def list_cases(search=None, risk_level=None) -> list:
    _init_store()
    results = []
    for c in st.session_state["_cases"]:
        if risk_level and c.get("risk_level") != risk_level:
            continue
        if search:
            s = search.lower()
            if not any(s in str(c.get(field, "")).lower() for field in ["subject", "sender_address", "case_id", "filename"]):
                continue
        results.append(copy.deepcopy(c))

    results.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return results

def get_case(case_id: str) -> dict:
    _init_store()
    for c in st.session_state["_cases"]:
        if c.get("case_id") == case_id:
            return copy.deepcopy(c)
    return None

def delete_case(case_id: str):
    _init_store()
    st.session_state["_cases"] = [c for c in st.session_state["_cases"] if c.get("case_id") != case_id]

def get_cases_for_correlation() -> list:
    _init_store()
    return copy.deepcopy(st.session_state["_cases"])

def update_case_campaign(case_id: str, campaign_id: str):
    _init_store()
    for c in st.session_state["_cases"]:
        if c.get("case_id") == case_id:
            c["campaign_id"] = campaign_id

def save_campaign(campaign: dict):
    _init_store()
    st.session_state["_campaigns"].append(copy.deepcopy(campaign))

def get_campaigns() -> list:
    _init_store()
    results = copy.deepcopy(st.session_state["_campaigns"])
    results.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return results

def get_campaign_cases(campaign_id: str) -> list:
    _init_store()
    cases = [c for c in st.session_state["_cases"] if c.get("campaign_id") == campaign_id]
    cases.sort(key=lambda x: x.get("created_at", ""), reverse=True)
    return copy.deepcopy(cases)

def get_dashboard_aggregates() -> dict:
    _init_store()
    cases = st.session_state["_cases"]
    campaigns = st.session_state["_campaigns"]

    total_cases = len(cases)
    high_critical = sum(1 for c in cases if c.get("risk_level") in ["High", "Critical"])
    total_campaigns = len(campaigns)

    total_score = sum(c.get("fraud_score", 0) for c in cases if isinstance(c.get("fraud_score"), (int, float)))
    avg_score = total_score / total_cases if total_cases > 0 else 0

    risk_counts = {}
    for c in cases:
        rl = c.get("risk_level", "Unknown")
        risk_counts[rl] = risk_counts.get(rl, 0) + 1

    domain_counts = {}
    for c in cases:
        domain = c.get("sender_domain", "")
        if domain:
            domain_counts[domain] = domain_counts.get(domain, 0) + 1

    sorted_domains = sorted(domain_counts.items(), key=lambda x: x[1], reverse=True)[:5]
    top_domains = [{"Domain": d[0], "Count": d[1]} for d in sorted_domains]

    recent_cases = sorted(cases, key=lambda x: x.get("created_at", ""), reverse=True)[:5]

    # We will format recent cases explicitly as a list of dicts to be ready for pandas DataFrame creation in Dashboard.py
    recent_cases_formatted = [{
        "case_id": c.get("case_id"),
        "created_at": c.get("created_at"),
        "subject": c.get("subject"),
        "sender_domain": c.get("sender_domain"),
        "fraud_score": c.get("fraud_score"),
        "risk_level": c.get("risk_level")
    } for c in recent_cases]

    return {
        "total_cases": total_cases,
        "high_critical": high_critical,
        "total_campaigns": total_campaigns,
        "avg_score": avg_score,
        "risk_counts": [{"Risk Level": k, "Count": v} for k, v in risk_counts.items()],
        "top_domains": top_domains,
        "recent_cases": recent_cases_formatted
    }
