import os
import pytest
from streamlit.testing.v1 import AppTest

from modules.ioc_relationship import (
    build_ioc_graph,
    render_ioc_graph,
    generate_fallback_table,
    _extract_hostnames,
    _is_valid_domain,
    _is_valid_ip,
    _is_valid_sha256,
)


@pytest.fixture(autouse=True)
def block_network_calls(monkeypatch):
    """Ensure no network requests can occur during graph processing."""
    def block_request(*args, **kwargs):
        raise RuntimeError("Network calls are forbidden during IOC analysis.")

    import urllib.request
    import socket
    monkeypatch.setattr(urllib.request, "urlopen", block_request)
    monkeypatch.setattr(socket, "create_connection", block_request)

    try:
        import requests
        monkeypatch.setattr(requests.Session, "request", block_request)
    except ImportError:
        pass


def test_is_valid_domain():
    assert _is_valid_domain("example.com") == "example.com"
    assert _is_valid_domain("sub.example.co.uk") == "sub.example.co.uk"
    # Rejections
    assert _is_valid_domain("123") is None
    assert _is_valid_domain(123) is None
    assert _is_valid_domain("example com") is None
    assert _is_valid_domain("http://example.com") is None
    assert _is_valid_domain("path/to/file") is None
    assert _is_valid_domain("example..com") is None
    assert _is_valid_domain("-bad.com") is None
    assert _is_valid_domain("bad-.com") is None
    assert _is_valid_domain("a" * 64 + ".com") is None  # oversized label
    assert _is_valid_domain("a" * 255 + ".com") is None  # oversized domain


def test_is_valid_ip():
    assert _is_valid_ip("192.168.1.1") == "192.168.1.1"
    assert _is_valid_ip("2001:0db8:85a3:0000:0000:8a2e:0370:7334") == "2001:db8:85a3::8a2e:370:7334"
    # Rejections
    assert _is_valid_ip("999.999.999.999") == ""
    assert _is_valid_ip("not_an_ip") == ""
    assert _is_valid_ip(123) == ""


def test_is_valid_sha256():
    valid_hash = "a" * 64
    assert _is_valid_sha256(valid_hash) is True
    assert _is_valid_sha256(valid_hash.upper()) is True
    # Rejections
    assert _is_valid_sha256("abcdef") is False
    assert _is_valid_sha256("a" * 65) is False
    assert _is_valid_sha256("g" * 64) is False  # not hex


def test_extract_hostnames():
    urls = [
        "http://example.com/path",
        "https://test.com",
        "hxxp://evil.com",
        "HXXPS://evil2.com",
        "http://defanged[.]com",
        "invalid_url",
        "http://user:pass@creds.com",
        "http://[2001:db8:85a3::8a2e:370:7334]",
        "http://[invalid",
        "ftp://rejected.com",
        123,
        None
    ]
    hosts = _extract_hostnames(urls)
    assert "example.com" in hosts
    assert "test.com" in hosts
    assert "evil.com" in hosts
    assert "evil2.com" in hosts
    assert "defanged.com" in hosts
    assert "creds.com" in hosts
    assert "2001:db8:85a3::8a2e:370:7334" in hosts
    assert "invalid_url" not in hosts
    assert "none" not in hosts
    assert "rejected.com" not in hosts


def test_malformed_top_level_and_nested():
    cases = [
        "not_a_dict",
        None,
        {"case_id": "C1", "extracted_urls": "not_a_list"},
        {"case_id": "C2", "analyzer_results": "not_a_dict"},
        {"case_id": "C3", "analyzer_results": {"attachment_analysis": {"attachments": "not_a_list"}}},
    ]
    graph = build_ioc_graph(cases)
    # C1, C2, C3 exist but with no edges
    assert len(graph["nodes"]) == 3
    assert len(graph["edges"]) == 0


def test_extreme_length_and_escaping():
    hostile_label = "<script>alert(1)</script>"
    long_label = "a" * 500
    cases = [
        {
            "case_id": hostile_label,
            "sender_domain": "example.com"
        },
        {
            "case_id": long_label,
            "sender_domain": "example.com"
        }
    ]
    graph = build_ioc_graph(cases)
    fig = render_ioc_graph(graph)

    # Check escaping in hover text
    html_found = False
    for trace in fig.data:
        if trace.hovertext:
            for text in trace.hovertext:
                if "&lt;script&gt;" in text:
                    html_found = True
                assert "<script>" not in text

    assert html_found

    # Check long label bounding
    c2_case_node = next(n for n in graph["nodes"] if n["type"] == "Case" and n["full_label"].startswith("a" * 50))
    assert len(c2_case_node["full_label"]) == 256
    assert c2_case_node["label"].endswith("...")


def test_node_id_collisions():
    cases = [
        {
            "case_id": "1.1.1.1",
            "probable_origin_ip": "1.1.1.1"
        }
    ]
    graph = build_ioc_graph(cases)
    assert len(graph["nodes"]) == 2
    ids = [n["id"] for n in graph["nodes"]]
    import hashlib
    case_hash = hashlib.sha256(b"1.1.1.1").hexdigest()
    assert f"case_{case_hash}" in ids
    assert "ip_1.1.1.1" in ids


def test_determinism():
    cases1 = [
        {"case_id": "B", "sender_domain": "z.com"},
        {"case_id": "A", "sender_domain": "a.com"}
    ]
    cases2 = [
        {"case_id": "A", "sender_domain": "a.com"},
        {"case_id": "B", "sender_domain": "z.com"}
    ]
    g1 = build_ioc_graph(cases1)
    g2 = build_ioc_graph(cases2)
    assert g1 == g2


def test_deduplication():
    cases = [
        {
            "case_id": "C1",
            "sender_domain": "Example.COM.",
            "reply_to_domain": "example.com"
        }
    ]
    graph = build_ioc_graph(cases)
    assert len(graph["nodes"]) == 2
    assert len(graph["edges"]) == 1
    domain_node = next(n for n in graph["nodes"] if n["type"] == "Domain")
    assert domain_node["id"] == "domain_example.com"


def test_node_limit():
    cases = [{"case_id": f"C{i}"} for i in range(101)]
    graph = build_ioc_graph(cases)
    assert len(graph["nodes"]) == 100
    assert graph["truncated"] is True


def test_edge_limit():
    cases = []
    for i in range(50):
        c = {"case_id": f"C{i}", "extracted_urls": [f"http://d{j}.com" for j in range(50)]}
        cases.append(c)

    graph = build_ioc_graph(cases)
    # nodes = 50 cases + 50 domains = 100 nodes.
    # edges = each case links to 50 domains, so as we process cases, edges grow rapidly.
    # It should hit 200 edges before processing all cases/urls.
    assert len(graph["edges"]) == 200
    assert graph["truncated"] is True


def test_raw_data_absent():
    cases = [{
        "case_id": "C1",
        "raw_email_body": "SECRET_PASSWORD",
        "sender_domain": "example.com",
        "analyzer_results": {
            "attachment_analysis": {
                "attachments": [
                    {"sha256": "a"*64, "raw_bytes": b"SENSITIVE_DATA"}
                ]
            }
        }
    }]
    graph = build_ioc_graph(cases)
    graph_str = str(graph)
    assert "SECRET_PASSWORD" not in graph_str
    assert "SENSITIVE_DATA" not in graph_str
    assert "a"*64 in graph_str


def test_fallback_table():
    cases = [{"case_id": "C1", "sender_domain": "example.com"}]
    graph = build_ioc_graph(cases)
    table = generate_fallback_table(graph)
    assert len(table) == 1
    assert table[0]["Case"] == "C1"
    assert table[0]["Indicator Type"] == "Domain"
    assert table[0]["Indicator Value"] == "example.com"


def test_fallback_table_empty():
    cases = [{"case_id": "C1"}]
    graph = build_ioc_graph(cases)
    table = generate_fallback_table(graph)
    assert table == []


def test_integration_session_case():
    from modules.session_case_store import save_case, _init_store, get_cases_for_correlation
    import streamlit as st

    _init_store()
    old_cases = st.session_state.get("_cases", [])
    st.session_state["_cases"] = []

    try:
        case_data = {
            "filename": "test.eml",
            "email_hash": "hash123",
            "subject": "Phishing",
            "sender_address": "attacker@evil.com",
            "sender_domain": "evil.com",
            "reply_to_domain": "reply.com",
            "probable_origin_ip": "1.2.3.4",
            "risk_level": "High",
            "fraud_score": 99,
            "extracted_urls": ["http://phish.com"],
            "analyzer_results": {
                "attachment_analysis": {
                    "attachments": [{"sha256": "a"*64}]
                }
            }
        }
        save_case(case_data)

        cases = get_cases_for_correlation()
        graph = build_ioc_graph(cases)

        # 1 Case + IP + 2 Domains + URL + Hash = 6 nodes
        assert len(graph["nodes"]) == 6
        assert len(graph["edges"]) == 5

        # Independent session test
        st.session_state["_cases"] = []
        cases_empty = get_cases_for_correlation()
        assert len(cases_empty) == 0
    finally:
        st.session_state["_cases"] = old_cases


def test_campaigns_page_empty(monkeypatch):
    monkeypatch.setattr("modules.ui_theme.sidebar_navigation", lambda: None)
    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    APP_PATH = os.path.join(PROJECT_ROOT, "pages", "2_Campaigns.py")
    at = AppTest.from_file(APP_PATH, default_timeout=10)
    at.session_state["_cases"] = []
    at.run()
    assert not at.exception
    assert any("No cases available to map relationships" in i.value for i in at.info)


def test_campaigns_page_populated(monkeypatch):
    monkeypatch.setattr("modules.ui_theme.sidebar_navigation", lambda: None)

    # Mock st.plotly_chart to easily track if it was called
    plotly_calls = []
    import streamlit as st
    monkeypatch.setattr(st, "plotly_chart", lambda fig, **kwargs: plotly_calls.append(fig))

    PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
    APP_PATH = os.path.join(PROJECT_ROOT, "pages", "2_Campaigns.py")

    at = AppTest.from_file(APP_PATH, default_timeout=10)

    # Populate the session state with a real mock case
    at.session_state["_cases"] = [
        {
            "case_id": "CASE-1",
            "sender_domain": "evil.com"
        },
        {
            "case_id": "CASE-2",
            "sender_domain": "evil.com"
        }
    ]

    at.run()
    assert not at.exception

    # Verify we did not show empty state
    assert not any("No cases available to map relationships" in getattr(i, "value", "") for i in at.info)

    # Assert one Plotly chart is present
    assert len(plotly_calls) == 1

    # Assert the attribution disclaimer is present
    assert any("Relationships indicate shared technical artifacts, not proof of common ownership" in getattr(c, "value", "") for c in at.caption)

    # Assert the Accessible Relationship Data expander exists
    assert any("Accessible Relationship Data" in getattr(e, "label", "") for e in at.expander)
