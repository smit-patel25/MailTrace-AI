import pytest
from modules.relay_analyzer import analyze_relay_chain, extract_and_classify_ips

def test_extract_and_classify_ips():
    # IPv4 public
    res = extract_and_classify_ips("from mx.example.com (mx.example.com [8.8.8.8])")
    assert len(res) == 1
    assert res[0]['ip'] == "8.8.8.8"
    assert res[0]['type'] == "public"
    
    # IPv4 private
    res = extract_and_classify_ips("from localhost ([10.0.0.5])")
    assert len(res) == 1
    assert res[0]['ip'] == "10.0.0.5"
    assert res[0]['type'] == "private"
    
    # IPv6 public
    res = extract_and_classify_ips("from [2606:4700:4700::1111]")
    assert len(res) == 1
    assert res[0]['ip'] == "2606:4700:4700::1111"
    assert res[0]['type'] == "public"
    
    # IPv6 loopback
    res = extract_and_classify_ips("from [::1]")
    assert len(res) == 1
    assert res[0]['ip'] == "::1"
    assert res[0]['type'] == "loopback"
    
    # Reserved/Private (e.g. 240.0.0.1)
    res = extract_and_classify_ips("from [240.0.0.1]")
    assert len(res) == 1
    assert res[0]['ip'] == "240.0.0.1"
    assert res[0]['type'] in ["reserved", "private"]

def test_multiple_relay_headers_and_origin():
    parsed_email = {
        "received": [
            "from mx2.example.com (mx2 [8.8.4.4]) by mx1.example.com", # latest
            "from sender.com (sender [8.8.8.8]) by mx2.example.com" # earliest
        ]
    }
    
    result = analyze_relay_chain(parsed_email)
    assert len(result["chronological_hops"]) == 2
    assert result["chronological_hops"][0] == "from sender.com (sender [8.8.8.8]) by mx2.example.com"
    assert result["probable_origin_ip"] == "8.8.8.8"
    assert result["origin_confidence"] == "medium"

def test_private_origin_low_confidence():
    parsed_email = {
        "received": [
            "from mx2.example.com (mx2 [8.8.8.8]) by mx1.example.com", # latest (public)
            "from internal (internal [10.0.0.1]) by mx2.example.com" # earliest (private)
        ]
    }
    result = analyze_relay_chain(parsed_email)
    assert result["probable_origin_ip"] == "8.8.8.8"
    assert result["origin_confidence"] == "low"

def test_missing_received():
    result = analyze_relay_chain({"received": []})
    assert result["probable_origin_ip"] is None
    assert result["origin_confidence"] == "low"
    assert result["chronological_hops"] == []

def test_malformed_ip():
    parsed_email = {
        "received": [
            "from mx (mx [999.999.999.999])" # Invalid IP
        ]
    }
    result = analyze_relay_chain(parsed_email)
    assert result["probable_origin_ip"] is None
    assert result["probable_origin_ip"] is None
    assert len(result["all_extracted_ips"]) == 0

def test_malformed_ipv6():
    parsed_email = {
        "received": [
            "from mx (mx [2606:4700:4700:gggg::1111])" # Invalid IPv6 (gggg)
        ]
    }
    result = analyze_relay_chain(parsed_email)
    assert result["probable_origin_ip"] is None
    # As long as it doesn't crash, the malformed IPv6 is handled.
