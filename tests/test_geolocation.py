import pytest
from unittest.mock import patch, Mock
import requests
from modules.geolocation import geolocate_ip, _GEO_CACHE

@pytest.fixture(autouse=True)
def clear_cache():
    _GEO_CACHE.clear()
    yield

def test_invalid_ip():
    res = geolocate_ip("999.999.999.999")
    assert res["available"] is False
    assert "Invalid IP" in res["error"]

def test_private_ip():
    res = geolocate_ip("192.168.1.1")
    assert res["available"] is False
    assert "private" in res["error"]

def test_reserved_ip():
    res = geolocate_ip("240.0.0.1")
    assert res["available"] is False
    assert "private, reserved" in res["error"]

@patch('modules.geolocation.requests.get')
def test_successful_lookup(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {"X-Rl": "44", "X-Ttl": "60"}
    mock_response.json.return_value = {
        "status": "success",
        "country": "United States",
        "proxy": True,
        "hosting": False
    }
    mock_get.return_value = mock_response

    res = geolocate_ip("8.8.8.8")
    assert res["available"] is True
    assert res["location"]["country"] == "United States"
    assert res["proxy"] is True
    assert res["rate_limit_remaining"] == 44
    assert res["rate_limit_reset_seconds"] == 60

@patch('modules.geolocation.requests.get')
def test_cached_result(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.json.return_value = {
        "status": "success",
        "country": "Canada"
    }
    mock_get.return_value = mock_response

    res1 = geolocate_ip("1.1.1.1")
    assert mock_get.call_count == 1
    assert res1["available"] is True

    res2 = geolocate_ip("1.1.1.1")
    assert mock_get.call_count == 1 # should remain 1 because it's cached
    assert res2["available"] is True

@patch('modules.geolocation.requests.get')
def test_http_429(mock_get):
    mock_response = Mock()
    mock_response.status_code = 429
    mock_response.headers = {}
    mock_get.return_value = mock_response

    res = geolocate_ip("8.8.4.4")
    assert res["available"] is False
    assert "429" in res["error"]

@patch('modules.geolocation.requests.get')
def test_api_failure_response(mock_get):
    mock_response = Mock()
    mock_response.status_code = 200
    mock_response.headers = {}
    mock_response.json.return_value = {
        "status": "fail",
        "message": "private range"
    }
    mock_get.return_value = mock_response

    res = geolocate_ip("8.8.4.4")
    assert res["available"] is False
    assert "API error: private range" in res["error"]

@patch('modules.geolocation.requests.get')
def test_timeout(mock_get):
    mock_get.side_effect = requests.exceptions.Timeout
    res = geolocate_ip("8.8.4.4")
    assert res["available"] is False
    assert "timed out" in res["error"]
