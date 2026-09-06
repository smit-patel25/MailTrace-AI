import pytest
from unittest.mock import patch, Mock
import requests
import json
from modules.geolocation import geolocate_ip

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
    assert "private" in res["error"]

def test_loopback_ip():
    res = geolocate_ip("127.0.0.1")
    assert res["available"] is False
    assert "private" in res["error"]

@patch('modules.geolocation.requests.get')
def test_successful_lookup(mock_get):
    mock_response = Mock()
    mock_response.__enter__ = Mock(return_value=mock_response)
    mock_response.__exit__ = Mock(return_value=None)
    mock_response.status_code = 200

    mock_data = {
        "ipAddress": "8.8.8.8",
        "latitude": 37.751,
        "longitude": -97.822,
        "countryName": "United States",
        "countryCode": "US",
        "regionName": "Virginia",
        "cityName": "Ashburn",
        "asn": "15169",
        "asnOrganization": "Google LLC",
        "isProxy": True
    }

    mock_response.raw.read.return_value = json.dumps(mock_data).encode("utf-8")
    mock_get.return_value = mock_response

    res = geolocate_ip("8.8.8.8")

    # Assert requests.get was called securely
    mock_get.assert_called_once_with(
        "https://free.freeipapi.com/api/json/8.8.8.8",
        timeout=(3.0, 5.0),
        allow_redirects=False,
        stream=True
    )

    assert res["available"] is True
    assert res["location"]["country"] == "United States"
    assert res["location"]["org"] == "Google LLC"
    assert res["proxy"] is True
    assert res["hosting"] is False # Must not blindly copy proxy to hosting

@patch('modules.geolocation.requests.get')
def test_http_429(mock_get):
    mock_response = Mock()
    mock_response.__enter__ = Mock(return_value=mock_response)
    mock_response.__exit__ = Mock(return_value=None)
    mock_response.status_code = 429
    mock_get.return_value = mock_response

    res = geolocate_ip("8.8.4.4")
    assert res["available"] is False
    assert "429" in res["error"]

@patch('modules.geolocation.requests.get')
def test_timeout(mock_get):
    mock_get.side_effect = requests.exceptions.Timeout
    res = geolocate_ip("8.8.4.4")
    assert res["available"] is False
    assert "timed out" in res["error"]

@patch('modules.geolocation.requests.get')
def test_malformed_json(mock_get):
    mock_response = Mock()
    mock_response.__enter__ = Mock(return_value=mock_response)
    mock_response.__exit__ = Mock(return_value=None)
    mock_response.status_code = 200
    mock_response.raw.read.return_value = b"{ invalid json"
    mock_get.return_value = mock_response

    res = geolocate_ip("8.8.4.4")
    assert res["available"] is False
    assert "Invalid JSON" in res["error"]

@patch('modules.geolocation.requests.get')
def test_invalid_coordinates(mock_get):
    mock_response = Mock()
    mock_response.__enter__ = Mock(return_value=mock_response)
    mock_response.__exit__ = Mock(return_value=None)
    mock_response.status_code = 200

    mock_data = {
        "ipAddress": "8.8.8.8",
        "latitude": 900.0, # Invalid
        "longitude": "not_a_float", # Invalid
        "countryName": "Test"
    }

    mock_response.raw.read.return_value = json.dumps(mock_data).encode("utf-8")
    mock_get.return_value = mock_response

    res = geolocate_ip("8.8.8.8")
    assert res["available"] is True
    assert res["location"]["lat"] is None
    assert res["location"]["lon"] is None
