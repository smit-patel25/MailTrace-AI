import pytest
from unittest.mock import patch, Mock
import datetime
from modules.domain_intelligence import analyze_domain, validate_and_normalize_domain, _DOMAIN_CACHE

@pytest.fixture(autouse=True)
def clear_cache():
    _DOMAIN_CACHE.clear()
    yield

def test_validate_and_normalize_domain():
    assert validate_and_normalize_domain("example.com") == "example.com"
    assert validate_and_normalize_domain("  ExAmPlE.cOm  ") == "example.com"
    assert validate_and_normalize_domain("192.168.1.1") is None
    assert validate_and_normalize_domain("invalid_domain") is None
    assert validate_and_normalize_domain("") is None
    assert validate_and_normalize_domain("http://example.com") is None

@patch('modules.domain_intelligence.dns.resolver.Resolver.resolve')
@patch('modules.domain_intelligence.whois.whois')
def test_successful_domain_analysis(mock_whois, mock_resolve):
    # Mock WHOIS
    mock_w = Mock()
    mock_w.registrar = "Test Registrar"
    mock_w.creation_date = datetime.datetime(2020, 1, 1) # naive
    mock_w.expiration_date = [datetime.datetime(2030, 1, 1), datetime.datetime(2030, 1, 2)] # list
    mock_whois.return_value = mock_w
    
    # Mock DNS
    def mock_dns_resolve(qname, rdtype):
        mock_answer = Mock()
        if rdtype == 'MX':
            mock_answer.preference = 10
            mock_answer.exchange.to_text.return_value = 'mail.example.com'
            return [mock_answer]
        elif rdtype == 'TXT':
            if qname == 'example.com':
                mock_answer.strings = [b'v=spf1 include:_spf.google.com ~all']
                return [mock_answer]
            elif qname == '_dmarc.example.com':
                mock_answer.strings = [b'v=DMARC1; p=reject;']
                return [mock_answer]
        elif rdtype == 'A':
            mock_answer.to_text.return_value = '93.184.216.34'
            return [mock_answer]
        elif rdtype == 'AAAA':
            mock_answer.to_text.return_value = '2606:2800:220:1:248:1893:25c8:1946'
            return [mock_answer]
        raise Exception("Not found")
        
    mock_resolve.side_effect = mock_dns_resolve
    
    res = analyze_domain("example.com")
    
    assert res["available"] is True
    assert res["normalized_domain"] == "example.com"
    assert "10 mail.example.com" in res["mx_records"]
    assert res["spf_record"] == "v=spf1 include:_spf.google.com ~all"
    assert res["dmarc_record"] == "v=DMARC1; p=reject;"
    assert "93.184.216.34" in res["a_records"]
    assert "2606:2800:220:1:248:1893:25c8:1946" in res["aaaa_records"]
    assert res["registrar"] == "Test Registrar"
    assert "2020-01-01" in res["creation_date"]
    assert "2030-01-01" in res["expiration_date"]
    assert res["domain_age_days"] > 1000

@patch('modules.domain_intelligence.dns.resolver.Resolver.resolve')
@patch('modules.domain_intelligence.whois.whois')
def test_missing_records_and_cached(mock_whois, mock_resolve):
    mock_whois.side_effect = Exception("WHOIS timeout")
    mock_resolve.side_effect = Exception("DNS timeout")
    
    res = analyze_domain("missing.com")
    assert res["available"] is True
    assert res["mx_records"] == []
    assert res["spf_record"] is None
    assert res["dmarc_record"] is None
    assert res["registrar"] is None
    assert len(res["errors"]) == 1
    assert "WHOIS timeout" in res["errors"][0]
    
    # Check cache
    res2 = analyze_domain("missing.com")
    assert mock_whois.call_count == 1 # still 1

@patch('modules.domain_intelligence.whois.whois')
def test_whois_tz_aware_date(mock_whois):
    # Some WHOIS returns tz-aware dates
    mock_w = Mock()
    mock_w.registrar = None
    mock_w.creation_date = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
    mock_w.expiration_date = None
    mock_whois.return_value = mock_w
    
    res = analyze_domain("tz-aware.com")
    assert "2020-01-01" in res["creation_date"]
