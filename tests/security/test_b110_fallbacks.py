import pytest
from unittest.mock import patch
import dns.exception
from modules.campaign_correlator import _extract_hostnames
from modules.content_analyzer import analyze_urls
from modules.domain_intelligence import get_dns_records
from modules.email_parser import parse_eml_bytes

def test_campaign_correlator_malformed_url():
    with patch('modules.campaign_correlator.urllib.parse.urlparse', side_effect=ValueError('malformed')):
        res = _extract_hostnames(['http://bad'])
        assert res == set()

def test_analyze_urls_malformed_url():
    with patch('modules.content_analyzer.urlparse', side_effect=ValueError('malformed')):
        inds = []
        pts = analyze_urls(['http://bad'], inds)
        assert pts == 0
        assert len(inds) == 0

def test_dns_records_failure():
    with patch('dns.resolver.Resolver.resolve', side_effect=dns.exception.DNSException('timeout')):
        assert get_dns_records('example.com', 'A') == []

def test_email_parser_malformed_mime():
    with patch('email.message.EmailMessage.get_content', side_effect=Exception('fail1')):
        with patch('email.message.Message.get_payload', side_effect=MemoryError('fail2')):
            with pytest.raises(MemoryError):
                parse_eml_bytes(b'Subject: Test\r\nContent-Type: text/plain\r\n\r\nBody')

def test_email_parser_recursion_error():
    with patch('email.message.EmailMessage.get_content', side_effect=Exception('fail1')):
        with patch('email.message.Message.get_payload', side_effect=RecursionError('fail2')):
            parsed = parse_eml_bytes(b'Subject: Test\r\nContent-Type: text/plain\r\n\r\nBody')
            assert parsed['body_plain'] == ''
            assert 'Error decoding body part.' in parsed['defects']
