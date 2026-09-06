import dns.resolver
import whois
from datetime import datetime, timezone
import re
import ipaddress

_DOMAIN_CACHE = {}

def validate_and_normalize_domain(domain: str) -> str:
    """Validates and normalizes a domain name, rejecting IPs and malformed strings."""
    if not domain:
        return None
    domain = domain.lower().strip()
    
    # Reject IP addresses
    try:
        ipaddress.ip_address(domain)
        return None
    except ValueError:
        pass
        
    # Basic regex for valid domain (no spaces, special chars except dash)
    # Must have at least one dot, parts cannot start/end with dash
    if not re.match(r'^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$', domain):
        return None
        
    return domain

def get_dns_records(domain: str, record_type: str) -> list:
    """Safely queries DNS records with a short timeout."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 4.0
    resolver.lifetime = 4.0
    
    try:
        answers = resolver.resolve(domain, record_type)
        if record_type == 'MX':
            return sorted([f"{r.preference} {r.exchange.to_text(omit_final_dot=True)}" for r in answers])
        elif record_type == 'TXT':
            return [b"".join(r.strings).decode('utf-8', errors='ignore') for r in answers]
        elif record_type in ['A', 'AAAA']:
            return [r.to_text() for r in answers]
    except (dns.exception.DNSException, ValueError, TypeError, AttributeError):
        pass
    return []

def analyze_domain(domain: str) -> dict:
    """
    Retrieves DNS and WHOIS intelligence for a domain.
    """
    normalized = validate_and_normalize_domain(domain)
    
    result = {
        "available": False,
        "normalized_domain": normalized,
        "mx_records": [],
        "spf_record": None,
        "dmarc_record": None,
        "a_records": [],
        "aaaa_records": [],
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "domain_age_days": None,
        "errors": []
    }
    
    if not normalized:
        result["errors"].append("Invalid, empty, or IP-based domain.")
        return result
        
    if normalized in _DOMAIN_CACHE:
        return _DOMAIN_CACHE[normalized]
        
    result["available"] = True
    
    # 1. DNS Queries
    result["mx_records"] = get_dns_records(normalized, 'MX')
    result["a_records"] = get_dns_records(normalized, 'A')
    result["aaaa_records"] = get_dns_records(normalized, 'AAAA')
    
    # SPF
    txt_records = get_dns_records(normalized, 'TXT')
    for txt in txt_records:
        if txt.startswith("v=spf1"):
            result["spf_record"] = txt
            break
            
    # DMARC
    dmarc_domain = f"_dmarc.{normalized}"
    dmarc_txt_records = get_dns_records(dmarc_domain, 'TXT')
    for txt in dmarc_txt_records:
        if txt.startswith("v=DMARC1"):
            result["dmarc_record"] = txt
            break
            
    # 2. WHOIS Query
    try:
        w = whois.whois(normalized)
        
        if w.registrar:
            if isinstance(w.registrar, list):
                result["registrar"] = w.registrar[0]
            else:
                result["registrar"] = w.registrar
                
        def parse_date(date_obj):
            if not date_obj:
                return None
            if isinstance(date_obj, list):
                date_val = date_obj[0]
            else:
                date_val = date_obj
            
            if isinstance(date_val, datetime):
                # if naive, assume UTC
                if date_val.tzinfo is None:
                    date_val = date_val.replace(tzinfo=timezone.utc)
                return date_val
            return None
            
        creation_date = parse_date(w.creation_date)
        expiration_date = parse_date(w.expiration_date)
        
        if creation_date:
            result["creation_date"] = creation_date.isoformat()
            now = datetime.now(timezone.utc)
            age = (now - creation_date).days
            result["domain_age_days"] = age if age >= 0 else 0
            
        if expiration_date:
            result["expiration_date"] = expiration_date.isoformat()
            
    except Exception as e:
        result["errors"].append(f"WHOIS lookup failed: {str(e)}")
        
    _DOMAIN_CACHE[normalized] = result
    
    return result
