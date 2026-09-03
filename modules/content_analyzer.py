import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

def extract_urls(text, html):
    urls = set()
    # Extract from text using regex (support defanged)
    text_urls = re.findall(r'((?:https?|hxxps?)://[^\s]+)', text, flags=re.IGNORECASE)
    urls.update(text_urls)
    
    # Extract from HTML href
    if html:
        try:
            soup = BeautifulSoup(html, 'html.parser')
            for a in soup.find_all('a', href=True):
                href = a['href'].lower()
                if href.startswith('http://') or href.startswith('https://') or href.startswith('hxxp://') or href.startswith('hxxps://'):
                    urls.add(a['href'])
        except Exception:
            pass
                
    return list(urls)

def defang_url(url):
    defanged = url.replace('http://', 'hxxp://').replace('https://', 'hxxps://')
    return defanged.replace('.', '[.]')

def is_ip_hostname(hostname):
    if not hostname: return False
    return re.match(r'^(\d{1,3}\.){3}\d{1,3}$', hostname) is not None

def has_excessive_subdomains(hostname):
    if not hostname: return False
    parts = hostname.split('.')
    return len(parts) > 4  # e.g. a.b.c.example.com -> 5 parts -> 3 subdomains + domain + tld

SHORTENERS = {'bit.ly', 't.co', 'tinyurl.com', 'ow.ly', 'is.gd', 'buff.ly', 'goo.gl', 'cutt.ly'}

def analyze_urls(urls, indicators):
    points = 0
    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""
            
            # punycode
            if hostname.startswith('xn--'):
                indicators.append({"severity": "high", "explanation": f"Punycode (IDN) used in URL: {defang_url(url)}", "points": 20})
                points += 20
                
            # IP hostname
            if is_ip_hostname(hostname):
                indicators.append({"severity": "high", "explanation": f"IP address used as hostname: {defang_url(url)}", "points": 30})
                points += 30
                
            # @ symbol in authority (parsed.netloc contains user:pass@host)
            if '@' in parsed.netloc:
                indicators.append({"severity": "high", "explanation": f"Credential embedded in URL (@ symbol): {defang_url(url)}", "points": 25})
                points += 25
                
            # excessive subdomains
            if has_excessive_subdomains(hostname):
                indicators.append({"severity": "medium", "explanation": f"Excessive subdomains in URL: {defang_url(url)}", "points": 15})
                points += 15
                
            # shortener
            if hostname.lower() in SHORTENERS:
                indicators.append({"severity": "medium", "explanation": f"URL shortener used: {defang_url(url)}", "points": 10})
                points += 10
                
        except Exception:
            pass
    return points

def extract_clean_text(parsed_email):
    text = parsed_email.get("analysis_text", "")
            
    subject = parsed_email.get("subject", "")
    full_content = f"{subject}\n\n{text}"
    
    if len(full_content) > 50000:
        full_content = full_content[:50000]
        
    return full_content

def analyze_content(parsed_email: dict) -> dict:
    content = extract_clean_text(parsed_email)
    content_lower = content.lower()
    
    indicators = []
    categories = set()
    total_points = 0
    
    # Keyword checks
    keywords = {
        "urgency": (["urgent", "immediately", "action required", "asap", "within 24 hours"], 15, "medium"),
        "credential request": (["password", "login", "sign into", "verify your account", "verifying your identity", "update your account", "click here to secure"], 30, "high"),
        "payment diversion": (["wire transfer", "bank details", "swift code", "payment instructions"], 30, "high"),
        "fake invoice": (["invoice attached", "outstanding payment", "billing statement"], 20, "medium"),
        "executive impersonation": (["ceo", "director", "president", "are you at your desk"], 15, "medium"),
        "secrecy request": (["confidential", "keep this private", "secret", "do not discuss"], 20, "medium"),
        "threats or fear": (["account suspended", "restricted", "legal action", "final warning", "will be closed"], 25, "high"),
    }
    
    for cat, (phrases, points, severity) in keywords.items():
        for phrase in phrases:
            if phrase in content_lower:
                indicators.append({"severity": severity, "explanation": f"Language indicates {cat} ('{phrase}')", "points": points})
                categories.add(cat)
                total_points += points
                break # count category once
                
    # Contextual rules
    contextual_rules = [
        ("threats or fear", r'\b(accounts?|wallets?|profiles?)\b', r'\b(blocked|locked|restricted|suspended|disabled)\b', 25, "high", "Account-access threat"),
        ("credential request", r'\b(restore|unblock|reactivate|recover)s?\b', r'\b(accounts?|wallets?|access)\b', 25, "high", "Restoration action"),
        ("credential request", r'\b(verify|confirm|validate|update)s?\b', r'\b(identit(?:y|ies)|accounts?|informations?|details?)\b', 25, "high", "Verification request"),
        ("suspicious url", r'\b(click|follow|use|open)s?\b', r'\b(links?|buttons?|below|here)\b', 15, "medium", "Link action"),
        ("urgency", r'\b(funds?|withdrawals?|payments?|wallets?)\b', r'\b(restricted|blocked|held|frozen)\b', 25, "high", "Financial-access urgency"),
        ("executive impersonation", r'\b(ceo|president|director|executive|manager|founder)s?\b', r'\b(wire|transfer|pay|payments?|vendors?|invoices?)\b', 30, "high", "Executive payment request"),
        ("urgency", r'\b(urgent|immediately|asap|rush)\b', r'\b(wire|transfer|payments?|funds?)\b', 25, "high", "Urgent payment request"),
        ("secrecy request", r'\b(confidential|private|secret|discreet|do not discuss)\b', r'\b(wire|transfer|payments?|pay|vendors?)\b', 25, "high", "Secret payment request")
    ]
    
    added_explanations = set()
    for cat, grp_a, grp_b, pts, sev, explanation in contextual_rules:
        # Match both groups within an 80-character window in either order
        pattern = fr'(?:{grp_a})[\s\S]{{0,80}}?(?:{grp_b})|(?:{grp_b})[\s\S]{{0,80}}?(?:{grp_a})'
        if re.search(pattern, content_lower):
            if explanation not in added_explanations:
                indicators.append({"severity": sev, "explanation": f"Contextual pattern detected: {explanation}", "points": pts})
                categories.add(cat)
                total_points += pts
                added_explanations.add(explanation)
                
    # Attachments
    suspicious_exts = ['.exe', '.scr', '.vbs', '.js', '.bat', '.cmd', '.wsf', '.ps1', '.zip', '.rar', '.iso']
    for att in parsed_email.get("attachments", []):
        fname = att.get("filename", "").lower()
        if any(fname.endswith(ext) for ext in suspicious_exts):
            indicators.append({"severity": "high", "explanation": f"Suspicious attachment extension: {fname}", "points": 40})
            categories.add("suspicious attachment")
            total_points += 40
            
    # URLs
    urls = extract_urls(parsed_email.get("analysis_text", ""), parsed_email.get("body_html", ""))
    url_points = analyze_urls(urls, indicators)
    total_points += url_points
    if url_points > 0:
        categories.add("suspicious url")
        
    defanged_urls = [defang_url(u) for u in urls]
    
    score = min(max(total_points, 0), 100)
    
    return {
        "analyzed_text_length": len(content),
        "categories_detected": list(categories),
        "indicators": indicators,
        "original_urls": urls,
        "defanged_urls": defanged_urls,
        "rule_content_score": score,
        "sanitized_text": content
    }
