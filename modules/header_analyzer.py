import re

def extract_domain(email_str):
    if not email_str:
        return None
    match = re.search(r'@([\w.-]+)', email_str)
    if match:
        return match.group(1).lower().strip('>')
    return None

def is_aligned(domain1, domain2):
    if not domain1 or not domain2:
        return False
    d1, d2 = domain1.lower(), domain2.lower()
    return d1 == d2 or d1.endswith('.' + d2) or d2.endswith('.' + d1)

def analyze_headers(parsed_email: dict) -> dict:
    indicators = []
    
    from_header = parsed_email.get("from", "")
    return_path = parsed_email.get("return_path", "")
    reply_to = parsed_email.get("reply_to", "")
    message_id = parsed_email.get("message_id", "")
    
    from_domain = extract_domain(from_header)
    return_path_domain = extract_domain(return_path)
    reply_to_domain = extract_domain(reply_to)
    message_id_domain = extract_domain(message_id)
    
    domains = {
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "reply_to_domain": reply_to_domain,
        "message_id_domain": message_id_domain
    }

    # Missing headers
    if not message_id:
        indicators.append({"severity": "medium", "explanation": "Missing Message-ID header."})
    
    if not return_path:
        indicators.append({"severity": "medium", "explanation": "Missing Return-Path header."})
        
    if not parsed_email.get("received"):
        indicators.append({"severity": "high", "explanation": "Missing Received headers."})
        
    # Domain mismatches
    if from_domain and return_path_domain and not is_aligned(from_domain, return_path_domain):
        indicators.append({"severity": "high", "explanation": f"From domain ({from_domain}) and Return-Path domain ({return_path_domain}) mismatch."})
        
    if from_domain and reply_to_domain and not is_aligned(from_domain, reply_to_domain):
        indicators.append({"severity": "medium", "explanation": f"From domain ({from_domain}) and Reply-To domain ({reply_to_domain}) mismatch."})
        
    if from_domain and message_id_domain and not is_aligned(from_domain, message_id_domain):
        indicators.append({"severity": "low", "explanation": f"From domain ({from_domain}) and Message-ID domain ({message_id_domain}) mismatch."})
        
    # X-Mailer check
    x_mailer = parsed_email.get("x_mailer", "").lower()
    suspicious_mailers = ["php", "python", "java", "ruby", "perl", "curl", "wget"]
    if x_mailer:
        if any(sm in x_mailer for sm in suspicious_mailers):
            indicators.append({"severity": "high", "explanation": f"Suspicious X-Mailer found: {x_mailer}"})
            
    # Authentication Results
    auth_results = parsed_email.get("authentication_results", [])
    auth_statuses = {"spf": "none", "dkim": "none", "dmarc": "none"}
    
    for result in auth_results:
        res_lower = result.lower()
        
        if "spf=pass" in res_lower: auth_statuses["spf"] = "pass"
        elif "spf=fail" in res_lower: auth_statuses["spf"] = "fail"
        elif "spf=softfail" in res_lower: auth_statuses["spf"] = "softfail"
        
        if "dkim=pass" in res_lower: auth_statuses["dkim"] = "pass"
        elif "dkim=fail" in res_lower: auth_statuses["dkim"] = "fail"
        
        if "dmarc=pass" in res_lower: auth_statuses["dmarc"] = "pass"
        elif "dmarc=fail" in res_lower: auth_statuses["dmarc"] = "fail"
        
    if auth_statuses["spf"] in ["fail", "softfail"]:
        indicators.append({"severity": "high", "explanation": f"Reported SPF status is {auth_statuses['spf']}."})
    if auth_statuses["dkim"] == "fail":
        indicators.append({"severity": "high", "explanation": "Reported DKIM status is fail."})
    if auth_statuses["dmarc"] == "fail":
        indicators.append({"severity": "high", "explanation": "Reported DMARC status is fail."})

    return {
        "extracted_domains": domains,
        "reported_auth_statuses": auth_statuses,
        "indicators": indicators
    }
