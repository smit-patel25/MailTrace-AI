import ipaddress
import re

def extract_and_classify_ips(text):
    """
    Extracts IPv4 and IPv6 addresses from text by tokenizing and validating,
    then classifies them.
    """
    # Split text by characters that are not valid in IP addresses
    tokens = re.split(r'[^a-fA-F0-9:.]', text)
    classified_ips = []
    seen = set()
    
    for token in tokens:
        if not token:
            continue
        try:
            ip = ipaddress.ip_address(token)
            ip_str = str(ip)
            
            # Filter out simple numbers that happen to be valid IPs in some contexts
            # but ipaddress module accepts them (e.g. "1" -> 0.0.0.1).
            # We want strings that actually look like IPs (contain dot or colon)
            if '.' not in token and ':' not in token:
                continue
                
            if ip_str in seen:
                continue
            seen.add(ip_str)
            
            # Determine type
            if ip.is_loopback:
                ip_type = 'loopback'
            elif ip.is_unspecified:
                ip_type = 'unspecified'
            elif ip.is_multicast:
                ip_type = 'multicast'
            elif ip.is_link_local:
                ip_type = 'link-local'
            elif ip.is_private:
                ip_type = 'private'
            elif ip.is_reserved:
                ip_type = 'reserved'
            else:
                ip_type = 'public'
                
            classified_ips.append({
                'ip': ip_str,
                'type': ip_type,
                'version': ip.version
            })
        except ValueError:
            pass # Not a valid IP
            
    return classified_ips

def analyze_relay_chain(parsed_email: dict) -> dict:
    original_received = parsed_email.get("received", [])
    # Received headers are typically prepended, so the chronological order is reversed
    chronological_hops = list(reversed(original_received))
    
    all_extracted_ips = []
    public_ips = []
    probable_origin_ip = None
    origin_confidence = "low"
    confidence_explanation = "No reliable public origin can be determined."
    
    seen_all = set()
    seen_pub = set()
    
    for i, hop in enumerate(chronological_hops):
        ips_in_hop = extract_and_classify_ips(hop)
        
        for ip_info in ips_in_hop:
            if ip_info['ip'] not in seen_all:
                seen_all.add(ip_info['ip'])
                all_extracted_ips.append(ip_info)
                
            if ip_info['type'] == 'public':
                if ip_info['ip'] not in seen_pub:
                    seen_pub.add(ip_info['ip'])
                    public_ips.append(ip_info)
                
                # First chronological public IP is the probable origin
                if probable_origin_ip is None:
                    probable_origin_ip = ip_info['ip']
                    if i == 0:
                        origin_confidence = "medium"
                        confidence_explanation = "The earliest chronological hop contains a public IP (probable infrastructure origin, not necessarily attacker's physical location)."
                    else:
                        origin_confidence = "low"
                        confidence_explanation = "A public IP was found, but not in the earliest chronological hop."

    return {
        "original_received_headers": original_received,
        "chronological_hops": chronological_hops,
        "all_extracted_ips": all_extracted_ips,
        "public_ips": public_ips,
        "probable_origin_ip": probable_origin_ip,
        "origin_confidence": origin_confidence,
        "confidence_explanation": confidence_explanation
    }
