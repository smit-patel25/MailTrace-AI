import ipaddress
import re
from modules.relay_analyzer import extract_and_classify_ips

def _is_valid_dns_hostname(hostname):
    if not hostname:
        return None
    hostname = hostname.lower()
    if hostname.endswith('.'):
        hostname = hostname[:-1]
    if not hostname or len(hostname) > 253:
        return None

    labels = hostname.split('.')
    if not labels or len(labels) > 127:
        return None

    for label in labels:
        if not label or len(label) > 63:
            return None
        if label.startswith('-') or label.endswith('-'):
            return None
        if not re.fullmatch(r'[a-z0-9-]+', label):
            return None

    return hostname

def _extract_from_hostname(header, probable_ip_str):
    if not isinstance(header, str) or not header.strip():
        return None

    if type(probable_ip_str) is not str or not probable_ip_str.strip():
        return None

    try:
        canonical_probable = ipaddress.ip_address(probable_ip_str)
    except (ValueError, TypeError):
        return None

    match = re.match(r'(?i)^\s*from\s+(\S+)', header)
    if not match:
        return None

    hostname_token = match.group(1)

    i = 0
    length = len(header)
    in_parens = 0
    in_brackets = 0
    end_of_from = length

    while i < length:
        c = header[i]

        # Backslash escaping is only valid inside RFC 5321 comments (parentheses).
        # A top-level backslash is not a valid Received-header construct; reject it
        # conservatively so an attacker cannot use it to hide a `by` keyword.
        if c == '\\':
            if in_parens > 0:
                # consume the next character inside a comment
                i += 2
                continue
            else:
                # unsupported top-level escape — reject the whole header
                return None

        if c == '(':
            in_parens += 1
        elif c == ')':
            in_parens -= 1
            if in_parens < 0:
                return None
            # After closing a top-level comment, check whether `by` follows
            # immediately (no whitespace separator), e.g. "(relay)by ...".
            if in_parens == 0 and in_brackets == 0:
                j = i + 1
                if j + 1 < length and header[j].lower() == 'b' and header[j + 1].lower() == 'y':
                    if j + 2 == length or header[j + 2].isspace() or header[j + 2] in '([;':
                        end_of_from = i + 1  # include the ')' itself but stop before 'by'
                        break
        elif c == '[':
            in_brackets += 1
        elif c == ']':
            in_brackets -= 1
            if in_brackets < 0:
                return None
            # Same check after a closing bracket at top level.
            if in_parens == 0 and in_brackets == 0:
                j = i + 1
                if j + 1 < length and header[j].lower() == 'b' and header[j + 1].lower() == 'y':
                    if j + 2 == length or header[j + 2].isspace() or header[j + 2] in '([;':
                        end_of_from = i + 1
                        break
        elif in_parens == 0 and in_brackets == 0:
            if c == ';':
                end_of_from = i
                break

            # Detect whitespace-separated `by` at top level.
            if c.lower() == 'b' and i > 0 and header[i - 1].isspace():
                if i + 1 < length and header[i + 1].lower() == 'y':
                    if i + 2 == length or header[i + 2].isspace() or header[i + 2] in '([;':
                        end_of_from = i
                        break
        i += 1

    if in_parens != 0 or in_brackets != 0:
        return None

    from_clause = header[:end_of_from]

    extracted = extract_and_classify_ips(from_clause)

    found = False
    for item in extracted:
        ip_str = item.get('ip')
        if not ip_str:
            continue
        try:
            if ipaddress.ip_address(ip_str) == canonical_probable:
                found = True
                break
        except (ValueError, TypeError):
            continue

    if not found:
        return None

    return _is_valid_dns_hostname(hostname_token)

def calculate_fraud_score(
    header_analysis,
    content_analysis,
    relay_analysis,
    geolocation_result=None,
    domain_result=None,
    gemini_result=None,
    attachment_analysis=None
) -> dict:

    top_reasons = []
    unavailable_sources = []

    # 1. Header and authentication risk (Max 35)
    header_points = 0
    for ind in header_analysis.get("indicators", []):
        sev = ind.get("severity", "info").lower()
        explanation = ind.get("explanation", "")
        if sev == "high":
            pts = 15
        elif sev == "medium":
            pts = 10
        elif sev == "low":
            pts = 5
        else:
            pts = 0

        if pts > 0:
            header_points += pts
            if explanation not in top_reasons:
                top_reasons.append(explanation)

    header_score = min(35, header_points)

    # 2. Infrastructure risk (Max 20)
    infra_points = 0
    if geolocation_result:
        if geolocation_result.get("available"):
            # Determine recognized infrastructure
            probable_ip = relay_analysis.get("probable_origin_ip") if relay_analysis else None
            received_headers = relay_analysis.get("original_received_headers", []) if relay_analysis else []
            matched_hostname = None
            for header in received_headers:
                extracted_host = _extract_from_hostname(header, probable_ip)
                if extracted_host:
                    matched_hostname = extracted_host
                    break

            org_asn = str(geolocation_result.get("location", {}).get("org", "")).lower() + " " + str(geolocation_result.get("location", {}).get("as", "")).lower()

            is_recognized_infra = False
            if matched_hostname:
                if "google" in org_asn and (matched_hostname == "google.com" or matched_hostname.endswith(".google.com") or matched_hostname == "googlemail.com" or matched_hostname.endswith(".googlemail.com")):
                    is_recognized_infra = True
                elif "microsoft" in org_asn and (matched_hostname == "outlook.com" or matched_hostname.endswith(".outlook.com")):
                    is_recognized_infra = True
                elif "amazon" in org_asn and (matched_hostname == "amazonses.com" or matched_hostname.endswith(".amazonses.com")):
                    is_recognized_infra = True

            if is_recognized_infra:
                top_reasons.append("Recognized email delivery infrastructure — neutral signal. Note: The IP is a mail relay, not necessarily the sender's device or physical origin.")
            else:
                if geolocation_result.get("proxy"):
                    infra_points += 10
                    top_reasons.append("Origin IP is an anonymizing proxy.")
                if geolocation_result.get("hosting"):
                    infra_points += 10
                    top_reasons.append("Origin IP belongs to a hosting provider/datacenter.")
        else:
            unavailable_sources.append("Geolocation (Unavailable)")
    else:
        unavailable_sources.append("Geolocation (Not checked)")

    infra_score = min(20, infra_points)

    # 3. URL, domain and identity risk (Max 20)
    domain_points = 0
    if domain_result:
        if domain_result.get("available"):
            age = domain_result.get("domain_age_days")
            if age is not None:
                if age < 14:
                    domain_points += 15
                    top_reasons.append("Sender domain is extremely new (under 14 days).")
                elif age < 30:
                    domain_points += 10
                    top_reasons.append("Sender domain is newly registered (under 30 days).")
        else:
            unavailable_sources.append("Domain Intelligence")

    # Extract URL indicators from content_analysis to avoid double counting
    rule_content_points = 0
    for ind in content_analysis.get("indicators", []):
        explanation = ind.get("explanation", "")
        pts = ind.get("points", 0)

        # Check if this indicator relates to a URL
        if "url" in explanation.lower() or "hostname" in explanation.lower() or "punycode" in explanation.lower():
            domain_points += pts * 0.5  # scale down to fit within the domain risk max
            if explanation not in top_reasons:
                top_reasons.append(explanation)
        else:
            rule_content_points += pts
            if explanation not in top_reasons:
                top_reasons.append(explanation)

    domain_score = min(20, int(domain_points))

    # 4. Content and BEC risk (Max 25)
    base_content_score = min(100, rule_content_points)

    if gemini_result:
        if gemini_result.get("available"):
            gemini_score = gemini_result.get("nlp_risk_score", 0)
            # Combine rule-based score and AI score equally
            base_content_score = (base_content_score + gemini_score) / 2.0

            # Add Gemini specific cues to top reasons
            cat = gemini_result.get("threat_category", "Legitimate")
            if cat not in ["Legitimate", "Unknown"]:
                top_reasons.append(f"AI classified content as {cat}.")

            if gemini_result.get("urgency_cues"): top_reasons.append("AI detected urgency cues.")
            if gemini_result.get("financial_request"): top_reasons.append("AI detected financial requests.")
            if gemini_result.get("credential_request"): top_reasons.append("AI detected credential requests.")
            if gemini_result.get("impersonation_language"): top_reasons.append("AI detected impersonation language.")
        else:
            unavailable_sources.append("Gemini Analysis")

    # Scale from 100 to max 25
    content_score = min(25, int((base_content_score / 100.0) * 25))

    # 5. Attachment metadata risk (Max 50)
    attachment_points = 0
    if isinstance(attachment_analysis, dict):
        overall_att_risk = attachment_analysis.get("overall_metadata_risk", "None")
        if overall_att_risk == "High":
            attachment_points = 50
            top_reasons.append("Attachment metadata indicates a high-risk file or structural anomaly.")
        elif overall_att_risk == "Review":
            attachment_points = 15
            top_reasons.append("Attachment metadata contains characteristics requiring review.")

    # Calculate final score
    final_score = header_score + infra_score + domain_score + content_score + attachment_points

    corroboration_bonus = 0
    if gemini_result and gemini_result.get("available"):
        gemini_score = gemini_result.get("nlp_risk_score", 0)
        cat = gemini_result.get("threat_category", "")
        valid_cats = {"Phishing", "Credential Harvesting", "BEC", "Business Email Compromise", "Impersonation"}
        if gemini_score >= 80 and rule_content_points >= 40 and cat in valid_cats:
            corroboration_bonus = 30

    if corroboration_bonus > 0:
        final_score += corroboration_bonus
        top_reasons.append("Independent AI and rule-based analysis strongly corroborate a severe email threat.")

    final_score = max(0, min(100, final_score))

    # Determine risk level and verdict
    if final_score <= 24:
        risk_level = "Low"
        verdict = "Low Risk"
    elif final_score <= 49:
        risk_level = "Moderate"
        verdict = "Suspicious"
    elif final_score <= 74:
        risk_level = "High"
        verdict = "Likely Malicious"
    else:
        risk_level = "Critical"
        verdict = "Highly Likely Malicious"

    confidence = "High" if not unavailable_sources else "Medium"
    if len(unavailable_sources) >= 2:
        confidence = "Low"

    # Deduplicate top_reasons while keeping order
    seen_reasons = set()
    deduped_reasons = []
    for r in top_reasons:
        if r not in seen_reasons:
            seen_reasons.add(r)
            deduped_reasons.append(r)

    return {
        "final_score": final_score,
        "risk_level": risk_level,
        "verdict": verdict,
        "confidence": confidence,
        "component_scores": {
            "header_risk": header_score,
            "content_risk": content_score,
            "infrastructure_risk": infra_score,
            "domain_risk": domain_score,
            "attachment_risk": min(50, attachment_points)
        },
        "top_reasons": deduped_reasons[:10], # Top 10 reasons max
        "unavailable_sources": unavailable_sources,
        "corroboration_bonus": corroboration_bonus,
        "scoring_version": "1.2"
    }
