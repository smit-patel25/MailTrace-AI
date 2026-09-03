def calculate_fraud_score(
    header_analysis,
    content_analysis,
    relay_analysis,
    geolocation_result=None,
    domain_result=None,
    gemini_result=None
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
            matched_hostname = ""
            for header in received_headers:
                if probable_ip and probable_ip in header:
                    matched_hostname = header.lower()
                    break

            org_asn = str(geolocation_result.get("location", {}).get("org", "")).lower() + " " + str(geolocation_result.get("location", {}).get("as", "")).lower()

            is_recognized_infra = False
            if "google" in org_asn and ("google.com" in matched_hostname or "googlemail.com" in matched_hostname):
                is_recognized_infra = True
            elif "microsoft" in org_asn and ("outlook.com" in matched_hostname):
                is_recognized_infra = True
            elif "amazon" in org_asn and ("amazonses.com" in matched_hostname):
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
            unavailable_sources.append("Geolocation")

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

    # Calculate final score
    final_score = header_score + infra_score + domain_score + content_score

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
            "domain_risk": domain_score
        },
        "top_reasons": deduped_reasons[:10], # Top 10 reasons max
        "unavailable_sources": unavailable_sources,
        "corroboration_bonus": corroboration_bonus,
        "scoring_version": "1.1"
    }
