import uuid
import urllib.parse
from datetime import datetime, timezone
from modules.session_case_store import get_case, get_cases_for_correlation, update_case_campaign, save_campaign, get_campaigns, get_campaign_cases as store_get_campaign_cases

COMMON_PROVIDERS = {"gmail.com", "outlook.com", "yahoo.com", "hotmail.com", "aol.com", "icloud.com"}

def _extract_hostnames(urls):
    hosts = set()
    for url in urls:
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname or url
            host = host.lower()
            if host:
                hosts.add(host)
        except (ValueError, TypeError, AttributeError):
            pass
    return hosts

def correlate_case(db_path, case_id) -> dict:
    # db_path is ignored now
    case_data = get_case(case_id)
    if not case_data:
        return {"error": "Case not found"}

    if case_data.get("campaign_id"):
        return {"status": "already_correlated", "campaign_id": case_data["campaign_id"]}

    target_ip = case_data.get("probable_origin_ip")
    target_urls = case_data.get("extracted_urls", [])
    target_hosts = _extract_hostnames(target_urls)

    target_sender = (case_data.get("sender_domain") or "").lower()
    target_reply = (case_data.get("reply_to_domain") or "").lower()

    if target_sender in COMMON_PROVIDERS: target_sender = ""
    if target_reply in COMMON_PROVIDERS: target_reply = ""

    other_cases = [c for c in get_cases_for_correlation() if c.get("case_id") != case_id]

    best_matched_indicators = []
    best_confidence = "low"

    matched_campaign_id = None
    matched_cases_to_join = []

    found_match = False

    for row in other_cases:
        other_ip = row.get("probable_origin_ip")
        other_urls = row.get("extracted_urls", [])
        other_hosts = _extract_hostnames(other_urls)

        other_sender = (row.get("sender_domain") or "").lower()
        other_reply = (row.get("reply_to_domain") or "").lower()

        if other_sender in COMMON_PROVIDERS: other_sender = ""
        if other_reply in COMMON_PROVIDERS: other_reply = ""

        strong_matches = []
        weak_matches = []

        if target_ip and other_ip and target_ip == other_ip:
            strong_matches.append(f"Shared Origin IP: {target_ip}")

        shared_hosts = target_hosts.intersection(other_hosts)
        for h in shared_hosts:
            strong_matches.append(f"Shared URL Hostname: {h}")

        if target_sender and other_sender and target_sender == other_sender:
            weak_matches.append(f"Shared Sender Domain: {target_sender}")

        if target_reply and other_reply and target_reply == other_reply:
            weak_matches.append(f"Shared Reply-To Domain: {target_reply}")

        is_match = False
        confidence = "low"

        if len(strong_matches) >= 2:
            is_match = True
            confidence = "high"
        elif len(strong_matches) == 1:
            is_match = True
            confidence = "medium" if len(weak_matches) == 0 else "high"
        elif len(weak_matches) >= 2:
            is_match = True
            confidence = "low"

        if is_match:
            found_match = True
            matched_indicators = strong_matches + weak_matches

            if row.get("campaign_id"):
                matched_campaign_id = row["campaign_id"]
                best_matched_indicators = matched_indicators
                best_confidence = confidence
                break
            else:
                matched_cases_to_join.append(row["case_id"])
                if not best_matched_indicators:
                    best_matched_indicators = matched_indicators
                    best_confidence = confidence

    if found_match:
        if matched_campaign_id:
            update_case_campaign(case_id, matched_campaign_id)

            res = {
                "status": "joined_campaign",
                "campaign_id": matched_campaign_id,
                "matched_indicators": best_matched_indicators,
                "correlation_confidence": best_confidence,
                "explanation": "Correlation indicates likely shared infrastructure, not proof of a shared attacker."
            }
        else:
            new_camp_id = "CAMPAIGN-" + uuid.uuid4().hex[:8].upper()
            created_at = datetime.now(timezone.utc).isoformat()

            campaign = {
                "campaign_id": new_camp_id,
                "created_at": created_at,
                "matched_indicators": best_matched_indicators,
                "correlation_confidence": best_confidence
            }
            save_campaign(campaign)

            cases_to_update = matched_cases_to_join + [case_id]
            for cid in cases_to_update:
                update_case_campaign(cid, new_camp_id)

            res = {
                "status": "created_campaign",
                "campaign_id": new_camp_id,
                "matched_indicators": best_matched_indicators,
                "correlation_confidence": best_confidence,
                "explanation": "Correlation indicates likely shared infrastructure, not proof of a shared attacker."
            }
    else:
        res = {"status": "no_correlation"}

    return res

def list_campaigns(db_path=None) -> list:
    # db_path is ignored
    campaigns = get_campaigns()
    for c in campaigns:
        # Calculate case_count
        camp_cases = store_get_campaign_cases(c["campaign_id"])
        c["case_count"] = len(camp_cases)
    return campaigns

def get_campaign_cases(db_path, campaign_id) -> list:
    # db_path is ignored
    return store_get_campaign_cases(campaign_id)
