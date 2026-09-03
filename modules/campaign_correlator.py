import sqlite3
import json
import uuid
import urllib.parse
from datetime import datetime, timezone
from modules.case_database import get_case, initialize_database

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
        except:
            pass
    return hosts

def correlate_case(db_path, case_id) -> dict:
    initialize_database(db_path)
    
    case_data = get_case(db_path, case_id)
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
    
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    cursor.execute("SELECT * FROM cases WHERE case_id != ?", (case_id,))
    other_cases = cursor.fetchall()
    
    best_match_campaign = None
    best_matched_indicators = []
    best_confidence = "low"
    
    matched_campaign_id = None
    matched_cases_to_join = []
    
    found_match = False
    
    for row in other_cases:
        other_ip = row["probable_origin_ip"]
        try:
            other_urls = json.loads(row["extracted_urls"]) if row["extracted_urls"] else []
        except:
            other_urls = []
        other_hosts = _extract_hostnames(other_urls)
        
        other_sender = (row["sender_domain"] or "").lower()
        other_reply = (row["reply_to_domain"] or "").lower()
        
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
            
            if row["campaign_id"]:
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
            cursor.execute("UPDATE cases SET campaign_id = ? WHERE case_id = ?", (matched_campaign_id, case_id))
            conn.commit()
            
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
            
            cursor.execute('''
                INSERT INTO campaigns (campaign_id, created_at, matched_indicators, correlation_confidence)
                VALUES (?, ?, ?, ?)
            ''', (
                new_camp_id, created_at,
                json.dumps(best_matched_indicators), best_confidence
            ))
            
            cases_to_update = matched_cases_to_join + [case_id]
            for cid in cases_to_update:
                cursor.execute("UPDATE cases SET campaign_id = ? WHERE case_id = ?", (new_camp_id, cid))
                
            conn.commit()
            res = {
                "status": "created_campaign",
                "campaign_id": new_camp_id,
                "matched_indicators": best_matched_indicators,
                "correlation_confidence": best_confidence,
                "explanation": "Correlation indicates likely shared infrastructure, not proof of a shared attacker."
            }
    else:
        res = {"status": "no_correlation"}
        
    conn.close()
    return res

def list_campaigns(db_path) -> list:
    initialize_database(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM campaigns ORDER BY created_at DESC")
    rows = cursor.fetchall()
    
    campaigns = []
    for r in rows:
        c = dict(r)
        try:
            c['matched_indicators'] = json.loads(c['matched_indicators'])
        except:
            c['matched_indicators'] = []
            
        cursor.execute("SELECT COUNT(*) FROM cases WHERE campaign_id = ?", (c["campaign_id"],))
        c["case_count"] = cursor.fetchone()[0]
        
        campaigns.append(c)
        
    conn.close()
    return campaigns

def get_campaign_cases(db_path, campaign_id) -> list:
    initialize_database(db_path)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cases WHERE campaign_id = ? ORDER BY created_at DESC", (campaign_id,))
    rows = cursor.fetchall()
    
    cases = []
    for row in rows:
        case = dict(row)
        try:
            case['extracted_urls'] = json.loads(case['extracted_urls'])
        except:
            case['extracted_urls'] = []
        try:
            case['analyzer_results'] = json.loads(case['analyzer_results'])
        except:
            case['analyzer_results'] = {}
        cases.append(case)
        
    conn.close()
    return cases
