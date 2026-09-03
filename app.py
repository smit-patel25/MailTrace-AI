import streamlit as st
import os
import hashlib
from dotenv import load_dotenv
from modules.email_parser import parse_eml_bytes
from modules.header_analyzer import analyze_headers
from modules.relay_analyzer import analyze_relay_chain
from modules.geolocation import geolocate_ip
from modules.domain_intelligence import analyze_domain
from modules.content_analyzer import analyze_content
from modules.gemini_analyzer import analyze_with_gemini
from modules.risk_scoring import calculate_fraud_score
from modules.ui_theme import apply_theme, sidebar_header, footer, risk_badge
import folium
from streamlit_folium import st_folium

load_dotenv()

st.set_page_config(page_title="MailTrace AI", layout="wide")
apply_theme()
sidebar_header()

st.title("MailTrace AI")
st.subheader("Email Threat Detection and Forensic Intelligence Platform")

uploaded_file = st.file_uploader("Upload an .eml file", type=["eml"])

if uploaded_file is not None:
    if "current_file_name" not in st.session_state or st.session_state.current_file_name != uploaded_file.name:
        st.session_state.current_file_name = uploaded_file.name
        if "geo_result" in st.session_state:
            del st.session_state["geo_result"]
        if "domain_result" in st.session_state:
            del st.session_state["domain_result"]

    # 2 MB limit
    MAX_FILE_SIZE = 2 * 1024 * 1024
    if uploaded_file.size > MAX_FILE_SIZE:
        st.error("File exceeds the maximum allowed size of 2 MB.")
    else:
        # Read file as bytes
        raw_bytes = uploaded_file.getvalue()
        email_hash = hashlib.sha256(raw_bytes).hexdigest()
        
        # Parse
        parsed_data = parse_eml_bytes(raw_bytes)
        
        # Handle parser errors gracefully
        if "defects" in parsed_data and any("Fatal parsing error" in str(d) for d in parsed_data["defects"]):
            st.error("Failed to parse the email file. Please ensure it is a valid .eml format.")
        else:
            st.success("Email parsed successfully!")
            
            # Run core analyzers
            analysis = analyze_headers(parsed_data)
            relay_analysis = analyze_relay_chain(parsed_data)
            content_analysis = analyze_content(parsed_data)
            
            geo_res = st.session_state.get("geo_result")
            domain_res = st.session_state.get("domain_result")
            gemini_res = st.session_state.get(f"gemini_{email_hash}")
            
            fraud_score = calculate_fraud_score(
                analysis, content_analysis, relay_analysis,
                geo_res, domain_res, gemini_res
            )
            
            # Threat Assessment
            st.header("Threat Assessment")
            
            score = fraud_score["final_score"]
            risk_level = fraud_score["risk_level"]
            verdict = fraud_score["verdict"]
            
            
            st.markdown(f"### Final Fraud Score: <span style='color:var(--cyan-accent);'>{score} / 100</span>", unsafe_allow_html=True)
            
            corroboration_bonus = fraud_score.get("corroboration_bonus", 0)
            if corroboration_bonus > 0:
                st.markdown(f"**Cross-Signal Corroboration Bonus: <span style='color:var(--cyan-accent);'>+{corroboration_bonus}</span>**", unsafe_allow_html=True)
                
            st.markdown(f"**Verdict:** {verdict} | **Risk Level:** {risk_badge(risk_level)} | **Confidence:** {fraud_score['confidence']} | **Scoring Version:** {fraud_score['scoring_version']}", unsafe_allow_html=True)
            st.info("Note: This result is an investigative assessment, not proof of attacker identity.")
            
            c1, c2, c3, c4 = st.columns(4)
            c_scores = fraud_score["component_scores"]
            with c1:
                st.write("Header & Auth (Max 35)")
                st.progress(c_scores["header_risk"] / 35.0)
                st.write(f"{c_scores['header_risk']} pts")
            with c2:
                st.write("Content & BEC (Max 25)")
                st.progress(c_scores["content_risk"] / 25.0)
                st.write(f"{c_scores['content_risk']} pts")
            with c3:
                st.write("Infrastructure (Max 20)")
                st.progress(c_scores["infrastructure_risk"] / 20.0)
                st.write(f"{c_scores['infrastructure_risk']} pts")
            with c4:
                st.write("URL, Domain & Identity (Max 20)")
                st.progress(c_scores["domain_risk"] / 20.0)
                st.write(f"{c_scores['domain_risk']} pts")
                
            st.subheader("Top Reasons")
            if fraud_score["top_reasons"]:
                for r in fraud_score["top_reasons"]:
                    st.write(f"- {r}")
            else:
                st.write("No significant risk reasons detected.")
                
            if fraud_score["unavailable_sources"]:
                st.write("**Unavailable Optional Sources (Not treated as failures):** " + ", ".join(fraud_score["unavailable_sources"]))
                
            st.markdown("---")
            
            st.subheader("Case Management")
            if st.button("Save as Case"):
                with st.spinner("Saving case..."):
                    from modules.case_database import save_case
                    from modules.campaign_correlator import correlate_case
                    
                    case_data = {
                        "filename": uploaded_file.name,
                        "email_hash": email_hash,
                        "subject": parsed_data.get("subject", ""),
                        "sender_address": parsed_data.get("from", ""),
                        "sender_domain": analysis["extracted_domains"].get("from_domain", ""),
                        "reply_to_domain": analysis["extracted_domains"].get("reply_to_domain", ""),
                        "probable_origin_ip": relay_analysis.get("probable_origin_ip", ""),
                        "extracted_urls": content_analysis.get("original_urls", []),
                        "fraud_score": fraud_score["final_score"],
                        "risk_level": fraud_score["risk_level"],
                        "verdict": fraud_score["verdict"],
                        "confidence": fraud_score["confidence"],
                        "analyzer_results": {
                            "header_analysis": analysis,
                            "relay_analysis": relay_analysis,
                            "content_analysis": content_analysis,
                            "fraud_score": fraud_score
                        }
                    }
                    db_path = os.getenv("DB_PATH", "database.sqlite3")
                    case_id = save_case(db_path, case_data)
                    st.success(f"Successfully saved as {case_id}.")
                    
                    corr_res = correlate_case(db_path, case_id)
                    if corr_res.get("status") == "joined_campaign":
                        st.info(f"Case joined existing campaign: **{corr_res['campaign_id']}**")
                    elif corr_res.get("status") == "created_campaign":
                        st.info(f"Case formed a new campaign: **{corr_res['campaign_id']}**")
                    elif corr_res.get("status") == "already_correlated":
                        st.info(f"Case is already correlated to campaign: **{corr_res['campaign_id']}**")
                    else:
                        st.info("Case currently has no campaign match.")

            st.markdown("---")
            
            # Display basic headers
            st.header("Basic Information")
            col1, col2 = st.columns(2)
            with col1:
                st.text_input("Subject", value=parsed_data.get("subject", ""), disabled=True)
                st.text_input("From", value=parsed_data.get("from", ""), disabled=True)
                st.text_input("To", value=parsed_data.get("to", ""), disabled=True)
                st.text_input("Date", value=parsed_data.get("date", ""), disabled=True)
            with col2:
                st.text_input("Message-ID", value=parsed_data.get("message_id", ""), disabled=True)
                st.text_input("Reply-To", value=parsed_data.get("reply_to", ""), disabled=True)
                st.text_input("Return-Path", value=parsed_data.get("return_path", ""), disabled=True)
                st.text_input("Relay Hops", value=str(len(parsed_data.get("received", []))), disabled=True)
                st.text_input("Attachments", value=str(len(parsed_data.get("attachments", []))), disabled=True)
                
            # Header Forensics
            st.header("Header Forensics")
            
            # Auth Results Statuses
            st.markdown("**Reported status - not independently verified**")
            auth = analysis["reported_auth_statuses"]
            
            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown(f"### SPF\n{risk_badge(auth['spf'].upper())}", unsafe_allow_html=True)
            with c2:
                st.markdown(f"### DKIM\n{risk_badge(auth['dkim'].upper())}", unsafe_allow_html=True)
            with c3:
                st.markdown(f"### DMARC\n{risk_badge(auth['dmarc'].upper())}", unsafe_allow_html=True)
            
            st.markdown("---")
            
            # Extracted Domains
            st.subheader("Extracted Domains")
            domains = analysis["extracted_domains"]
            st.write(f"- **From Domain:** {domains.get('from_domain') or 'None'}")
            st.write(f"- **Return-Path Domain:** {domains.get('return_path_domain') or 'None'}")
            st.write(f"- **Reply-To Domain:** {domains.get('reply_to_domain') or 'None'}")
            st.write(f"- **Message-ID Domain:** {domains.get('message_id_domain') or 'None'}")
            
            # Indicators
            st.subheader("Detected Indicators")
            if not analysis["indicators"]:
                st.success("No header anomalies detected.")
            else:
                for ind in analysis["indicators"]:
                    sev = ind["severity"].lower()
                    if sev == "high":
                        st.error(f"**HIGH:** {ind['explanation']}")
                    elif sev == "medium":
                        st.warning(f"**MEDIUM:** {ind['explanation']}")
                    elif sev == "low":
                        st.info(f"**LOW:** {ind['explanation']}")
                    else:
                        st.write(f"**INFO:** {ind['explanation']}")

            # Email Route Trace
            st.header("Email Route Trace")
            if relay_analysis.get("probable_origin_ip"):
                st.markdown("### Probable infrastructure origin")
                st.info(f"**IP:** {relay_analysis['probable_origin_ip']}  \n**Confidence:** {relay_analysis['origin_confidence'].upper()}  \n**Explanation:** {relay_analysis['confidence_explanation']}")
                
                if os.getenv("ENABLE_GEOLOCATION", "true").lower() != "false":
                    if st.button("Enrich Origin IP"):
                        with st.spinner("Geolocating IP..."):
                            st.session_state.geo_result = geolocate_ip(relay_analysis['probable_origin_ip'])
                            
                    if "geo_result" in st.session_state:
                        geo_result = st.session_state.geo_result
                        if geo_result.get("available"):
                            st.markdown("### Estimated infrastructure location")
                            st.warning("Note: This does not represent the attacker's exact physical location.")
                            loc = geo_result.get("location", {})
                            
                            c1, c2 = st.columns(2)
                            with c1:
                                st.write(f"**Country:** {loc.get('country')}")
                                st.write(f"**Region:** {loc.get('regionName')}")
                                st.write(f"**City:** {loc.get('city')}")
                                st.write(f"**Timezone:** {loc.get('timezone')}")
                            with c2:
                                st.write(f"**ISP:** {loc.get('isp')}")
                                st.write(f"**Organization:** {loc.get('org')}")
                                st.write(f"**ASN:** {loc.get('as')}")
                                st.write(f"**Proxy:** {'Yes' if geo_result.get('proxy') else 'No'} | **Hosting:** {'Yes' if geo_result.get('hosting') else 'No'}")
                            
                            if loc.get("lat") and loc.get("lon"):
                                st.subheader("Origin Map")
                                m = folium.Map(location=[loc["lat"], loc["lon"]], zoom_start=10)
                                folium.Marker(
                                    [loc["lat"], loc["lon"]],
                                    popup=f"{loc.get('city')}, {loc.get('country')}",
                                    tooltip=relay_analysis['probable_origin_ip']
                                ).add_to(m)
                                st_folium(m, width=700, height=500)
                        else:
                            st.warning(f"Geolocation failed: {geo_result.get('error')}")
            else:
                st.warning("No reliable public origin could be determined from the relay chain.")
                
            st.subheader("Chronological Relay Hops")
            for i, hop in enumerate(relay_analysis["chronological_hops"]):
                st.markdown(f"**Hop {i+1}:**")
                st.code(hop, language="text")
                
            st.subheader("Extracted IPs")
            if relay_analysis.get("all_extracted_ips"):
                ip_data = []
                for ip_info in relay_analysis["all_extracted_ips"]:
                    eligible = "Yes" if ip_info['type'] == 'public' else "No"
                    ip_data.append({
                        "IP Address": ip_info['ip'],
                        "Classification": ip_info['type'],
                        "Eligible for Geolocation": eligible
                    })
                st.table(ip_data)
            else:
                st.write("No IPs extracted from relay chain.")

            # Sender Domain Intelligence
            st.header("Sender Domain Intelligence")
            sender_domain = domains.get("from_domain")
            if sender_domain:
                if st.button("Analyze Sender Domain"):
                    with st.spinner(f"Analyzing {sender_domain}..."):
                        st.session_state.domain_result = analyze_domain(sender_domain)
                        
                if "domain_result" in st.session_state:
                    domain_intel = st.session_state.domain_result
                    if domain_intel.get("errors"):
                        for err in domain_intel["errors"]:
                            st.warning(f"Lookup Warning: {err}")
                            
                    if domain_intel.get("available"):
                        st.subheader("Domain Registration")
                        col_a, col_b = st.columns(2)
                        with col_a:
                            st.write(f"**Normalized Domain:** {domain_intel.get('normalized_domain')}")
                            registrar = domain_intel.get('registrar')
                            st.write(f"**Registrar:** {registrar if registrar else 'Unknown / Privacy Protected'}")
                            age = domain_intel.get('domain_age_days')
                            st.write(f"**Domain Age:** {f'{age} days' if age is not None else 'Unknown'}")
                        with col_b:
                            created = domain_intel.get('creation_date')
                            st.write(f"**Creation Date:** {created if created else 'Unknown'}")
                            expires = domain_intel.get('expiration_date')
                            st.write(f"**Expiration Date:** {expires if expires else 'Unknown'}")
                            
                        st.subheader("DNS Records")
                        
                        # MX
                        st.markdown("**MX Records**")
                        if domain_intel.get("mx_records"):
                            for mx in domain_intel["mx_records"]:
                                st.code(mx, language="text")
                        else:
                            st.info("No MX records found. (Indicator, not proof of malicious activity)")
                            
                        # SPF
                        st.markdown("**SPF Record**")
                        if domain_intel.get("spf_record"):
                            st.code(domain_intel["spf_record"], language="text")
                        else:
                            st.info("No SPF record found. (Indicator, not proof of malicious activity)")
                            
                        # DMARC
                        st.markdown("**DMARC Record**")
                        if domain_intel.get("dmarc_record"):
                            st.code(domain_intel["dmarc_record"], language="text")
                        else:
                            st.info("No DMARC record found. (Indicator, not proof of malicious activity)")
                            
                        # A / AAAA
                        st.markdown("**A Records**")
                        if domain_intel.get("a_records"):
                            st.write(", ".join(domain_intel["a_records"]))
                        else:
                            st.write("None")
                            
                        st.markdown("**AAAA Records**")
                        if domain_intel.get("aaaa_records"):
                            st.write(", ".join(domain_intel["aaaa_records"]))
                        else:
                            st.write("None")
            else:
                st.info("No valid sender domain found to analyze.")

            # Content Threat Analysis
            st.header("Content Threat Analysis")
            
            st.metric(label="Rule-based content score (Not a final fraud score)", value=f"{content_analysis['rule_content_score']} / 100")
            
            if content_analysis["categories_detected"]:
                st.write("**Detected Categories:**")
                st.write(", ".join([c.title() for c in content_analysis["categories_detected"]]))
                
            if content_analysis["indicators"]:
                st.subheader("Content Indicators")
                for ind in content_analysis["indicators"]:
                    sev = ind["severity"].lower()
                    msg = f"**{sev.upper()}** ({ind['points']} pts): {ind['explanation']}"
                    if sev == "high":
                        st.error(msg)
                    elif sev == "medium":
                        st.warning(msg)
                    else:
                        st.info(msg)
            else:
                st.success("No suspicious content indicators found in the message body or subject.")
                
            if content_analysis["defanged_urls"]:
                st.subheader("Extracted URLs (Defanged)")
                st.info("URLs have been defanged for safety and are not clickable.")
                for url in content_analysis["defanged_urls"]:
                    st.code(url, language="text")

            # AI Threat Analysis
            st.header("AI Threat Analysis")
            gemini_key = f"gemini_{email_hash}"
            if st.button("Analyze with Gemini"):
                with st.spinner("Analyzing with Gemini..."):
                    if gemini_key not in st.session_state:
                        subject = parsed_data.get("subject", "")
                        sanitized_body = parsed_data.get("analysis_text", "")
                        res = analyze_with_gemini(subject, sanitized_body)
                        st.session_state[gemini_key] = res
                        st.rerun()
            
            if gemini_key in st.session_state:
                g_res = st.session_state[gemini_key]
                if not g_res.get("available"):
                    st.warning(f"Gemini analysis unavailable: {g_res.get('error', 'Unknown error')}")
                else:
                    st.metric(label="Gemini content-risk score (Not a final fraud score)", value=f"{g_res.get('nlp_risk_score', 0)} / 100")
                    st.write(f"**Threat Category:** {g_res.get('threat_category')}")
                    
                    st.subheader("Detected AI Cues")
                    cues = []
                    if g_res.get("urgency_cues"): cues.append("Urgency")
                    if g_res.get("financial_request"): cues.append("Financial Request")
                    if g_res.get("credential_request"): cues.append("Credential Request")
                    if g_res.get("impersonation_language"): cues.append("Impersonation")
                    if g_res.get("secrecy_request"): cues.append("Secrecy Request")
                    
                    if cues:
                        st.write(", ".join(cues))
                    else:
                        st.write("None")
                        
                    st.subheader("Explanation")
                    st.write(g_res.get("explanation", ""))

            # Expanders for detailed headers
            with st.expander("Received Headers"):
                if parsed_data.get("received"):
                    for i, recv in enumerate(parsed_data["received"]):
                        st.text_area(f"Hop {i+1}", value=recv, disabled=True, height=100)
                else:
                    st.write("No Received headers found.")
                    
            with st.expander("Authentication Results"):
                if parsed_data.get("authentication_results"):
                    for i, auth_header in enumerate(parsed_data["authentication_results"]):
                        st.text_area(f"Result {i+1}", value=auth_header, disabled=True, height=100)
                else:
                    st.write("No Authentication-Results headers found.")
                    
            # Body Tabs
            st.header("Message Body")
            tab1, tab2 = st.tabs(["Plain Text", "HTML Source"])
            with tab1:
                if parsed_data.get("analysis_text"):
                    if parsed_data.get("used_html_fallback"):
                        st.info("Visible Text Extracted from HTML")
                    st.text_area("Plain Text Content", value=parsed_data["analysis_text"], disabled=True, height=300)
                else:
                    st.info("No plain-text body found.")
            with tab2:
                if parsed_data.get("body_html"):
                    st.code(parsed_data["body_html"], language="html")
                else:
                    st.info("No HTML body found.")
                    
            # Attachments
            if parsed_data.get("attachments"):
                st.header("Attachments Metadata")
                for att in parsed_data["attachments"]:
                    st.write(f"- **Filename:** {att['filename']} | **Type:** {att['content_type']} | **Size:** {att['size']} bytes")
            
            # Show any defects if present
            if parsed_data.get("defects"):
                with st.expander("Parser Defects (Warnings)"):
                    for d in parsed_data["defects"]:
                        st.warning(d)
                        
footer()
