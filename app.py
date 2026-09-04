import streamlit as st
import os
import hashlib
import html
from dotenv import load_dotenv
import time
from modules.email_parser import parse_eml_bytes
from modules.header_analyzer import analyze_headers
from modules.relay_analyzer import analyze_relay_chain
from modules.geolocation import geolocate_ip
from modules.domain_intelligence import analyze_domain
from modules.content_analyzer import analyze_content
from modules.gemini_analyzer import analyze_with_gemini
from modules.risk_scoring import calculate_fraud_score
from modules.ui_theme import apply_theme, app_header, section_header, sidebar_navigation, footer, risk_badge, get_risk_color
import folium
from streamlit_folium import st_folium

load_dotenv()

st.set_page_config(page_title="MailTrace AI", layout="wide", initial_sidebar_state="expanded")
apply_theme()
sidebar_navigation()

app_header()

uploaded_file = st.file_uploader("Upload an .eml file", type=["eml"])

if uploaded_file is None:
    st.markdown("""
        <div style="display: flex; gap: 1rem; margin-top: 1rem; margin-bottom: 2rem; flex-wrap: wrap;">
            <div class="soc-card card-cyan" style="flex: 1; min-width: 220px; margin-bottom: 0;">
                <h4>1. Upload Email</h4>
                <p>Provide a raw .eml file to begin analysis.</p>
            </div>
            <div class="soc-card card-blue" style="flex: 1; min-width: 220px; margin-bottom: 0;">
                <h4>2. Analyze Threat Signals</h4>
                <p>Automatically extract and verify forensic data.</p>
            </div>
            <div class="soc-card card-violet" style="flex: 1; min-width: 220px; margin-bottom: 0;">
                <h4>3. Review Forensic Report</h4>
                <p>Investigate indicators and save case files.</p>
            </div>
        </div>
        <div style="display: flex; gap: 0.5rem; justify-content: center; margin-bottom: 2rem; flex-wrap: wrap;">
            <span class="badge badge-none">Header Analysis</span>
            <span class="badge badge-none">AI Detection</span>
            <span class="badge badge-none">Origin Trace</span>
            <span class="badge badge-none">Reports</span>
        </div>
    """, unsafe_allow_html=True)

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
            section_header("Threat Assessment", "cyan")

            score = fraud_score["final_score"]
            risk_level = fraud_score["risk_level"]
            verdict = fraud_score["verdict"]


            st.markdown(f"### Final Fraud Score: <span class='score-display' style='color:{get_risk_color(risk_level)};'>{score} / 100</span>", unsafe_allow_html=True)

            corroboration_bonus = fraud_score.get("corroboration_bonus", 0)
            if corroboration_bonus > 0:
                st.markdown(f"<span title='Additional risk added only when strong offline and AI detections agree.'>**Cross-Signal Corroboration Bonus: <span style='color:var(--cyan-accent);'>+{corroboration_bonus}</span>**</span>", unsafe_allow_html=True)

            st.markdown(f"**Verdict:** {verdict} | **Risk Level:** {risk_badge(risk_level)} | **Confidence:** {fraud_score['confidence']} | **Scoring Version:** {fraud_score['scoring_version']}", unsafe_allow_html=True)

            # 1. Plain-language meaning
            st.markdown("### What this result means")

            summary_color = get_risk_color(risk_level)
            if risk_level == "Low":
                summary_desc = "No strong threat signals were detected."
                summary_action = "Continue normally, but verify unexpected requests before sharing sensitive information."
            elif risk_level == "Moderate":
                summary_desc = "Some suspicious signals require review."
                summary_action = "Verify the sender independently and avoid opening unexpected links or attachments."
            elif risk_level == "High":
                summary_desc = "Multiple strong threat signals were detected."
                summary_action = "Do not click links, open attachments, reply, or share credentials until the message is verified."
            else:
                summary_desc = "The message shows severe and corroborated threat indicators."
                summary_action = "Treat the email as potentially malicious. Isolate it and report it to your security team or email provider."

            st.markdown(f"""
            <div class="soc-card" style="border-left: 4px solid {summary_color}; margin-bottom: 1rem;">
                <p><strong>{summary_desc}</strong></p>
                <p>Action: {summary_action}</p>
                <small>This is an investigative assessment, not a guarantee that the sender is malicious or legitimate.</small>
            </div>
            """, unsafe_allow_html=True)

            # 2. Add "Why was this score given?"
            st.markdown("### Why was this score given?")

            if fraud_score["top_reasons"]:
                displayed_reasons = fraud_score["top_reasons"][:3]
                for r in displayed_reasons:
                    st.write(f"- {r}")
                with st.expander("View technical scoring reasons"):
                    for r in fraud_score["top_reasons"]:
                        st.write(f"- {r}")
            else:
                st.write("No major forensic anomalies contributed to this score.")
                with st.expander("View technical scoring reasons"):
                    st.write("No significant risk reasons detected.")

            c1, c2, c3, c4 = st.columns(4)
            c_scores = fraud_score["component_scores"]
            with c1:
                st.markdown(f'<div class="component-card accent-blue" title="Checks sender-domain consistency and reported SPF, DKIM, and DMARC results."><div class="component-title">Header & Auth</div><div class="component-score">{c_scores["header_risk"]} / 35</div></div>', unsafe_allow_html=True)
            with c2:
                st.markdown(f'<div class="component-card accent-amber" title="Looks for suspicious wording, impersonation, urgency, credential requests, and business-email-compromise patterns."><div class="component-title">Content & BEC</div><div class="component-score">{c_scores["content_risk"]} / 25</div></div>', unsafe_allow_html=True)
            with c3:
                st.markdown(f'<div class="component-card accent-teal" title="Reviews the probable email-delivery infrastructure. It does not identify a person’s physical location."><div class="component-title">Infrastructure</div><div class="component-score">{c_scores["infrastructure_risk"]} / 20</div></div>', unsafe_allow_html=True)
            with c4:
                st.markdown(f'<div class="component-card accent-violet" title="Examines links and domain-related signals for suspicious characteristics."><div class="component-title">URL, Domain & Identity</div><div class="component-score">{c_scores["domain_risk"]} / 20</div></div>', unsafe_allow_html=True)

            # (Original Top Reasons block replaced with new design)
            if fraud_score["unavailable_sources"]:
                st.write("**Unavailable Optional Sources (Not treated as failures):** " + ", ".join(fraud_score["unavailable_sources"]))

            st.markdown("---")

            section_header("Case Management", "indigo")
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
            section_header("Basic Information", "cyan")
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
                st.text_input("Relay Hops", value=str(len(parsed_data.get("received", []))), disabled=True, help="One mail server that handled the message during delivery.")
                st.text_input("Attachments", value=str(len(parsed_data.get("attachments", []))), disabled=True)

            # Header Forensics
            section_header("Header Forensics", "blue")

            # Auth Results Statuses
            st.markdown("**Reported status - not independently verified**")
            auth = analysis["reported_auth_statuses"]

            c1, c2, c3 = st.columns(3)
            with c1:
                st.markdown(f"<div class='soc-card' style='text-align:center;' title='Checks whether the sending server was permitted to send mail for the domain.'><h4>SPF</h4><div style='margin-top:10px;'>{risk_badge(auth['spf'].upper())}</div></div>", unsafe_allow_html=True)
            with c2:
                st.markdown(f"<div class='soc-card' style='text-align:center;' title='Checks whether the message carries a valid domain signature.'><h4>DKIM</h4><div style='margin-top:10px;'>{risk_badge(auth['dkim'].upper())}</div></div>", unsafe_allow_html=True)
            with c3:
                st.markdown(f"<div class='soc-card' style='text-align:center;' title='Shows the domain’s policy and alignment result.'><h4>DMARC</h4><div style='margin-top:10px;'>{risk_badge(auth['dmarc'].upper())}</div></div>", unsafe_allow_html=True)

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
            section_header("Email Route Trace", "teal")
            if relay_analysis.get("probable_origin_ip"):
                st.markdown("<h3 title='The earliest reliable public server found in the delivery path—not the sender’s physical location.'>Probable infrastructure origin</h3>", unsafe_allow_html=True)
                st.info(f"**IP:** {relay_analysis['probable_origin_ip']}  \n**Confidence:** {relay_analysis['origin_confidence'].upper()}  \n**Explanation:** {relay_analysis['confidence_explanation']}")

                if os.getenv("ENABLE_GEOLOCATION", "true").lower() != "false":
                    if st.button("Check infrastructure location"):
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
                                m = folium.Map(location=[loc["lat"], loc["lon"]], zoom_start=10, tiles="CartoDB dark_matter")
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
                st.markdown(f"<div class='soc-card'><strong>Hop {i+1}</strong><br><br><span class='soc-wrap'>{html.escape(hop)}</span></div>", unsafe_allow_html=True)

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
            section_header("Sender Domain Intelligence", "violet")
            sender_domain = domains.get("from_domain")
            if analysis["extracted_domains"].get("from_domain"):
                if st.button("Check sender domain details"):
                    with st.spinner(f"Analyzing {analysis['extracted_domains']['from_domain']}..."):
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
            section_header("Content Threat Analysis", "amber")

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
                st.markdown("<h3 title='A link intentionally made non-clickable for safe investigation.'>Extracted URLs (Defanged)</h3>", unsafe_allow_html=True)
                st.info("URLs have been defanged for safety and are not clickable.")
                for url in content_analysis["defanged_urls"]:
                    st.code(url, language="text")

            # AI Threat Analysis
            section_header("AI Threat Analysis", "purple")
            gemini_key = f"gemini_{email_hash}"
            gemini_lock_key = f"gemini_lock_{email_hash}"
            gemini_cooldown_key = f"gemini_cooldown_{email_hash}"

            for k in ["gemini_attempts", "gemini_successes", "gemini_failures"]:
                if k not in st.session_state:
                    st.session_state[k] = 0

            is_running = st.session_state.get(gemini_lock_key, False)
            has_result = gemini_key in st.session_state
            g_res = st.session_state.get(gemini_key, {})
            is_failed = has_result and not g_res.get("available")

            btn_label = "Try AI analysis again" if is_failed else "Run optional AI content analysis"

            if not has_result or is_failed:
                col1, col2 = st.columns([1, 2])
                with col1:
                    btn_disabled = is_running
                    if st.button(btn_label, disabled=btn_disabled, key=f"btn_{email_hash}"):
                        now = time.monotonic()
                        cooldown_end = st.session_state.get(gemini_cooldown_key, 0) + 15
                        if is_failed and now < cooldown_end:
                            st.toast(f"Please wait {int(cooldown_end - now)}s before retrying.")
                        else:
                            st.session_state[gemini_lock_key] = True
                            st.rerun()

                with col2:
                    if is_failed:
                        st.write("AI result unavailable")
                        st.caption("Retrying uses another Gemini request.")
                    else:
                        st.caption("Uses one Gemini request. Offline forensic results remain available without it.")

                st.caption(f"This session: {st.session_state.gemini_attempts} attempted • {st.session_state.gemini_successes} successful")

                if is_running:
                    with st.spinner("AI analysis in progress..."):
                        try:
                            st.session_state.gemini_attempts += 1
                            subject = parsed_data.get("subject", "")
                            sanitized_body = parsed_data.get("analysis_text", "")
                            res = analyze_with_gemini(subject, sanitized_body)

                            if res.get("available"):
                                st.session_state.gemini_successes += 1
                                st.session_state[gemini_key] = res
                            else:
                                st.session_state.gemini_failures += 1
                                st.session_state[gemini_cooldown_key] = time.monotonic()
                                st.session_state[gemini_key] = res
                                err_msg = str(res.get("error", ""))
                                if "503" in err_msg:
                                    st.toast("Gemini is temporarily busy. No AI result was returned. Your offline forensic assessment is still available.")
                                elif "429" in err_msg:
                                    st.toast("Gemini’s free request limit is currently unavailable or has been reached. Try again later. Offline forensic results are unaffected.")
                                elif "404" in err_msg:
                                    st.toast("The configured Gemini model is unavailable. The application owner must update the model setting.")
                                elif "timeout" in err_msg.lower():
                                    st.toast("Gemini could not be reached. Check your connection and try again later.")
                                else:
                                    st.toast("AI analysis could not be completed. Offline forensic results remain available.")
                        finally:
                            st.session_state[gemini_lock_key] = False
                            st.rerun()

            if has_result:
                if is_failed:
                    with st.expander("View technical error details"):
                        st.code(g_res.get("error", "Unknown error"), language="text")
                else:
                    st.metric(label="Gemini content-risk score (Not a final fraud score)", value=f"{g_res.get('nlp_risk_score', 0)} / 100", help="AI assessment of message content only. It is not the final fraud score.")
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
            section_header("Message Body", "cyan")
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
                section_header("Attachments Metadata", "cyan")
                for att in parsed_data["attachments"]:
                    st.write(f"- **Filename:** {att['filename']} | **Type:** {att['content_type']} | **Size:** {att['size']} bytes")

            # Show any defects if present
            if parsed_data.get("defects"):
                with st.expander("Parser Defects (Warnings)"):
                    for d in parsed_data["defects"]:
                        st.warning(d)

footer()
