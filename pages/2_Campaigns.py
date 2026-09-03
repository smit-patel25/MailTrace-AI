import streamlit as st
import os
import json
from modules.campaign_correlator import list_campaigns, get_campaign_cases
from modules.ui_theme import apply_theme, sidebar_header, footer, risk_badge

st.set_page_config(page_title="Campaigns - MailTrace AI", layout="wide")
apply_theme()
sidebar_header()

st.title("Campaign Intelligence")
st.warning("Note: Correlation indicates likely shared infrastructure, not proof of a shared attacker.")

db_path = os.getenv("DB_PATH", "database.sqlite3")
campaigns = list_campaigns(db_path)

if not campaigns:
    st.info("No active campaigns detected.")
else:
    st.metric("Total Campaigns", len(campaigns))
    
    st.subheader("Active Campaigns")
    for camp in campaigns:
        with st.expander(f"{camp['campaign_id']} ({camp['case_count']} cases) - Confidence: {camp['correlation_confidence'].upper()}"):
            st.write(f"**Created At:** {camp['created_at']}")
            st.write(f"**Confidence:** {camp['correlation_confidence'].title()}")
            st.write("**Matched Indicators:**")
            for ind in camp['matched_indicators']:
                st.write(f"- {ind}")
            
            if st.button(f"View {camp['case_count']} Cases", key=camp['campaign_id']):
                st.session_state["view_campaign"] = camp['campaign_id']

    if "view_campaign" in st.session_state:
        selected_id = st.session_state["view_campaign"]
        st.markdown("---")
        st.subheader(f"Cases for {selected_id}")
        c_cases = get_campaign_cases(db_path, selected_id)
        
        cases_df = []
        for c in c_cases:
            cases_df.append({
                "Case ID": c["case_id"],
                "Filename": c["filename"],
                "Score": c["fraud_score"],
                "Risk": c["risk_level"],
                "Subject": c["subject"],
                "Sender Domain": c["sender_domain"]
            })
        
        st.dataframe(cases_df, hide_index=True, use_container_width=True)

footer()
