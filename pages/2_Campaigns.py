import streamlit as st
from modules.campaign_correlator import list_campaigns, get_campaign_cases
from modules.ui_theme import apply_theme, app_header, sidebar_navigation, footer, apply_chart_theme
from modules.ioc_relationship import (
    build_ioc_graph,
    generate_fallback_table,
    render_ioc_graph,
)
from modules.session_case_store import get_cases_for_correlation

st.set_page_config(page_title="Campaigns - MailTrace AI", layout="wide", initial_sidebar_state="expanded")
apply_theme()
sidebar_navigation()

app_header(title="Campaign Intelligence", subtitle="Correlate cases and track attacker infrastructure", status="Campaigns")
st.warning("Note: Correlation indicates likely shared infrastructure, not proof of a shared attacker.")

st.info("Privacy mode: Cases are stored only for your current session and are automatically cleared when the session ends.")

st.markdown("---")
st.subheader("IOC Relationship Explorer")
cases = get_cases_for_correlation()
if not cases:
    st.info("No cases available to map relationships.")
else:
    graph_data = build_ioc_graph(cases)
    if graph_data.get("truncated"):
        st.warning("Graph truncated to 100 nodes / 200 edges for performance.")

    fig = render_ioc_graph(graph_data)
    fig = apply_chart_theme(fig)
    st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    st.caption("Relationships indicate shared technical artifacts, not proof of common ownership or attribution to a specific person.")

    with st.expander("Accessible Relationship Data"):
        fallback = generate_fallback_table(graph_data)
        if fallback:
            st.dataframe(fallback, use_container_width=True, hide_index=True)
        else:
            st.write("No indicators to display.")

st.markdown("---")

campaigns = list_campaigns()

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
        c_cases = get_campaign_cases(selected_id)

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
