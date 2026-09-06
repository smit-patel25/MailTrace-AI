import streamlit as st
import pandas as pd
import plotly.express as px
from modules.ui_theme import apply_theme, app_header, sidebar_navigation, footer, apply_chart_theme
from modules.session_case_store import get_dashboard_aggregates

st.set_page_config(page_title="Dashboard - MailTrace AI", layout="wide", initial_sidebar_state="expanded")
apply_theme()
sidebar_navigation()

app_header(title="MailTrace Security Overview", subtitle="System-wide threat metrics and trends", status="Dashboard")
st.info("Privacy mode: Cases are stored only for your current session and are automatically cleared when the session ends.")

agg = get_dashboard_aggregates()

if agg["total_cases"] == 0:
    st.info("No cases found in the current session. Analyze and save some cases to populate the dashboard.")
else:
    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Total Cases", agg["total_cases"])
    col2.metric("High/Critical Cases", agg["high_critical"])
    col3.metric("Detected Campaigns", agg["total_campaigns"])
    col4.metric("Avg Fraud Score", f"{agg['avg_score']:.1f}")

    st.markdown("---")

    c1, c2 = st.columns(2)

    color_map = {"Low": "#14B8A6", "Moderate": "#F59E0B", "High": "#F87171", "Critical": "#EF4444"}

    with c1:
        st.subheader("Risk Level Distribution")
        risk_counts_df = pd.DataFrame(agg["risk_counts"])
        if not risk_counts_df.empty:
            fig_risk = px.pie(risk_counts_df, values='Count', names='Risk Level',
                              color='Risk Level', color_discrete_map=color_map, hole=0.4)
            fig_risk = apply_chart_theme(fig_risk)
            st.plotly_chart(fig_risk, use_container_width=True)
        else:
            st.write("No risk data available.")

    with c2:
        st.subheader("Fraud Score Distribution")
        # We need all cases to plot a histogram of scores
        from modules.session_case_store import get_cases_for_correlation
        cases = get_cases_for_correlation()
        cases_df = pd.DataFrame(cases)
        if not cases_df.empty and 'fraud_score' in cases_df.columns:
            fig_score = px.histogram(cases_df, x='fraud_score', nbins=20,
                                     color_discrete_sequence=['#00E5FF'])
            fig_score.update_layout(xaxis_title="Fraud Score", yaxis_title="Count")
            fig_score = apply_chart_theme(fig_score)
            st.plotly_chart(fig_score, use_container_width=True)
        else:
            st.write("No score data available.")

    st.markdown("---")

    c3, c4 = st.columns(2)
    with c3:
        st.subheader("Top Sender Domains")
        top_domains_df = pd.DataFrame(agg["top_domains"])
        if not top_domains_df.empty:
            st.dataframe(top_domains_df, hide_index=True, use_container_width=True)
        else:
            st.write("No domain data available.")

    with c4:
        st.subheader("Recent Cases")
        recent_cases_df = pd.DataFrame(agg["recent_cases"])
        if not recent_cases_df.empty:
            st.dataframe(recent_cases_df, hide_index=True, use_container_width=True)
        else:
            st.write("No recent cases available.")

footer()
