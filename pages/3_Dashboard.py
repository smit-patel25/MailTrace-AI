import streamlit as st
import pandas as pd
import sqlite3
import os
import plotly.express as px
from modules.ui_theme import apply_theme, sidebar_header, footer, risk_badge

st.set_page_config(page_title="Dashboard - MailTrace AI", layout="wide")
apply_theme()
sidebar_header()

st.title("MailTrace Security Overview")

# Use data/mailtrace.db if exists, otherwise fallback to our local test db database.sqlite3
db_path = os.getenv("DB_PATH", "data/mailtrace.db")
if not os.path.exists(db_path) and os.path.exists("database.sqlite3"):
    db_path = "database.sqlite3"

if not os.path.exists(db_path):
    st.info("The database is currently empty. Analyze and save some cases to view the dashboard.")
else:
    conn = sqlite3.connect(db_path)
    
    try:
        cases_df = pd.read_sql_query("SELECT case_id, created_at, subject, sender_domain, fraud_score, risk_level FROM cases", conn)
        campaigns_df = pd.read_sql_query("SELECT campaign_id FROM campaigns", conn)
    except sqlite3.OperationalError:
        cases_df = pd.DataFrame()
        campaigns_df = pd.DataFrame()
        
    conn.close()
    
    if cases_df.empty:
        st.info("No cases found in the database. Analyze and save some cases to populate the dashboard.")
    else:
        total_cases = len(cases_df)
        high_critical = len(cases_df[cases_df['risk_level'].isin(['High', 'Critical'])])
        total_campaigns = len(campaigns_df) if not campaigns_df.empty else 0
        avg_score = cases_df['fraud_score'].mean()
        
        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total Cases", total_cases)
        col2.metric("High/Critical Cases", high_critical)
        col3.metric("Detected Campaigns", total_campaigns)
        col4.metric("Avg Fraud Score", f"{avg_score:.1f}")
        
        st.markdown("---")
        
        c1, c2 = st.columns(2)
        
        color_map = {"Low": "green", "Moderate": "#ffbf00", "High": "orange", "Critical": "red"}
        
        with c1:
            st.subheader("Risk Level Distribution")
            risk_counts = cases_df['risk_level'].value_counts().reset_index()
            risk_counts.columns = ['Risk Level', 'Count']
            fig_risk = px.pie(risk_counts, values='Count', names='Risk Level', 
                              color='Risk Level', color_discrete_map=color_map, hole=0.4)
            st.plotly_chart(fig_risk, use_container_width=True)
            
        with c2:
            st.subheader("Fraud Score Distribution")
            fig_score = px.histogram(cases_df, x='fraud_score', nbins=20, 
                                     color_discrete_sequence=['#4287f5'])
            fig_score.update_layout(xaxis_title="Fraud Score", yaxis_title="Count")
            st.plotly_chart(fig_score, use_container_width=True)
            
        st.markdown("---")
        
        c3, c4 = st.columns(2)
        with c3:
            st.subheader("Top Sender Domains")
            top_domains = cases_df['sender_domain'].value_counts().head(5).reset_index()
            top_domains.columns = ['Domain', 'Count']
            st.dataframe(top_domains, hide_index=True, use_container_width=True)
            
        with c4:
            st.subheader("Recent Cases")
            recent_cases = cases_df.sort_values(by='created_at', ascending=False).head(5)
            st.dataframe(recent_cases, hide_index=True, use_container_width=True)

footer()
