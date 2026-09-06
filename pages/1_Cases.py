import streamlit as st
from modules.session_case_store import get_case, list_cases, delete_case
from modules.report_generator import generate_json_report, generate_html_report, generate_pdf_report
from modules.ui_theme import apply_theme, app_header, sidebar_navigation, footer

st.set_page_config(page_title="Cases - MailTrace AI", layout="wide", initial_sidebar_state="expanded")
apply_theme()
sidebar_navigation()

app_header(title="Case Management", subtitle="View and manage saved forensic cases", status="Cases")

st.info("Privacy mode: Cases are stored only for your current session and are automatically cleared when the session ends.")

search_query = st.text_input("Search Cases (Subject, Sender, ID)")
risk_filter = st.selectbox("Filter by Risk Level", ["All", "Low", "Moderate", "High", "Critical"])

r_filter = risk_filter if risk_filter != "All" else None

cases = list_cases(search=search_query, risk_level=r_filter)

if not cases:
    st.info("No cases found matching your criteria.")
else:
    df_cases = []
    for c in cases:
        df_cases.append({
            "Case ID": c["case_id"],
            "Created At": c["created_at"],
            "Subject": c["subject"],
            "Sender": c["sender_address"],
            "Risk Level": c["risk_level"],
            "Score": c["fraud_score"],
            "Campaign": c.get("campaign_id", "")
        })
    st.dataframe(df_cases, use_container_width=True)

    st.markdown("---")
    st.subheader("Case Details")
    selected_id = st.selectbox("Select a Case ID to view details", [c["case_id"] for c in cases])

    if selected_id:
        case_data = get_case(selected_id)
        if not case_data:
            st.error("Case data is unavailable or corrupted.")
        else:
            if st.button("Delete Case"):
                delete_case(selected_id)
                st.success("Case deleted.")
                st.rerun()

            st.write(f"**Filename:** {case_data.get('filename')}")
            st.write(f"**Origin IP:** {case_data.get('probable_origin_ip')}")
            st.write(f"**Verdict:** {case_data.get('verdict')}")

            st.markdown("### Download Forensic Report")
            c1, c2, c3 = st.columns(3)

            with c1:
                json_bytes = generate_json_report(case_data)
                st.download_button(
                    label="Download JSON Report",
                    data=json_bytes,
                    file_name=f"{selected_id}-report.json",
                    mime="application/json"
                )

            with c2:
                html_bytes = generate_html_report(case_data)
                st.download_button(
                    label="Download HTML Report",
                    data=html_bytes,
                    file_name=f"{selected_id}-report.html",
                    mime="text/html"
                )

            with c3:
                pdf_bytes = generate_pdf_report(case_data)
                st.download_button(
                    label="Download PDF Report",
                    data=pdf_bytes,
                    file_name=f"{selected_id}-report.pdf",
                    mime="application/pdf"
                )

footer()
