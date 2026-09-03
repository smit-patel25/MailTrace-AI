import streamlit as st
import html

def apply_theme():
    st.markdown("""
        <style>
        /* Base Colors */
        :root {
            --bg-color: #07111F;
            --card-bg: #0D1B2A;
            --border-color: #1F3449;
            --cyan-accent: #21D4FD;
            --green: #2ECC71;
            --amber: #F5A524;
            --orange: #FF8C42;
            --red: #FF4D6D;
            --main-text: #E6EDF3;
            --secondary-text: #8FA3B8;
        }
        
        /* App Background */
        .stApp {
            background-color: var(--bg-color);
            color: var(--main-text);
        }
        
        /* Sidebar */
        [data-testid="stSidebar"] {
            background-color: var(--card-bg) !important;
        }
        
        /* Text */
        h1, h2, h3, h4, h5, h6 {
            color: var(--main-text) !important;
            font-weight: 600 !important;
        }
        p, span, label {
            color: var(--secondary-text);
        }
        
        /* Markdown rendering inside divs */
        div[data-testid="stMarkdownContainer"] p {
            color: var(--secondary-text) !important;
        }
        
        /* Cards */
        .soc-card {
            background-color: var(--card-bg);
            border: 1px solid var(--border-color);
            border-radius: 8px;
            padding: 16px;
            margin-bottom: 16px;
        }
        
        /* Word wrapping */
        .soc-wrap {
            word-break: break-all;
            white-space: pre-wrap;
        }
        
        /* Badges */
        .badge {
            padding: 4px 8px;
            border-radius: 4px;
            font-weight: bold;
            font-size: 0.85em;
            display: inline-block;
        }
        .badge-low { background-color: rgba(46, 204, 113, 0.2); color: var(--green); border: 1px solid var(--green); }
        .badge-moderate { background-color: rgba(245, 165, 36, 0.2); color: var(--amber); border: 1px solid var(--amber); }
        .badge-high { background-color: rgba(255, 140, 66, 0.2); color: var(--orange); border: 1px solid var(--orange); }
        .badge-critical { background-color: rgba(255, 77, 109, 0.2); color: var(--red); border: 1px solid var(--red); }
        .badge-none { background-color: rgba(143, 163, 184, 0.2); color: var(--secondary-text); border: 1px solid var(--secondary-text); }
        
        /* Buttons */
        .stButton>button {
            background-color: transparent !important;
            border: 1px solid var(--cyan-accent) !important;
            color: var(--cyan-accent) !important;
            border-radius: 4px !important;
            transition: all 0.2s ease;
        }
        .stButton>button:hover {
            background-color: rgba(33, 212, 253, 0.1) !important;
            color: #fff !important;
        }
        
        /* Footer */
        .soc-footer {
            margin-top: 40px;
            padding-top: 20px;
            border-top: 1px solid var(--border-color);
            font-size: 0.8em;
            text-align: center;
            color: var(--secondary-text);
        }
        
        /* Metrics */
        [data-testid="stMetricValue"] {
            color: var(--main-text) !important;
        }
        [data-testid="stMetricLabel"] {
            color: var(--secondary-text) !important;
        }
        
        </style>
    """, unsafe_allow_html=True)

def sidebar_header():
    st.sidebar.markdown("""
        <div style="margin-bottom: 20px;">
            <h2 style="margin-bottom: 0px; color: #21D4FD !important;">MailTrace AI</h2>
            <div style="font-size: 0.9em; color: #8FA3B8;">Email Forensic Intelligence</div>
        </div>
    """, unsafe_allow_html=True)

def footer():
    st.markdown("""
        <div class="soc-footer">
            Disclaimer: Geolocation represents estimated infrastructure location. 
            Authentication header values may be reported rather than independently verified. 
            Campaign correlation is not proof of attacker identity. 
            Assessment is for investigative support only. Data provided by OpenStreetMap where applicable.
        </div>
    """, unsafe_allow_html=True)

def get_badge_class(level_or_status):
    val = str(level_or_status).lower()
    if val in ['low', 'pass', 'neutral', 'info', 'aligned']: return 'badge-low'
    if val in ['moderate']: return 'badge-moderate'
    if val in ['high', 'softfail', 'mismatched']: return 'badge-high'
    if val in ['critical', 'fail']: return 'badge-critical'
    return 'badge-none'

def risk_badge(text):
    cls = get_badge_class(text)
    return f'<span class="badge {cls}">{html.escape(str(text))}</span>'
