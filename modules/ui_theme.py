"""
modules/ui_theme.py
MailTrace AI — single source of truth for all theme CSS and UI helpers.
Permanent Dark Forensic Interface.
"""
import streamlit as st
import html as _html

# ---------------------------------------------------------------------------
# Theme CSS injection — single authoritative block
# ---------------------------------------------------------------------------

def apply_theme():
    """Inject the complete application CSS. Call after st.set_page_config()."""
    palette = """
        --app-bg: #050E17;
        --surface-primary: #0B1928;
        --surface-secondary: #101F30;
        --surface-elevated: #152638;
        --surface-hover: #1A2D42;
        --text-primary: #F1F5F9;
        --text-secondary: #CBD5E1;
        --text-muted: #94A3B8;
        --border-primary: #334155;
        --border-hover: #4B6B88;
        --sidebar-bg: #0B1928;
        --sidebar-text: #F1F5F9;
        --nav-selected-bg: #263548;
        --nav-selected-text: #FFFFFF;
        --accent-primary: #19C3E6;
        --accent-blue: #4C8DFF;
        --accent-purple: #A678FF;
        --success: #2DBE8C;
        --warning: #F0B44D;
        --danger: #F97066;
        --focus-ring: #38BDF8;
        --shadow-soft: rgba(0, 0, 0, 0.20);
        --shadow-raised: rgba(0, 0, 0, 0.32);

        /* Map old accent names to new or existing variables for backwards compatibility if used elsewhere */
        --accent-cyan:   var(--accent-primary);
        --accent-teal:   var(--success);
        --accent-violet: var(--accent-purple);
        --accent-amber:  var(--warning);
        --accent-indigo: var(--accent-blue);
        --accent-rose:   #E11D48;

        --input-bg:            #101F30;
        --input-bg-disabled:   #101F30;
        --input-text:          #F1F5F9;
        --input-text-disabled: #CBD5E1;
        --input-placeholder:   #94A3B8;
        --input-border:        #334155;
        --input-border-focus:  #19C3E6;

        --code-bg:   #152638;
        --code-text: #D6E4FF;

        --card-bg:      #101F30;
        --card-heading: #BFDBFE;
        --card-body:    #F1F5F9;

        --table-header-bg:   #152638;
        --table-header-text: #F1F5F9;
        --table-body-bg:     #101F30;
        --table-body-text:   #CBD5E1;
        --table-border:      #334155;
        --table-row-hover:   #1A2D42;
    """

    st.markdown(f"""
        <style>
        /* ================================================================
           SECTION A — PALETTE & TOKENS
           ================================================================ */
        :root {{
            {palette}

            /* Derived / always-same */
            --gradient-primary: linear-gradient(135deg, var(--accent-primary) 0%, var(--accent-purple) 100%);

            /* Structural */
            --space-xs:   0.25rem;
            --space-sm:   0.5rem;
            --space-md:   1rem;
            --space-lg:   1.5rem;
            --space-xl:   2rem;

            --radius-sm:   0.4rem;
            --radius-md:   0.5rem;
            --radius-lg:   0.65rem;
            --radius-pill: 999px;

            --content-max-width: 1200px;

            --card-padding:    1.35rem 1.65rem;
            --card-padding-sm: 0.85rem 1rem;
            --input-pad-x:     1rem;
            --input-pad-y:     0.7rem;
            --cell-pad-x:      0.75rem;
            --cell-pad-y:      0.65rem;
            --header-padding:  1.5rem;

            /* Motion */
            --motion-fast:   140ms;
            --motion-normal: 190ms;
            --motion-slow:   240ms;
            --motion-ease:   cubic-bezier(0.2, 0.8, 0.2, 1);
        }}

        /* ================================================================
           SECTION B — STRUCTURAL & BASE
           ================================================================ */

        html {{ scrollbar-gutter: stable; }}

        [data-testid="stAppViewContainer"],
        [data-testid="stAppViewContainer"] *,
        [data-testid="stSidebar"],
        [data-testid="stSidebar"] * {{
            box-sizing: border-box;
            transition:
                background-color var(--motion-fast) var(--motion-ease),
                border-color     var(--motion-fast) var(--motion-ease),
                color            var(--motion-fast) var(--motion-ease),
                box-shadow       var(--motion-fast) var(--motion-ease),
                opacity          var(--motion-fast) var(--motion-ease);
        }}

        @media (prefers-reduced-motion: reduce) {{
            [data-testid="stAppViewContainer"] *,
            [data-testid="stSidebar"] * {{
                transition: none !important;
                animation:  none !important;
            }}
            .soc-card:hover,
            .component-card:hover,
            .stButton > button:hover,
            .stDownloadButton > button:hover {{
                transform: none !important;
            }}
        }}

        /* Removed toolbar/decoration rules to unhide sidebar controls */

        *:focus-visible {{
            outline:        2px solid var(--focus-ring) !important;
            outline-offset: 2px !important;
        }}

        html, body,
        [data-testid="stAppViewContainer"],
        [data-testid="stMain"] {{
            background-color: var(--app-bg) !important;
            color:            var(--text-primary) !important;
        }}
        [data-testid="stAppViewContainer"] {{
            background-image:
                radial-gradient(circle at 15% 50%, rgba(25, 195, 230, 0.02), transparent 25%),
                radial-gradient(circle at 85% 30%, rgba(166, 120, 255, 0.02), transparent 25%);
        }}
        /* Removed stHeader transparency to allow native controls */

        .block-container {{
            max-width:      var(--content-max-width) !important;
            padding-top:    3rem !important; /* Reduced top padding since toggle is gone */
            padding-bottom: var(--space-xl) !important;
        }}

        /* ── Sidebar ── */
        [data-testid="stSidebar"] {{
            background-color: var(--sidebar-bg) !important;
            border-right:     1px solid var(--border-primary) !important;
        }}
        [data-testid="stSidebarNav"] li a,
        [data-testid="stPageLink"] span,
        .stPageLink a,
        .stPageLink span {{
            color:         var(--sidebar-text) !important;
            border-radius: var(--radius-sm);
            padding:       0.45rem 0.75rem;
            display:       block;
            transition:    background-color var(--motion-fast) ease, color var(--motion-fast) ease !important;
        }}
        [data-testid="stSidebarNav"] li a[aria-current="page"],
        [data-testid="stPageLink"] a[aria-current="page"] {{
            background-color: var(--nav-selected-bg)   !important;
            color:            var(--nav-selected-text) !important;
            font-weight:      600 !important;
        }}
        @media (hover: hover) and (pointer: fine) {{
            [data-testid="stPageLink"] a:not([aria-current="page"]):hover,
            .stPageLink a:not([aria-current="page"]):hover,
            [data-testid="stPageLink"] a:not([aria-current="page"]):focus-visible,
            .stPageLink a:not([aria-current="page"]):focus-visible {{
                background-color: var(--surface-hover) !important;
                color:            var(--text-primary) !important;
                border-left:      3px solid var(--accent-primary) !important;
                padding-left:     calc(0.75rem - 3px); /* keep text aligned */
            }}
        }}

        /* ── Typography ── */
        h1, h2, h3, h4, h5, h6 {{
            color:         var(--text-primary) !important;
            font-weight:   600 !important;
            margin-bottom: var(--space-md) !important;
        }}
        div[data-testid="stMarkdownContainer"] p {{
            color:       var(--text-primary) !important;
            line-height: 1.6;
        }}
        caption, small {{
            color:     var(--text-muted) !important;
            font-size: 0.82rem !important;
        }}

        /* ================================================================
           APP HEADER BRANDING
           ================================================================ */
        .app-header-container {{
            display:flex;
            flex-direction:row;
            align-items:flex-start;
            gap:1rem;
            padding:var(--header-padding);
            margin:0;
            transition: border-color var(--motion-normal) ease;
        }}
        @media (hover: hover) and (pointer: fine) {{
            div:has(> .app-header-container):hover {{
                border-color: var(--border-hover) !important;
            }}
        }}
        .app-header-title {{
            background:              var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            font-size:   1.5rem;
            font-weight: 700;
            margin:      0;
            letter-spacing: 0.5px;
            line-height: 1.25;
        }}
        .app-header-subtitle {{
            color:       var(--text-primary);
            font-size:   1rem;
            font-weight: 500;
            margin:      0;
            line-height: 1.4;
        }}
        .app-header-status {{
            display:          inline-flex;
            align-items:      center;
            width:            fit-content;
            max-width:        100%;
            flex:             0 0 auto;
            align-self:       flex-start;
            white-space:      nowrap;
            background-color: rgba(25, 195, 230, 0.12);
            color:            var(--accent-primary);
            padding:          0.32rem 0.7rem;
            border-radius:    var(--radius-pill);
            font-size:        0.72rem;
            font-weight:      700;
            text-transform:   uppercase;
            letter-spacing:   0.6px;
            line-height:      1.1;
            margin-top:       0.45rem;
        }}

        /* ================================================================
           TABS
           ================================================================ */
        [data-testid="stTabs"] [aria-selected="true"] {{
            color:        var(--accent-primary) !important;
            border-color: var(--accent-primary) !important;
        }}
        [data-testid="stTabs"] [data-baseweb="tab-border"] {{
            background-color: var(--border-primary) !important;
        }}
        [data-testid="stTabs"] [role="tab"] {{
            color: var(--text-muted) !important;
        }}
        @media (hover: hover) and (pointer: fine) {{
            [data-testid="stTabs"] [role="tab"]:not([aria-selected="true"]):hover {{
                color: var(--text-primary) !important;
            }}
        }}

        /* ================================================================
           FORM CONTROLS
           ================================================================ */
        [data-baseweb="input"],
        [data-baseweb="textarea"] {{
            background-color: var(--input-bg)     !important;
            border-color:     var(--input-border) !important;
        }}
        [data-baseweb="input"] input,
        [data-baseweb="textarea"] textarea,
        [data-testid="stTextInput"] input,
        [data-testid="stTextArea"]  textarea,
        .stTextInput input,
        .stTextArea textarea {{
            background-color:  var(--input-bg)     !important;
            color:             var(--input-text)   !important;
            border-color:      var(--input-border) !important;
            border-radius:     var(--radius-md)    !important;
            padding:           var(--input-pad-y) var(--input-pad-x) !important;
            min-height:        3rem                !important;
            line-height:       1.45               !important;
            caret-color:       var(--accent-primary) !important;
        }}
        [data-baseweb="input"] input::placeholder,
        [data-baseweb="textarea"] textarea::placeholder,
        .stTextInput input::placeholder,
        .stTextArea textarea::placeholder {{
            color:   var(--input-placeholder) !important;
            opacity: 1 !important;
        }}
        [data-baseweb="input"]:focus-within,
        [data-baseweb="textarea"]:focus-within,
        .stTextInput input:focus,
        .stTextArea textarea:focus {{
            border-color: var(--input-border-focus) !important;
            box-shadow:   0 0 0 1px var(--input-border-focus) !important;
        }}
        [data-baseweb="input"] input:disabled,
        [data-baseweb="textarea"] textarea:disabled,
        .stTextInput input:disabled,
        .stTextArea textarea:disabled,
        [data-testid="stTextInput"] input[readonly],
        [data-testid="stTextArea"]  textarea[readonly],
        [aria-disabled="true"] input,
        [aria-disabled="true"] textarea {{
            background-color:        var(--input-bg-disabled)   !important;
            color:                   var(--text-secondary) !important;
            -webkit-text-fill-color: var(--text-secondary) !important;
            opacity:                 1   !important;
            cursor:                  default !important;
        }}
        .stSelectbox [data-baseweb="select"] > div:first-of-type,
        .stSelectbox [data-baseweb="select"] input {{
            background-color: var(--input-bg)     !important;
            color:            var(--input-text)   !important;
            border-color:     var(--input-border) !important;
        }}
        [data-baseweb="popover"] [data-baseweb="menu"] {{
            background-color: var(--surface-primary) !important;
            border:           1px solid var(--border-primary) !important;
        }}
        [data-baseweb="popover"] [role="option"] {{
            color: var(--text-primary) !important;
        }}
        [data-baseweb="popover"] [role="option"]:hover {{
            background-color: var(--surface-secondary) !important;
        }}

        /* ================================================================
           MESSAGE BODY TEXTAREA
           ================================================================ */
        [data-testid="stTextArea"] {{ background-color: transparent; }}
        [data-testid="stTextArea"] textarea {{
            background-color:        var(--input-bg)   !important;
            color:                   var(--input-text) !important;
            -webkit-text-fill-color: var(--input-text) !important;
            opacity:                 1       !important;
            padding:                 1rem   !important;
            line-height:             1.55   !important;
            font-size:               0.93rem !important;
            resize:                  vertical !important;
            overflow-x:              auto;
            white-space:             pre-wrap;
        }}
        [data-testid="stTextArea"] textarea:disabled {{
            background-color:        var(--input-bg-disabled)   !important;
            color:                   var(--text-secondary) !important;
            -webkit-text-fill-color: var(--text-secondary) !important;
            opacity:                 1 !important;
        }}

        /* ================================================================
           CODE BLOCKS & DEFANGED URLS
           ================================================================ */
        [data-testid="stCodeBlock"],
        [data-testid="stCodeBlock"] pre,
        .stCodeBlock,
        .stCodeBlock pre {{
            background-color: var(--code-bg)       !important;
            color:            var(--code-text)     !important;
            border:           1px solid var(--border-primary) !important;
            border-radius:    var(--radius-md)     !important;
            padding:          0.9rem 1rem          !important;
            line-height:      1.45                 !important;
            overflow-x:       auto                 !important;
            max-width:        100%                 !important;
        }}
        [data-testid="stCodeBlock"] code,
        .stCodeBlock code,
        pre code {{
            background-color: transparent !important;
            color:            var(--code-text) !important;
            font-size:        0.88rem !important;
            word-break:       break-all;
        }}
        [data-testid="stCodeBlock"] button {{
            background-color: var(--surface-elevated) !important;
            color:            var(--text-secondary)   !important;
            border:           1px solid var(--border-primary) !important;
        }}

        /* ================================================================
           PERMANENT DARK UPLOADER
           ================================================================ */
        /* Outer wrapper transparent to hold the label natively */
        [data-testid="stFileUploader"] {{
            background-color: transparent !important;
            padding:          0 !important;
        }}
        [data-testid="stFileUploader"] > label,
        [data-testid="stFileUploader"] > div > label {{
            color:         #F1F5F9 !important;
            margin-bottom: 0.55rem !important;
            line-height:   1.4    !important;
            display:       block  !important;
        }}
        /* Drop zone background overrides */
        [data-testid="stFileUploaderDropzone"],
        [data-testid="stFileUploaderDropzone"] section,
        [data-testid="stFileUploaderDropzone"] section > div,
        [data-testid="stFileUploaderDropzone"] > section {{
            background-color: #101F30 !important;
            color:            #F1F5F9 !important;
        }}
        [data-testid="stFileUploaderDropzone"] {{
            border:        1px solid #334155 !important;
            border-radius: 0.65rem !important;
            padding:       1rem !important;
            min-height:    5.25rem !important;
            transition:    border-color var(--motion-normal) ease, background-color var(--motion-normal) ease, box-shadow var(--motion-normal) ease !important;
        }}
        /* Hover micro-interactions */
        @media (hover: hover) and (pointer: fine) {{
            [data-testid="stFileUploaderDropzone"]:hover {{
                border-color:     var(--accent-primary) !important;
                background-color: rgba(25, 195, 230, 0.04) !important;
                box-shadow:       0 2px 8px var(--shadow-soft) !important;
            }}
        }}
        /* Drag active pseudo-state */
        [data-testid="stFileUploaderDropzone"]:has(div[data-baseweb="file-uploader"]:active) {{
            border-color:     var(--accent-primary) !important;
            background-color: rgba(25, 195, 230, 0.08) !important;
        }}

        [data-testid="stFileUploaderDropzoneInstructions"],
        [data-testid="stFileUploaderDropzoneInstructions"] span,
        [data-testid="stFileUploaderDropzoneInstructions"] div {{
            color: #F1F5F9 !important;
        }}
        [data-testid="stFileUploaderDropzone"] small,
        [data-testid="stFileUploader"] small,
        [data-testid="stFileUploaderDropzoneInstructions"] small {{
            color: #CBD5E1 !important;
        }}
        [data-testid="stFileUploader"] span {{
            color: #F1F5F9 !important;
        }}
        /* Buttons inside uploader */
        [data-testid="stFileUploader"] button,
        [data-testid="stFileUploaderDropzone"] button {{
            background-color: #0B1928 !important;
            color:            #F1F5F9 !important;
            border:           1px solid #334155 !important;
        }}
        [data-testid="stFileUploader"] button svg,
        [data-testid="stFileUploaderDropzone"] button svg {{
            fill: #F1F5F9 !important;
        }}
        /* Uploaded file card */
        [data-testid="stUploadedFile"],
        [data-testid="stFileUploaderFile"] {{
            background-color: #152638 !important;
            border:           1px solid #334155 !important;
            color:            #F1F5F9 !important;
            border-radius:    0.65rem !important;
        }}
        [data-testid="stUploadedFile"] svg,
        [data-testid="stFileUploaderFile"] svg {{
            fill: #F1F5F9 !important;
        }}

        /* ================================================================
           TABLES
           ================================================================ */
        .stDataFrame {{
            background-color: var(--surface-secondary) !important;
            border:           1px solid var(--border-primary) !important;
            border-radius:    var(--radius-md) !important;
            overflow:         hidden;
        }}
        table {{
            background-color: var(--table-body-bg) !important;
            border-collapse:  collapse !important;
            width:            100% !important;
        }}
        th {{
            background-color: var(--table-header-bg)   !important;
            color:            var(--table-header-text) !important;
            padding:          var(--cell-pad-y) var(--cell-pad-x) !important;
            border:           1px solid var(--table-border) !important;
            font-weight:      600;
            text-align:       left;
        }}
        td {{
            background-color: var(--table-body-bg)   !important;
            color:            var(--table-body-text) !important;
            padding:          var(--cell-pad-y) var(--cell-pad-x) !important;
            border:           1px solid var(--table-border) !important;
            max-width:        220px;
            overflow:         hidden;
            text-overflow:    ellipsis;
            white-space:      nowrap;
        }}
        tr:hover td {{
            background-color: var(--table-row-hover) !important;
        }}

        /* ================================================================
           CARDS — soc-card, component-card
           ================================================================ */
        .soc-card {{
            background-color: var(--card-bg) !important;
            border:           1px solid var(--border-primary) !important;
            border-left:      3px solid var(--border-primary) !important;
            border-radius:    var(--radius-lg) !important;
            padding:          var(--card-padding) !important;
            margin-bottom:    var(--space-lg) !important;
            box-shadow:       0 2px 4px var(--shadow-soft) !important;
        }}
        @media (hover: hover) and (pointer: fine) {{
            .soc-card:hover, .component-card:hover {{
                transform:    translateY(-2px) !important;
                box-shadow:   0 4px 12px var(--shadow-raised) !important;
                border-color: var(--border-hover) !important;
                transition:
                    transform    var(--motion-normal) var(--motion-ease),
                    box-shadow   var(--motion-normal) var(--motion-ease),
                    border-color var(--motion-normal) ease !important;
            }}
        }}
        .soc-card h4 {{
            color:      var(--card-heading) !important;
            margin-top: 0    !important;
            font-size:  1.1rem !important;
            line-height: 1.35 !important;
        }}
        .soc-card p {{
            color:         var(--card-body) !important;
            margin-bottom: 0    !important;
            font-size:     0.9rem !important;
            line-height:   1.5 !important;
        }}
        .card-cyan   {{ border-left-color: var(--accent-primary) !important; }}
        .card-blue   {{ border-left-color: var(--accent-blue)   !important; }}
        .card-teal   {{ border-left-color: var(--success)       !important; }}
        .card-violet {{ border-left-color: var(--accent-purple) !important; }}
        .card-amber  {{ border-left-color: var(--warning)       !important; }}
        .card-purple {{ border-left-color: var(--accent-purple) !important; }}
        .card-indigo {{ border-left-color: var(--accent-blue)   !important; }}

        /* Component score cards */
        .component-card {{
            background-color: var(--card-bg) !important;
            border:           1px solid var(--border-primary) !important;
            border-top:       3px solid var(--border-primary) !important;
            border-radius:    var(--radius-lg) !important;
            padding:          var(--card-padding-sm) !important;
            text-align:       center !important;
            height:           100% !important;
            box-shadow:       0 2px 4px var(--shadow-soft) !important;
        }}
        .component-card.accent-cyan   {{ border-top-color: var(--accent-primary) !important; }}
        .component-card.accent-amber  {{ border-top-color: var(--warning) !important; }}
        .component-card.accent-teal   {{ border-top-color: var(--success) !important; }}
        .component-card.accent-violet {{ border-top-color: var(--accent-purple) !important; }}
        .component-card.accent-blue   {{ border-top-color: var(--accent-blue) !important; }}
        .component-card.accent-rose   {{ border-top-color: var(--accent-rose) !important; }}

        .component-title {{
            color:          var(--text-muted) !important;
            font-size:      0.85rem !important;
            text-transform: uppercase !important;
            margin-bottom:  var(--space-sm) !important;
            line-height:    1.3 !important;
        }}
        .component-score {{
            font-size:   1.25rem !important;
            font-weight: 600 !important;
            color:       var(--text-primary) !important;
        }}

        /* ================================================================
           BUTTONS
           ================================================================ */
        .stButton > button,
        .stDownloadButton > button {{
            background-color: var(--surface-primary) !important;
            border:           1px solid var(--border-primary) !important;
            color:            var(--text-primary) !important;
            border-radius:    var(--radius-md) !important;
            padding:          0.5rem 1rem !important;
            font-weight:      500 !important;
        }}
        @media (hover: hover) and (pointer: fine) {{
            .stButton > button:hover,
            .stDownloadButton > button:hover {{
                border-color:     var(--accent-primary) !important;
                background-color: var(--surface-hover) !important;
                box-shadow:       0 2px 6px var(--shadow-soft) !important;
                transform:        translateY(-1px) !important;
                transition:
                    transform        var(--motion-fast) var(--motion-ease),
                    background-color var(--motion-fast) ease,
                    border-color     var(--motion-fast) ease,
                    box-shadow       var(--motion-fast) ease !important;
            }}
        }}
        .stButton > button:active,
        .stDownloadButton > button:active {{
            transform:  translateY(0) !important;
            box-shadow: none !important;
        }}

        /* ================================================================
           ONE-CLICK DEMO BUTTON INTERACTION ANIMATIONS (SCOPED ONLY)
           ================================================================ */

        /* Common base transition for scoped demo buttons */
        div.st-key-demo_legitimate button,
        [data-testid="stBaseButton-demo_legitimate"],
        div.st-key-demo_credential_phishing button,
        [data-testid="stBaseButton-demo_credential_phishing"],
        div.st-key-demo_executive_bec button,
        [data-testid="stBaseButton-demo_executive_bec"] {{
            transition: transform 200ms cubic-bezier(0.2, 0.8, 0.2, 1),
                        border-color 200ms ease,
                        box-shadow 200ms ease,
                        background-color 200ms ease !important;
        }}

        /* 1. Legitimate Email (Safe Cyan/Teal Accent) */
        @media (hover: hover) and (pointer: fine) {{
            div.st-key-demo_legitimate button:hover,
            [data-testid="stBaseButton-demo_legitimate"]:hover {{
                transform: translateY(-2px) !important;
                border-color: var(--accent-primary) !important;
                box-shadow: 0 4px 12px rgba(25, 195, 230, 0.25) !important;
                background-color: var(--surface-hover) !important;
            }}
        }}
        div.st-key-demo_legitimate button:active,
        [data-testid="stBaseButton-demo_legitimate"]:active {{
            transform: translateY(0) scale(0.98) !important;
            box-shadow: 0 1px 3px rgba(25, 195, 230, 0.15) !important;
        }}

        /* 2. Credential Phishing (Warning Amber/Red Accent) */
        @media (hover: hover) and (pointer: fine) {{
            div.st-key-demo_credential_phishing button:hover,
            [data-testid="stBaseButton-demo_credential_phishing"]:hover {{
                transform: translateY(-2px) !important;
                border-color: var(--danger) !important;
                box-shadow: 0 4px 12px rgba(249, 112, 102, 0.25) !important;
                background-color: var(--surface-hover) !important;
            }}
        }}
        div.st-key-demo_credential_phishing button:active,
        [data-testid="stBaseButton-demo_credential_phishing"]:active {{
            transform: translateY(0) scale(0.98) !important;
            box-shadow: 0 1px 3px rgba(249, 112, 102, 0.15) !important;
        }}

        /* 3. Executive BEC Scam (Professional Violet Accent) */
        @media (hover: hover) and (pointer: fine) {{
            div.st-key-demo_executive_bec button:hover,
            [data-testid="stBaseButton-demo_executive_bec"]:hover {{
                transform: translateY(-2px) !important;
                border-color: var(--accent-purple) !important;
                box-shadow: 0 4px 12px rgba(166, 120, 255, 0.25) !important;
                background-color: var(--surface-hover) !important;
            }}
        }}
        div.st-key-demo_executive_bec button:active,
        [data-testid="stBaseButton-demo_executive_bec"]:active {{
            transform: translateY(0) scale(0.98) !important;
            box-shadow: 0 1px 3px rgba(166, 120, 255, 0.15) !important;
        }}

        /* Accessibility: prefers-reduced-motion rule */
        @media (prefers-reduced-motion: reduce) {{
            div.st-key-demo_legitimate button,
            [data-testid="stBaseButton-demo_legitimate"],
            div.st-key-demo_credential_phishing button,
            [data-testid="stBaseButton-demo_credential_phishing"],
            div.st-key-demo_executive_bec button,
            [data-testid="stBaseButton-demo_executive_bec"] {{
                transition: none !important;
                transform: none !important;
            }}
            div.st-key-demo_legitimate button:hover,
            div.st-key-demo_credential_phishing button:hover,
            div.st-key-demo_executive_bec button:hover,
            div.st-key-demo_legitimate button:active,
            div.st-key-demo_credential_phishing button:active,
            div.st-key-demo_executive_bec button:active {{
                transform: none !important;
            }}
        }}

        /* ================================================================
           EXPANDERS
           ================================================================ */
        .streamlit-expanderHeader,
        [data-testid="stExpander"] summary {{
            background-color: var(--surface-primary) !important;
            border:           1px solid var(--border-primary) !important;
            border-radius:    var(--radius-md) !important;
            color:            var(--text-primary) !important;
            padding:          0.65rem 1rem !important;
        }}
        @media (hover: hover) and (pointer: fine) {{
            [data-testid="stExpander"] summary:hover {{
                background-color: var(--surface-hover) !important;
            }}
        }}
        [data-testid="stExpander"] {{
            border:        1px solid var(--border-primary) !important;
            border-radius: var(--radius-md) !important;
        }}

        /* ================================================================
           ALERTS & BADGES & METRICS
           ================================================================ */
        .stAlert, [data-testid="stAlert"] {{
            background-color: var(--surface-primary) !important;
            border:           1px solid var(--border-primary) !important;
            color:            var(--text-primary) !important;
        }}

        [data-testid="stMetricValue"] {{
            color:       var(--text-primary) !important;
            font-size:   1.8rem !important;
            font-weight: 700 !important;
        }}
        [data-testid="stMetricLabel"] {{
            color:          var(--text-muted) !important;
            font-size:      0.9rem !important;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}

        .badge {{
            padding:        4px 10px;
            border-radius:  var(--radius-pill);
            font-weight:    600;
            font-size:      0.8rem;
            display:        inline-flex;
            align-items:    center;
            width:          fit-content;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            line-height:    1.2;
            white-space:    nowrap;
        }}
        /* Hardcoded dark mode badge colors */
        .badge-low      {{ background-color: rgba(45,190,140,0.15);  color: #2DBE8C; border: 1px solid rgba(45,190,140,0.3);  }}
        .badge-moderate {{ background-color: rgba(240,180,77,0.15);  color: #F0B44D; border: 1px solid rgba(240,180,77,0.3);  }}
        .badge-high     {{ background-color: rgba(249,112,102,0.15); color: #F97066; border: 1px solid rgba(249,112,102,0.3); }}
        .badge-critical {{ background-color: rgba(249,112,102,0.15); color: #F97066; border: 1px solid rgba(249,112,102,0.3); }}
        .badge-none     {{ background-color: rgba(148,163,184,0.15); color: #94A3B8; border: 1px solid rgba(148,163,184,0.3); }}

        /* ================================================================
           SCORE DISPLAY
           ================================================================ */
        .score-display {{
            font-size:               2.5rem;
            font-weight:             800;
            background:              var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin:                  10px 0;
            display:                 inline-block;
        }}

        /* ================================================================
           FEATURE CHIPS
           ================================================================ */
        .feature-chip {{
            border: 1px solid var(--border-primary);
            border-radius: var(--radius-pill);
            padding: 0.2rem 0.6rem;
            font-size: 0.75rem;
            background-color: var(--surface-primary);
            color: var(--text-secondary);
        }}
        @media (hover: hover) and (pointer: fine) {{
            .feature-chip:hover {{
                border-color: var(--border-hover);
                background-color: var(--surface-hover);
            }}
        }}

        /* ================================================================
           FOOTER & HELPERS
           ================================================================ */
        .soc-footer {{
            margin-top:   var(--space-xl);
            padding-top:  var(--space-md);
            border-top:   1px solid var(--border-primary);
            font-size:    0.8rem;
            text-align:   center;
            color:        var(--text-muted);
            opacity:      0.7;
        }}
        .soc-wrap {{
            word-break: break-all;
            white-space: pre-wrap;
        }}

        /* ================================================================
           INITIAL ENTRANCE ANIMATION (Landing page only, staggered)
           ================================================================ */
        @keyframes cardIn {{
            from {{ opacity: 0.94; transform: translateY(3px); }}
            to   {{ opacity: 1;    transform: translateY(0); }}
        }}
        @media (prefers-reduced-motion: no-preference) {{
            div[data-testid="stVerticalBlock"] > div.element-container:nth-child(1) .app-header-container {{
                animation: cardIn var(--motion-slow) var(--motion-ease) both;
                animation-delay: 0ms;
            }}
            div[data-testid="stVerticalBlock"] > div.element-container:nth-child(2) .soc-card {{
                animation: cardIn var(--motion-slow) var(--motion-ease) both;
                animation-delay: 30ms;
            }}
            div[data-testid="stVerticalBlock"] > div.element-container:nth-child(3) .soc-card {{
                animation: cardIn var(--motion-slow) var(--motion-ease) both;
                animation-delay: 60ms;
            }}
            div[data-testid="stVerticalBlock"] > div.element-container:nth-child(4) .soc-card {{
                animation: cardIn var(--motion-slow) var(--motion-ease) both;
                animation-delay: 90ms;
            }}
        }}
        </style>
    """, unsafe_allow_html=True)


# ---------------------------------------------------------------------------
# Plotly helper
# ---------------------------------------------------------------------------

def style_plotly_figure(fig):
    """Apply the permanent Dark theme to a Plotly figure."""
    font_color, axis_color, grid_color = "#F1F5F9", "#94A3B8", "#334155"
    legend_color, title_color          = "#CBD5E1", "#F1F5F9"
    hoverlabel_bg, hoverlabel_fg, hoverlabel_bdr = "#152638", "#F1F5F9", "#334155"

    fig.update_layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color=font_color, size=13),
        title_font=dict(color=title_color, size=15),
        legend=dict(font=dict(color=legend_color), bgcolor="rgba(0,0,0,0)"),
        hoverlabel=dict(bgcolor=hoverlabel_bg, font_color=hoverlabel_fg, bordercolor=hoverlabel_bdr),
    )
    fig.update_xaxes(gridcolor=grid_color, linecolor=axis_color,
                     tickfont=dict(color=axis_color), title_font=dict(color=font_color),
                     zerolinecolor=grid_color)
    fig.update_yaxes(gridcolor=grid_color, linecolor=axis_color,
                     tickfont=dict(color=axis_color), title_font=dict(color=font_color),
                     zerolinecolor=grid_color)
    return fig


# Backward-compat alias
def apply_chart_theme(fig):
    return style_plotly_figure(fig)


# ---------------------------------------------------------------------------
# Page components
# ---------------------------------------------------------------------------

def app_header(
    title="MailTrace AI",
    subtitle="Email Threat Detection and Forensic Intelligence Platform",
    status="Forensic Intelligence Platform",
):
    svg_icon = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="32" height="32" viewBox="0 0 24 24"'
        ' fill="none" stroke="url(#hgrad)" stroke-width="1.5" stroke-linecap="round"'
        ' stroke-linejoin="round" style="margin-top:2px;flex-shrink:0;">'
        "<defs>"
        '<linearGradient id="hgrad" x1="0%" y1="0%" x2="100%" y2="100%">'
        '<stop offset="0%"   stop-color="var(--accent-primary)"/>'
        '<stop offset="100%" stop-color="var(--accent-purple)"/>'
        "</linearGradient>"
        "</defs>"
        '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>'
        '<path d="M4 7l8 5 8-5"/>'
        "</svg>"
    )
    with st.container(border=True):
        st.markdown(
            f"""
            <div class="app-header-container">
                {svg_icon}
                <div style="display:flex;flex-direction:column;align-items:flex-start;gap:0.2rem;min-width:0;">
                    <div class="app-header-title">{_html.escape(title)}</div>
                    <div class="app-header-subtitle">{_html.escape(subtitle)}</div>
                    <span class="app-header-status">{_html.escape(status)}</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    st.markdown("<div style='margin-bottom:var(--space-xl);'></div>", unsafe_allow_html=True)


def section_header(title: str, accent: str = "primary"):
    safe = _html.escape(title)
    st.markdown(
        f'<h2 style="border-bottom:2px solid var(--accent-{accent});'
        f'display:inline-block;padding-bottom:4px;margin-bottom:1rem;">{safe}</h2>',
        unsafe_allow_html=True,
    )


def sidebar_navigation():
    with st.sidebar:
        st.markdown(
            """
            <div style="margin-bottom:24px;padding-bottom:16px;border-bottom:1px solid var(--border-primary);">
                <h2 style="margin-bottom:4px;color:var(--accent-primary)!important;font-size:1.4rem;">MailTrace AI</h2>
                <div style="font-size:0.85rem;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px;">
                    Email Forensic Intelligence
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.page_link("app.py",               label="Analyze Email")
        st.page_link("pages/1_Cases.py",     label="Cases")
        st.page_link("pages/2_Campaigns.py", label="Campaigns")
        st.page_link("pages/3_Dashboard.py", label="Dashboard")


def footer():
    st.markdown(
        """
        <div class="soc-footer">
            Disclaimer: Geolocation represents estimated infrastructure location.
            Authentication header values may be reported rather than independently verified.
            Campaign correlation is not proof of attacker identity.
            Assessment is for investigative support only.
            Data provided by OpenStreetMap where applicable.
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Badge / risk helpers
# ---------------------------------------------------------------------------

def get_badge_class(level_or_status: str) -> str:
    val = str(level_or_status).lower()
    if val in {"low", "pass", "neutral", "info", "aligned"}:  return "badge-low"
    if val in {"moderate"}:                                    return "badge-moderate"
    if val in {"high", "softfail", "mismatched"}:             return "badge-high"
    if val in {"critical", "fail"}:                           return "badge-critical"
    return "badge-none"


def get_risk_color(level_or_status: str) -> str:
    val = str(level_or_status).lower()
    if val in {"low", "pass", "neutral", "info", "aligned"}:          return "var(--success)"
    if val in {"moderate"}:                                            return "var(--warning)"
    if val in {"high", "softfail", "mismatched", "critical", "fail"}: return "var(--danger)"
    return "var(--text-muted)"


def risk_badge(text) -> str:
    cls = get_badge_class(text)
    return f'<span class="badge {cls}">{_html.escape(str(text))}</span>'
