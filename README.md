# MailTrace AI

Email Threat Detection and Forensic Intelligence Platform.

**Live Demo:** https://mailtrace-ai.streamlit.app/ | **Privacy Contract:** [PRIVACY.md](PRIVACY.md)

## About the Project
This is a zero-budget 3-day hackathon project addressing the critical need for accessible, open-source email forensics. It provides an AI-powered interface for analyzing email threats, extracting infrastructure data, and generating forensic reports.

## Main Features
- Automated email parsing and header anomaly detection.
- Relay-chain and origin-IP extraction with IP geolocation mapping.
- Domain and DNS intelligence.
- Rule-based content analysis and Gemini AI-powered threat assessment.
- Campaign correlation and history tracking.
- Automated forensic PDF report generation.

## Architecture & Technology Stack
MailTrace AI is built on a completely free, open-source technology stack:
- **Python**: Core backend logic.
- **Streamlit**: Web-based interactive dashboard.
- **In-Memory Session State**: Isolated, temporary case storage and campaign tracking (Privacy Mode).
- Uses open-source libraries for DNS lookups, geographic mapping, and PDF generation.

## Local Installation (Windows)

1. Clone the repository and open the directory:
   ```powershell
   git clone <repository_url>
   cd MailTrace-AI
   ```

2. Create and activate a virtual environment:
   ```powershell
   python -m venv .venv
   .\.venv\Scripts\activate
   ```

3. Install all dependencies:
   ```powershell
   pip install -r requirements.txt
   ```

4. Configure your environment:
   Copy `.env.example` to `.env`.
   If you wish to enable AI assessments, provide your Gemini API key in the `.env` file. Do not use real keys in `.env.example`.

5. Start the application:
   ```powershell
   streamlit run app.py
   ```

## Automated Quality Gate
MailTrace AI includes a comprehensive test suite. To run the automated quality gate:
```powershell
pytest
```
**Current Status:** 105 automated tests passing.

## Safe Testing Instructions
When testing MailTrace AI, **only use synthetic or defanged `.eml` files.** The repository includes safe samples under `sample_emails/` and `tests/fixtures/`. These samples use synthetic domains (e.g., `example.com`), defanged URLs (`hxxp://`), and contain no real recipient identities or active malicious payloads.

## Privacy and Forensic Limitations
- **Case Storage (Privacy Mode):** Case storage is session-only and cases disappear when the current browser session ends. This feature is designed for demonstration and temporary investigation. Users should export a PDF/JSON report before leaving if they need a copy. The public prototype is not permanent evidence storage and is not authenticated storage.
- **Authentication Headers:** SPF, DKIM, and DMARC results are reported strictly as evidence. They are not guaranteed proof of identity or malice.
- **IP Geolocation:** The geolocation data provided represents the probable geographic region of the infrastructure used (e.g., a data center or relay node). It does **not** represent the physical location or identity of the attacker.
- Geolocation is completely **optional and manual**. Users can use offline analysis without sharing the IP.
- When explicitly requested, the public relay IP address is sent to FreeIPAPI (an independent third party) over HTTPS. No email bodies, subject lines, senders, or other PII are transmitted. Provider availability and rate limits may affect enrichment.

## Deployment Notes
- This project is hosted for free on **Streamlit Community Cloud**.
- **Gemini AI Threat Analysis:** Public AI usage is intentionally limited by a global process-wide safety quota and per-session limits to prevent abuse.
- If Gemini is disabled or quotas are reached, all offline features (header analysis, rule-based content scoring, relay geolocation, and forensic report generation) will continue working seamlessly.
- **Privacy Warning:** Unpaid Gemini must not receive personal, confidential, or sensitive content.
- **Quota Reset:** The global safety budget is best-effort. It resets daily at UTC midnight, or whenever the application container is restarted. This quota system is designed for public demo safety and does not constitute cryptographic authentication.
