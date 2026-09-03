# MailTrace AI

Email Threat Detection and Forensic Intelligence Platform.

**Live Demo:** https://mailtrace-ai.streamlit.app/

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
- **SQLite**: Local case database and campaign tracking.
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
- **Authentication Headers:** SPF, DKIM, and DMARC results are reported strictly as evidence. They are not guaranteed proof of identity or malice.
- **IP Geolocation:** The geolocation data provided represents the probable geographic region of the infrastructure used (e.g., a data center or relay node). It does **not** represent the physical location or identity of the attacker.

## Deployment Notes
- This project is hosted for free on **Streamlit Community Cloud**.
- Gemini AI threat analysis depends on limited free-tier API availability and may experience rate limits.
- If Gemini is unavailable, all offline features (header analysis, rule-based content scoring, relay geolocation, and forensic report generation) will continue working seamlessly.
