# Project Context

**Goal**: Create an AI-Powered Email Threat Detection, Geolocation, and Forensic Intelligence Platform.

**Constraints**: Zero-budget 3-day hackathon project.

**Technology Stack**: 
- Streamlit
- Python
- SQLite

**CRITICAL RULE**: API keys must **never** enter Git version control.

## Testing Rules
- **Offline Enforcement**: The pytest suite is enforced to run completely offline using `pytest-socket` (configured via `pyproject.toml`). Real outbound connections, including DNS and HTTP, are blocked at both test execution and test collection time (via `conftest.py`).
- **Mocks Required**: All external dependencies (Gemini, WHOIS, DNS) must be deterministically mocked. Do not add localhost socket exceptions or disable tests to bypass the offline enforcement.
