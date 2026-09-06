# MailTrace AI Privacy Contract

MailTrace AI is built with privacy and data minimization as core design principles. By using this application, you agree to the following data handling and privacy boundaries.

## 1. Data Processing Boundaries
1. **Local Server Analysis:** Uploaded `.eml` content reaches the Streamlit server for analysis.
2. **Zero Default AI Transmission:** Offline analysis does not intentionally transmit email body content to Gemini.
3. **Session-Isolated Storage:** Cases exist only in the current Streamlit session and are not permanent evidence storage.
4. **No Attachment Retention:** Raw attachments are not written, executed, extracted or included in reports.

## 2. Optional External Services
5. **Opt-in AI Analysis:** Optional Gemini analysis sends the disclosed email text/headers to Google only after consent and manual action.
6. **AI Content Restrictions:** Unpaid Gemini must not be used with personal, sensitive or confidential content.
7. **Opt-in Geolocation:** Optional FreeIPAPI lookup sends only the selected public relay IP after consent and manual action. No email content or identities are sent.
8. **Opt-in Domain Intelligence:** DNS/WHOIS/domain intelligence may disclose the queried domain to external infrastructure when manually requested.
9. **Map Provider Context:** Map providers may receive normal browser network information when a map is displayed.

## 3. Application Constraints
10. **Zero URL Fetching:** Extracted email URLs are never fetched.
11. **Not For Confidential Use:** Uploaded data should not be considered suitable for confidential organizational investigations on this public prototype.
12. **Synthetic Data Recommended:** Users should use synthetic, sanitized or non-sensitive emails.
13. **Session Expiry:** Closing the session removes access to session cases, but do not promise a precise provider-level memory deletion time that the application cannot prove.
14. **Platform Terms Apply:** Streamlit Community Cloud and external providers have their own privacy terms.
15. **No Security Guarantees:** Automated security checks reduce risk but do not guarantee the application is vulnerability-free.

## 4. Unsupported Claims
We explicitly **do not claim**:
- end-to-end encryption
- zero retention by hosting providers
- complete anonymity
- malware scanning
- attacker identification
- regulatory compliance
- guaranteed security
