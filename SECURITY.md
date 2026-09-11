# Security Policy

## Supported Versions

Only the latest code on the `main` branch is actively supported for security updates. Older commits, forks, and custom or modified deployments are not supported.

## Reporting a Vulnerability

We take the security of this project seriously. Please use **GitHub Private Vulnerability Reporting** via the repository's Security tab to report any suspected vulnerabilities.

**Do not** disclose vulnerabilities, exploit details, secrets, personal email data, or sensitive evidence in public GitHub issues.

When reporting a vulnerability, please provide the following details:
- A clear description of the vulnerability.
- The affected component or file.
- Safe reproduction steps.
- The potential impact.
- Suggested remediation, if known.
- Sanitized evidence only. Never include real credentials, API keys, or confidential email content in your report.

## Response Expectations

All reports will be reviewed on a best-effort basis by the maintainers. Please note that we do not promise a guaranteed response time, and we do not offer financial payments, bug bounties, guaranteed CVE assignments, or other rewards for vulnerability reports.

## Project Limitations

MailTrace AI is an educational and hackathon security-analysis prototype. While we strive to maintain a secure codebase, no software is completely secure or vulnerability-free.

- **Not Enterprise Grade:** This tool is not a replacement for enterprise email security gateways, antivirus software, sandboxing, or professional incident response services.
- **Use Safe Data:** Users are strongly advised to use synthetic, defanged, or non-sensitive emails when utilizing public deployments of this application.
- **Privacy Boundaries:** Please refer to [PRIVACY.md](PRIVACY.md) for complete details on our data-handling boundaries and session privacy limits.
- **Third-Party Services:** Optional external operations, such as Gemini AI analysis and IP geolocation, require explicit user consent. When utilized, the terms and conditions of those respective third-party services apply.
