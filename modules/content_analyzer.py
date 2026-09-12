"""
Content analyzer for MailTrace AI.

Safety properties:
- Text passed to regex and HTML processing is bounded by LIMITS.MAX_ANALYSIS_TEXT_CHARS.
- URL extraction stops at LIMITS.MAX_UNIQUE_URLS; URLs > LIMITS.MAX_URL_LENGTH are dropped.
- Domain extraction stops at LIMITS.MAX_UNIQUE_DOMAINS.
- Deduplication is deterministic (first-seen order preserved).
- No URLs are fetched.
- Regex patterns avoid catastrophic backtracking (bounded `{0,80}` quantifiers).
"""
import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup

from modules.analysis_limits import LIMITS


# ---------------------------------------------------------------------------
# URL helpers
# ---------------------------------------------------------------------------

def extract_urls(text: str, html: str) -> tuple[list[str], dict]:
    """
    Extract unique URLs from plain text and HTML, bounded by LIMITS.

    Returns (accepted_urls, stats) where stats contains:
        urls_truncated:    bool – True if limit was hit
        urls_accepted:     int
        urls_ignored:      int  – dropped due to length or count limit
    """
    seen: dict[str, None] = {}   # ordered set via dict
    ignored = 0

    def _add(url: str) -> None:
        nonlocal ignored
        if len(url) > LIMITS.MAX_URL_LENGTH:
            ignored += 1
            return
        if url in seen:
            return
        if len(seen) >= LIMITS.MAX_UNIQUE_URLS:
            ignored += 1
            return
        seen[url] = None

    # Plain-text URLs (support defanged hxxp/hxxps)
    bounded_text = text[:LIMITS.MAX_ANALYSIS_TEXT_CHARS]
    for m in re.finditer(r'(?:https?|hxxps?)://[^\s]{1,2048}', bounded_text, flags=re.IGNORECASE):
        _add(m.group(0))

    # HTML href URLs
    if html:
        bounded_html = html[:LIMITS.MAX_ANALYSIS_TEXT_CHARS]
        try:
            soup = BeautifulSoup(bounded_html, "html.parser")
            for a in soup.find_all("a", href=True):
                href: str = a["href"]
                lc = href.lower()
                if lc.startswith(("http://", "https://", "hxxp://", "hxxps://")):
                    _add(href)
        except (ValueError, TypeError, AttributeError):
            pass

    accepted = list(seen.keys())
    truncated = (ignored > 0) or (len(accepted) >= LIMITS.MAX_UNIQUE_URLS)
    return accepted, {
        "urls_truncated": truncated,
        "urls_accepted": len(accepted),
        "urls_ignored": ignored,
    }


def defang_url(url: str) -> str:
    defanged = url.replace("http://", "hxxp://").replace("https://", "hxxps://")
    return defanged.replace(".", "[.]")


def is_ip_hostname(hostname: str) -> bool:
    if not hostname:
        return False
    return bool(re.match(r"^(\d{1,3}\.){3}\d{1,3}$", hostname))


def has_excessive_subdomains(hostname: str) -> bool:
    if not hostname:
        return False
    return len(hostname.split(".")) > 4


SHORTENERS = {"bit.ly", "t.co", "tinyurl.com", "ow.ly", "is.gd", "buff.ly", "goo.gl", "cutt.ly"}


def analyze_urls(urls: list[str], indicators: list) -> int:
    """Score extracted URLs. Bounded by the list already being limited upstream."""
    points = 0
    seen_domains: dict[str, None] = {}

    for url in urls:
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname or ""

            # Domain deduplication for scoring purposes
            if hostname:
                if hostname not in seen_domains:
                    if len(seen_domains) >= LIMITS.MAX_UNIQUE_DOMAINS:
                        continue
                    seen_domains[hostname] = None

            # Punycode (IDN)
            if hostname.startswith("xn--"):
                indicators.append({
                    "severity": "high",
                    "explanation": f"Punycode (IDN) used in URL: {defang_url(url)}",
                    "points": 20,
                })
                points += 20

            # IP as hostname
            if is_ip_hostname(hostname):
                indicators.append({
                    "severity": "high",
                    "explanation": f"IP address used as hostname: {defang_url(url)}",
                    "points": 30,
                })
                points += 30

            # Credential embedded via @
            if "@" in parsed.netloc:
                indicators.append({
                    "severity": "high",
                    "explanation": f"Credential embedded in URL (@ symbol): {defang_url(url)}",
                    "points": 25,
                })
                points += 25

            # Excessive subdomains
            if has_excessive_subdomains(hostname):
                indicators.append({
                    "severity": "medium",
                    "explanation": f"Excessive subdomains in URL: {defang_url(url)}",
                    "points": 15,
                })
                points += 15

            # URL shortener
            if hostname.lower() in SHORTENERS:
                indicators.append({
                    "severity": "medium",
                    "explanation": f"URL shortener used: {defang_url(url)}",
                    "points": 10,
                })
                points += 10

        except (ValueError, TypeError, AttributeError):
            pass

    return points


# ---------------------------------------------------------------------------
# Text extraction
# ---------------------------------------------------------------------------

def extract_clean_text(parsed_email: dict) -> str:
    """
    Combine subject + analysis_text, bounded to MAX_ANALYSIS_TEXT_CHARS.
    The parser already truncated analysis_text; we still enforce the bound
    on the combined string in case callers bypass the parser.
    """
    text = parsed_email.get("analysis_text", "")
    subject = parsed_email.get("subject", "")
    full_content = f"{subject}\n\n{text}"
    if len(full_content) > LIMITS.MAX_ANALYSIS_TEXT_CHARS:
        full_content = full_content[: LIMITS.MAX_ANALYSIS_TEXT_CHARS]
    return full_content


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def analyze_content(parsed_email: dict) -> dict:
    content = extract_clean_text(parsed_email)
    content_lower = content.lower()

    indicators: list = []
    categories: set = set()
    total_points = 0

    # --- Keyword checks ---
    keywords = {
        "urgency": (["urgent", "immediately", "action required", "asap", "within 24 hours"], 15, "medium"),
        "credential request": (["password", "login", "sign into", "verify your account", "verifying your identity", "update your account", "click here to secure"], 30, "high"),
        "payment diversion": (["wire transfer", "bank details", "swift code", "payment instructions"], 30, "high"),
        "fake invoice": (["invoice attached", "outstanding payment", "billing statement"], 20, "medium"),
        "executive impersonation": (["ceo", "director", "president", "are you at your desk"], 15, "medium"),
        "secrecy request": (["confidential", "keep this private", "secret", "do not discuss"], 20, "medium"),
        "threats or fear": (["account suspended", "restricted", "legal action", "final warning", "will be closed"], 25, "high"),
    }

    for cat, (phrases, points, severity) in keywords.items():
        for phrase in phrases:
            if phrase in content_lower:
                indicators.append({
                    "severity": severity,
                    "explanation": f"Language indicates {cat} ('{phrase}')",
                    "points": points,
                })
                categories.add(cat)
                total_points += points
                break  # count category once

    # --- Contextual rules (bounded window {0,80} prevents catastrophic backtracking) ---
    contextual_rules = [
        ("threats or fear",          r"\b(accounts?|wallets?|profiles?)\b",           r"\b(blocked|locked|restricted|suspended|disabled)\b",       25, "high",   "Account-access threat"),
        ("credential request",       r"\b(restore|unblock|reactivate|recover)s?\b",   r"\b(accounts?|wallets?|access)\b",                          25, "high",   "Restoration action"),
        ("credential request",       r"\b(verify|confirm|validate|update)s?\b",       r"\b(identit(?:y|ies)|accounts?|informations?|details?)\b",  25, "high",   "Verification request"),
        ("suspicious url",           r"\b(click|follow|use|open)s?\b",                r"\b(links?|buttons?|below|here)\b",                         15, "medium", "Link action"),
        ("urgency",                  r"\b(funds?|withdrawals?|payments?|wallets?)\b", r"\b(restricted|blocked|held|frozen)\b",                     25, "high",   "Financial-access urgency"),
        ("executive impersonation",  r"\b(ceo|president|director|executive|manager|founder)s?\b", r"\b(wire|transfer|pay|payments?|vendors?|invoices?)\b", 30, "high", "Executive payment request"),
        ("urgency",                  r"\b(urgent|immediately|asap|rush)\b",           r"\b(wire|transfer|payments?|funds?)\b",                     25, "high",   "Urgent payment request"),
        ("secrecy request",          r"\b(confidential|private|secret|discreet|do not discuss)\b", r"\b(wire|transfer|payments?|pay|vendors?)\b",  25, "high",   "Secret payment request"),
    ]

    added_explanations: set = set()
    for cat, grp_a, grp_b, pts, sev, explanation in contextual_rules:
        # Bounded window {0,80} avoids catastrophic backtracking on pathological input
        pattern = rf"(?:{grp_a})[\s\S]{{0,80}}?(?:{grp_b})|(?:{grp_b})[\s\S]{{0,80}}?(?:{grp_a})"
        if re.search(pattern, content_lower):
            if explanation not in added_explanations:
                indicators.append({
                    "severity": sev,
                    "explanation": f"Contextual pattern detected: {explanation}",
                    "points": pts,
                })
                categories.add(cat)
                total_points += pts
                added_explanations.add(explanation)

    # --- URL extraction (bounded) ---
    urls, url_stats = extract_urls(
        parsed_email.get("analysis_text", ""),
        parsed_email.get("body_html", ""),
    )
    url_points = analyze_urls(urls, indicators)
    total_points += url_points
    if url_points > 0:
        categories.add("suspicious url")

    defanged_urls = [defang_url(u) for u in urls]
    score = min(max(total_points, 0), 100)

    # Propagate partial-analysis flag from parser
    content_truncated = bool(parsed_email.get("content_truncated", False))

    return {
        "analyzed_text_length": len(content),
        "content_truncated": content_truncated,
        "content_original_chars": parsed_email.get("content_original_chars", len(content)),
        "content_analyzed_chars": parsed_email.get("content_analyzed_chars", len(content)),
        "categories_detected": list(categories),
        "indicators": indicators,
        "original_urls": urls,
        "defanged_urls": defanged_urls,
        "urls_truncated": url_stats["urls_truncated"],
        "urls_accepted": url_stats["urls_accepted"],
        "urls_ignored": url_stats["urls_ignored"],
        "rule_content_score": score,
        "sanitized_text": content,
    }
