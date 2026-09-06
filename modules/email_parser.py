"""
Bounded email parser for MailTrace AI.

Safety properties:
- Validates raw input before any parsing begins.
- Uses an iterative (non-recursive) MIME walk with hard part/depth/header/attachment limits.
- Hard-rejection returns {"rejected": True, ...} — callers must check this key.
- Never reveals raw header content, paths, or payload bytes in error messages.
- Never writes temporary content to disk.
- Decodes each attachment payload exactly once.
"""
import hashlib
import email.policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

from modules.analysis_limits import LIMITS


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _extract_visible_html_text(html_content: str) -> str:
    """Strip scripts/styles from HTML and return visible text only."""
    if not html_content:
        return ""
    # Bound the HTML string before feeding to BeautifulSoup
    bounded = html_content[:LIMITS.MAX_ANALYSIS_TEXT_CHARS]
    try:
        soup = BeautifulSoup(bounded, "html.parser")
        for tag in soup(["script", "style", "iframe", "object", "embed", "form"]):
            tag.decompose()
        return soup.get_text(separator=" ", strip=True)
    except Exception:
        return ""


def _rejection(reason_code: str, human_reason: str) -> dict:
    """Produce a hard-rejection result dict. Never include raw content."""
    return {
        "rejected": True,
        "rejection_reason": reason_code,
        "rejection_human": human_reason,
        "defects": [],
    }


def _count_long_header_lines(raw_email: bytes) -> tuple[int, bool]:
    """
    Scan raw bytes for header lines (stop at first blank line / body separator).
    Returns (total_header_lines, any_oversized).

    Linear in input size; never decodes attacker-controlled content.
    """
    total = 0
    oversized = False
    # Work in raw bytes to avoid any charset decoding at this stage
    pos = 0
    length = len(raw_email)
    while pos < length:
        # Find end of line
        nl = raw_email.find(b"\n", pos)
        if nl == -1:
            line = raw_email[pos:]
            pos = length
        else:
            line = raw_email[pos : nl + 1]
            pos = nl + 1

        # Strip CRLF for length measurement
        stripped = line.rstrip(b"\r\n")

        # Blank line → end of headers
        if stripped == b"":
            break

        total += 1
        if len(stripped) > LIMITS.MAX_RAW_HEADER_LINE_BYTES:
            oversized = True

    return total, oversized


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_eml_bytes(raw_email: bytes) -> dict:
    """
    Parse raw email bytes into a structured dictionary.

    Returns a dict with key "rejected"=True and a safe human reason if any
    hard safety limit is exceeded.  Callers must check for this key before
    proceeding with analysis.

    All other returns are normal parsed-email dicts with optional
    partial-analysis metadata.
    """
    # -----------------------------------------------------------------------
    # 1. Raw input validation
    # -----------------------------------------------------------------------
    if not isinstance(raw_email, (bytes, bytearray)):
        return _rejection("invalid_type", "Input must be bytes.")

    if len(raw_email) == 0:
        return _rejection("empty_input", "The uploaded file is empty.")

    if len(raw_email) > LIMITS.MAX_RAW_BYTES:
        return _rejection(
            "file_too_large",
            "This email exceeds MailTrace AI's safe analysis limits and was not "
            "processed. Reason: file too large.",
        )

    # Check for excessively long individual header lines (O(n) in raw size)
    _, has_oversized_line = _count_long_header_lines(raw_email)
    if has_oversized_line:
        return _rejection(
            "excessive_header_line",
            "This email exceeds MailTrace AI's safe analysis limits and was not "
            "processed. Reason: excessive headers.",
        )

    # -----------------------------------------------------------------------
    # 2. Initial parse by Python stdlib
    # -----------------------------------------------------------------------
    try:
        msg = BytesParser(policy=email.policy.default).parsebytes(raw_email)
    except Exception:
        return {"defects": ["Fatal parsing error: could not parse email structure."]}

    defects = [str(d) for d in msg.defects]

    parsed_data = {
        "rejected": False,
        "subject": msg.get("subject", ""),
        "from": msg.get("from", ""),
        "to": msg.get("to", ""),
        "cc": msg.get("cc", ""),
        "date": msg.get("date", ""),
        "message_id": msg.get("message-id", ""),
        "reply_to": msg.get("reply-to", ""),
        "return_path": msg.get("return-path", ""),
        "x_mailer": msg.get("x-mailer", ""),
        "received": msg.get_all("received", []),
        "authentication_results": msg.get_all("authentication-results", []),
        "body_plain": "",
        "body_html": "",
        "analysis_text": "",
        "used_html_fallback": False,
        "attachments": [],
        "defects": defects,
        # Partial-analysis metadata
        "content_truncated": False,
        "content_original_chars": 0,
        "content_analyzed_chars": 0,
    }

    # -----------------------------------------------------------------------
    # 3. Bounded iterative MIME walk
    # -----------------------------------------------------------------------
    part_count = 0
    total_headers = 0
    attachment_count = 0
    cumulative_attachment_bytes = 0

    # Use an explicit stack for depth tracking (no Python recursion)
    # Each stack item is (message_part, depth)
    stack = [(msg, 0)]

    while stack:
        part, depth = stack.pop()

        if depth > LIMITS.MAX_MIME_NESTING_DEPTH:
            return _rejection(
                "excessive_nesting",
                "This email exceeds MailTrace AI's safe analysis limits and was not "
                "processed. Reason: excessive MIME complexity.",
            )

        part_count += 1
        if part_count > LIMITS.MAX_MIME_PARTS:
            return _rejection(
                "excessive_mime_parts",
                "This email exceeds MailTrace AI's safe analysis limits and was not "
                "processed. Reason: excessive MIME complexity.",
            )

        # Count headers on this part
        try:
            part_header_count = len(list(part.keys()))
        except Exception:
            part_header_count = 0

        if part_header_count > LIMITS.MAX_HEADERS_PER_PART:
            return _rejection(
                "excessive_headers_per_part",
                "This email exceeds MailTrace AI's safe analysis limits and was not "
                "processed. Reason: excessive headers.",
            )

        total_headers += part_header_count
        if total_headers > LIMITS.MAX_TOTAL_HEADERS:
            return _rejection(
                "excessive_total_headers",
                "This email exceeds MailTrace AI's safe analysis limits and was not "
                "processed. Reason: excessive headers.",
            )

        content_type = part.get_content_type()

        # Push sub-parts for multipart containers
        if content_type.startswith("multipart/"):
            try:
                sub_parts = part.get_payload()
                if isinstance(sub_parts, list):
                    for sub in reversed(sub_parts):
                        stack.append((sub, depth + 1))
            except Exception as exc:
                defects.append(f"Error reading multipart payload: {type(exc).__name__}")
            continue

        content_disposition = part.get_content_disposition()
        filename = part.get_filename()

        # --- Attachment parts ---
        if content_disposition == "attachment" or filename is not None:
            attachment_count += 1
            if attachment_count > LIMITS.MAX_ATTACHMENTS:
                return _rejection(
                    "excessive_attachments",
                    "This email exceeds MailTrace AI's safe analysis limits and was not "
                    "processed. Reason: excessive attachment data.",
                )

            try:
                payload_bytes = part.get_payload(decode=True)
                if payload_bytes is None:
                    payload_bytes = b""
            except RecursionError:
                defects.append("Attachment could not be decoded safely.")
                payload_bytes = b""
            except Exception:
                defects.append("Error decoding attachment payload.")
                payload_bytes = b""

            att_size = len(payload_bytes)

            if att_size > LIMITS.MAX_ATTACHMENT_BYTES:
                return _rejection(
                    "attachment_too_large",
                    "This email exceeds MailTrace AI's safe analysis limits and was not "
                    "processed. Reason: excessive attachment data.",
                )

            cumulative_attachment_bytes += att_size
            if cumulative_attachment_bytes > LIMITS.MAX_CUMULATIVE_ATTACHMENT_BYTES:
                return _rejection(
                    "cumulative_attachment_too_large",
                    "This email exceeds MailTrace AI's safe analysis limits and was not "
                    "processed. Reason: excessive attachment data.",
                )

            # Compute hash exactly once — do not store raw bytes beyond this block
            sha256_hash = hashlib.sha256(payload_bytes).hexdigest()

            # Truncate filename for display
            raw_filename = filename or ""
            if len(raw_filename.encode("utf-8", errors="replace")) > LIMITS.MAX_DISPLAY_FILENAME_BYTES:
                raw_filename = raw_filename[:LIMITS.MAX_DISPLAY_FILENAME_BYTES]

            parsed_data["attachments"].append({
                "filename": raw_filename,
                "content_type": content_type or "application/octet-stream",
                "size": att_size,
                "sha256": sha256_hash,
                "raw_bytes": payload_bytes,
            })

        else:
            # --- Text/HTML body parts ---
            try:
                payload = part.get_content()
                if content_type == "text/plain":
                    parsed_data["body_plain"] += str(payload)
                elif content_type == "text/html":
                    parsed_data["body_html"] += str(payload)
            except RecursionError:
                defects.append("Body part could not be decoded safely.")
            except Exception:
                defects.append("Error decoding body part.")
                try:
                    raw_payload = part.get_payload(decode=True)
                    if raw_payload:
                        fallback_str = raw_payload.decode("utf-8", errors="replace")
                        if content_type == "text/plain":
                            parsed_data["body_plain"] += fallback_str
                        elif content_type == "text/html":
                            parsed_data["body_html"] += fallback_str
                except (LookupError, ValueError, TypeError, AttributeError, RecursionError):
                    pass

    # -----------------------------------------------------------------------
    # 4. Build analysis_text with truncation tracking
    # -----------------------------------------------------------------------
    if parsed_data["body_plain"].strip():
        raw_text = parsed_data["body_plain"]
        parsed_data["used_html_fallback"] = False
    elif parsed_data["body_html"].strip():
        raw_text = _extract_visible_html_text(parsed_data["body_html"])
        parsed_data["used_html_fallback"] = True
    else:
        raw_text = ""
        parsed_data["used_html_fallback"] = False

    parsed_data["content_original_chars"] = len(raw_text)

    if len(raw_text) > LIMITS.MAX_ANALYSIS_TEXT_CHARS:
        parsed_data["analysis_text"] = raw_text[: LIMITS.MAX_ANALYSIS_TEXT_CHARS]
        parsed_data["content_truncated"] = True
        parsed_data["content_analyzed_chars"] = LIMITS.MAX_ANALYSIS_TEXT_CHARS
    else:
        parsed_data["analysis_text"] = raw_text
        parsed_data["content_truncated"] = False
        parsed_data["content_analyzed_chars"] = len(raw_text)

    parsed_data["defects"] = defects
    return parsed_data
