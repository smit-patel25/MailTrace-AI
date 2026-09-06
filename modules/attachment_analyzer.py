import os
import hashlib
import mimetypes

HIGH_RISK_EXTS = {".exe", ".scr", ".bat", ".cmd", ".com", ".js", ".vbs", ".ps1", ".msi", ".jar"}
MACRO_EXTS = {".docm", ".xlsm", ".pptm"}
ARCHIVE_EXTS = {".zip", ".rar", ".7z", ".iso"}
COMMON_DOC_IMAGE_EXTS = {"pdf", "docx", "xlsx", "pptx", "png", "jpg", "jpeg", "txt", "csv", "gif"}

GENERIC_MIME_TYPES = {
    "application/octet-stream",
    "application/x-download",
    "application/force-download",
    "binary/octet-stream",
}


def format_human_size(size_bytes: int) -> str:
    """Format bytes into a human-readable string."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    else:
        return f"{size_bytes / (1024 * 1024):.1f} MB"


def sanitize_filename(raw_filename: str) -> tuple[str, list[str]]:
    """
    Sanitize raw filename for display and detect suspicious filename anomalies.
    Returns (sanitized_filename, suspicious_indicators).
    """
    indicators = []

    if not raw_filename or not raw_filename.strip():
        return "unnamed_attachment", ["Missing or empty filename."]

    orig = raw_filename.strip()

    # Detect control characters
    if any(ord(c) < 32 or (127 <= ord(c) <= 159) for c in orig):
        indicators.append("Filename contains control characters.")
        orig = "".join(c for c in orig if ord(c) >= 32 and not (127 <= ord(c) <= 159))

    # Detect path components
    if "/" in orig or "\\" in orig or ".." in orig:
        indicators.append("Filename contains path traversal sequence or path delimiters.")

    # Detect misleading trailing spaces or dots
    if raw_filename != raw_filename.strip(" ."):
        indicators.append("Filename contains trailing whitespace or trailing dots.")

    # Strip path components
    clean_name = os.path.basename(orig.replace("\\", "/")).strip(" .")

    if not clean_name:
        clean_name = "unnamed_attachment"
        if "Missing or empty filename." not in indicators:
            indicators.append("Missing or empty filename after sanitization.")

    return clean_name, indicators


def check_mime_mismatch(declared_mime: str, ext: str) -> bool:
    """
    Conservatively check if declared MIME type conflicts with extension.
    Ignores generic MIME types like application/octet-stream.
    """
    if not declared_mime or not ext:
        return False

    declared_mime = declared_mime.lower().strip()
    ext = ext.lower().strip()
    if not ext.startswith("."):
        ext = "." + ext

    if declared_mime in GENERIC_MIME_TYPES:
        return False

    # Get expected extensions for declared MIME
    expected_exts = mimetypes.guess_all_extensions(declared_mime)
    # Guess MIME from extension
    guessed_type, _ = mimetypes.guess_type("file" + ext)

    if expected_exts and ext in expected_exts:
        return False

    if guessed_type and guessed_type.lower() == declared_mime:
        return False

    # If extension has a known MIME type that differs from non-generic declared MIME
    if guessed_type and guessed_type.lower() not in GENERIC_MIME_TYPES:
        return True

    # If declared MIME has known extensions and current extension is not among them
    if expected_exts and ext not in expected_exts:
        return True

    return False


def analyze_single_attachment(att: dict) -> dict:
    """
    Analyze metadata for a single MIME attachment.
    Accepts dict with keys: filename, content_type, size (and optional raw_bytes or sha256).
    """
    raw_filename = att.get("filename", "")
    declared_mime = att.get("content_type", "application/octet-stream") or "application/octet-stream"

    raw_bytes = att.get("raw_bytes")
    if raw_bytes is not None:
        size_bytes = len(raw_bytes)
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    else:
        size_bytes = att.get("size", 0)
        sha256_hash = att.get("sha256", hashlib.sha256(str(raw_filename).encode()).hexdigest())

    sanitized_name, filename_indicators = sanitize_filename(raw_filename)

    # Extension parsing
    parts = sanitized_name.lower().split(".")
    ext = ("." + parts[-1]) if len(parts) > 1 else ""

    reasons = list(filename_indicators)
    risk_level = "Low"

    # 1. High-risk executable/script extension
    if ext in HIGH_RISK_EXTS:
        reasons.append(f"High-risk executable or script extension ({ext}).")
        risk_level = "High"

    # 2. Macro-enabled document
    elif ext in MACRO_EXTS:
        reasons.append(f"Macro-enabled document format ({ext}).")
        if risk_level != "High":
            risk_level = "High"

    # 3. Archive/container requiring review
    elif ext in ARCHIVE_EXTS:
        reasons.append(f"Archive or container file requiring review ({ext}).")
        if risk_level == "Low":
            risk_level = "Review"

    # 4. Double extension deception (e.g. invoice.pdf.exe, document.docx.js)
    if len(parts) >= 3:
        second_last = parts[-2]
        last = parts[-1]
        if second_last in COMMON_DOC_IMAGE_EXTS and ("." + last in HIGH_RISK_EXTS or "." + last in MACRO_EXTS or "." + last in ARCHIVE_EXTS):
            reasons.append(f"Double-extension deception detected (e.g. .{second_last}.{last}).")
            risk_level = "High"

    # 5. MIME type mismatch
    if check_mime_mismatch(declared_mime, ext):
        reasons.append(f"Declared MIME type ({declared_mime}) mismatches file extension ({ext}).")
        if risk_level == "Low":
            risk_level = "Review"

    # Upgrade risk level if filename anomalies (like path traversal or control chars) are present
    if any("path traversal" in r.lower() or "control characters" in r.lower() for r in filename_indicators):
        if risk_level == "Low":
            risk_level = "Review"

    return {
        "filename": sanitized_name,
        "raw_filename": raw_filename,
        "extension": ext,
        "content_type": declared_mime,
        "size": size_bytes,
        "human_size": format_human_size(size_bytes),
        "sha256": sha256_hash,
        "risk_level": risk_level,
        "reasons": reasons
    }


def analyze_attachments(parsed_email: dict) -> dict:
    """
    Perform metadata-only inspection on all attachments in a parsed email dictionary.
    """
    raw_attachments = parsed_email.get("attachments", [])
    results = []

    has_high_risk = False
    has_review = False

    for att in raw_attachments:
        res = analyze_single_attachment(att)
        results.append(res)
        if res["risk_level"] == "High":
            has_high_risk = True
        elif res["risk_level"] == "Review":
            has_review = True

    if not results:
        overall_risk = "None"
    elif has_high_risk:
        overall_risk = "High"
    elif has_review:
        overall_risk = "Review"
    else:
        overall_risk = "Low"

    return {
        "attachment_count": len(results),
        "overall_metadata_risk": overall_risk,
        "attachments": results,
        "disclaimer": "Attachment assessment is based on metadata only and is not a malware scan."
    }
