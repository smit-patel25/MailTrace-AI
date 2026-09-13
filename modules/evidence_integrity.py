import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Optional

SUPPORTED_MANIFEST_VERSIONS = frozenset({"1.0"})

def generate_canonical_hash(manifest_dict: dict) -> str:
    """
    Generates a deterministic SHA-256 hash from a dictionary using canonical JSON.
    Excludes the 'manifest_sha256' key.
    """
    clean_dict = {k: v for k, v in manifest_dict.items() if k != "manifest_sha256"}
    json_str = json.dumps(clean_dict, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False)
    return hashlib.sha256(json_str.encode("utf-8")).hexdigest()

def _sanitize_filename(name: str) -> str:
    if not isinstance(name, str):
        return "unnamed"
    # Remove Windows and POSIX paths by getting the basename after standardizing slashes
    clean_name = name.replace("\\", "/").split("/")[-1]
    # Remove NUL and control characters
    clean_name = re.sub(r'[\x00-\x1f\x7f-\x9f]', '', clean_name)
    if not clean_name:
        return "unnamed"
    # Limit length to 255 chars
    return clean_name[:255]

def _safe_text(val, default="Unknown", max_len=255) -> str:
    if not isinstance(val, str):
        return default
    return val[:max_len]

def _safe_size(val) -> int:
    if not isinstance(val, int) or isinstance(val, bool) or val < 0:
        return 0
    return val

def _safe_sha256(val) -> Optional[str]:
    if isinstance(val, str) and re.fullmatch(r"[a-fA-F0-9]{64}", val):
        return val.lower()
    return None

def _is_valid_timestamp(val: str) -> bool:
    if not isinstance(val, str):
        return False
    try:
        normalized = val[:-1] + "+00:00" if val.endswith("Z") else val
        dt = datetime.fromisoformat(normalized)
        return dt.tzinfo is not None and dt.tzinfo.utcoffset(dt) is not None
    except (ValueError, TypeError):
        return False

def build_evidence_manifest(
    email_bytes: bytes,
    filename: Optional[str],
    analysis_timestamp: str,
    scoring_version: str,
    attachments_metadata: list,
    case_id: Optional[str] = None
) -> dict:
    """
    Creates an Evidence Integrity Manifest.
    """
    if case_id is not None:
        if not isinstance(case_id, str) or not case_id.strip() or len(case_id) > 255:
            raise ValueError("case_id must be a valid bounded string or None.")

    if not isinstance(email_bytes, (bytes, bytearray, memoryview)):
        raise TypeError("email_bytes must be a bytes-like object.")

    email_bytes = bytes(email_bytes)

    if not scoring_version or not isinstance(scoring_version, str) or not scoring_version.strip():
        raise ValueError("scoring_version must be a non-empty string.")

    try:
        if not isinstance(analysis_timestamp, str):
            raise ValueError("analysis_timestamp must be a string.")
        normalized_input = analysis_timestamp[:-1] + "+00:00" if analysis_timestamp.endswith("Z") else analysis_timestamp
        dt = datetime.fromisoformat(normalized_input)
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            raise ValueError("analysis_timestamp must be timezone-aware.")
        # Normalize to UTC and append 'Z'
        normalized_timestamp = dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except (ValueError, TypeError):
        raise ValueError("analysis_timestamp must be a valid timezone-aware ISO-8601 string.")

    email_sha256 = hashlib.sha256(email_bytes).hexdigest()
    email_size = len(email_bytes)

    safe_attachments = []
    if isinstance(attachments_metadata, list):
        for att in attachments_metadata[:100]:
            if not isinstance(att, dict):
                continue

            size = _safe_size(att.get("size"))
            clean_sha256 = _safe_sha256(att.get("sha256"))

            safe_attachments.append({
                "filename": _sanitize_filename(att.get("filename", "unnamed_attachment")),
                "size": size,
                "content_type": _safe_text(att.get("content_type"), default="application/octet-stream"),
                "sha256": clean_sha256,
                "risk_level": _safe_text(att.get("risk_level"), default="Unknown")
            })

    clean_name = _sanitize_filename(filename) if filename else "unnamed.eml"

    manifest = {
        "manifest_version": "1.0",
        "case_id": case_id if isinstance(case_id, str) else None,
        "source_filename": clean_name,
        "email_size": email_size,
        "email_sha256": email_sha256,
        "analysis_timestamp": normalized_timestamp,
        "scoring_version": str(scoring_version),
        "attachments": safe_attachments,
        "integrity_status": "Evidence Captured"
    }

    manifest["manifest_sha256"] = generate_canonical_hash(manifest)
    return manifest

def update_manifest_case_id(manifest: dict, new_case_id: str) -> dict:
    """
    Updates the case_id in an existing manifest and regenerates the canonical hash.
    """
    if not isinstance(manifest, dict):
        return manifest

    if not isinstance(new_case_id, str) or not new_case_id.strip() or len(new_case_id) > 255:
        return manifest

    updated = manifest.copy()
    updated["case_id"] = new_case_id
    try:
        updated["manifest_sha256"] = generate_canonical_hash(updated)
    except (ValueError, TypeError, OverflowError):
        # Fallback if somehow manifest contains un-serializable components added downstream
        return manifest
    return updated

def _validate_manifest_schema(manifest: dict) -> bool:
    if not isinstance(manifest, dict): return False

    mv = manifest.get("manifest_version")
    if not isinstance(mv, str) or mv not in SUPPORTED_MANIFEST_VERSIONS: return False

    cid = manifest.get("case_id")
    if cid is not None and (not isinstance(cid, str) or not cid.strip() or len(cid) > 255): return False

    sf = manifest.get("source_filename")
    if not isinstance(sf, str) or _sanitize_filename(sf) != sf: return False

    sz = manifest.get("email_size")
    if not isinstance(sz, int) or isinstance(sz, bool) or sz < 0: return False

    e_hash = manifest.get("email_sha256")
    if not _safe_sha256(e_hash): return False

    m_hash = manifest.get("manifest_sha256")
    if not _safe_sha256(m_hash): return False

    if not _is_valid_timestamp(manifest.get("analysis_timestamp", "")): return False

    sv = manifest.get("scoring_version")
    if not isinstance(sv, str) or not sv.strip() or len(sv) > 255: return False

    ists = manifest.get("integrity_status")
    if not isinstance(ists, str) or not ists.strip() or len(ists) > 255: return False

    atts = manifest.get("attachments")
    if not isinstance(atts, list): return False
    for att in atts:
        if not isinstance(att, dict): return False
        att_fname = att.get("filename")
        if not isinstance(att_fname, str) or _sanitize_filename(att_fname) != att_fname: return False
        att_sz = att.get("size")
        if not isinstance(att_sz, int) or isinstance(att_sz, bool) or att_sz < 0: return False
        att_hash = att.get("sha256")
        if att_hash is not None and not _safe_sha256(att_hash): return False
        att_ct = att.get("content_type")
        if not isinstance(att_ct, str) or not att_ct.strip() or len(att_ct) > 255: return False
        att_rl = att.get("risk_level")
        if not isinstance(att_rl, str) or not att_rl.strip() or len(att_rl) > 255: return False

    return True

def verify_evidence_manifest(manifest: dict, email_bytes: Optional[bytes] = None) -> dict:
    """
    Verifies a manifest structure and optionally checks original bytes.
    Returns a dict with 'status' and 'message'.
    """
    if not _validate_manifest_schema(manifest):
        return {"status": "Malformed Manifest", "message": "Manifest is missing required structural fields."}

    try:
        expected_hash = generate_canonical_hash(manifest)
    except (ValueError, TypeError, OverflowError):
        return {"status": "Malformed Manifest", "message": "Manifest metadata contains non-serializable fields."}

    if expected_hash != manifest.get("manifest_sha256"):
        return {"status": "Integrity Check Failed", "message": "Manifest metadata hash verification failed."}

    if email_bytes is not None:
        if not isinstance(email_bytes, (bytes, bytearray, memoryview)):
            return {"status": "Integrity Check Failed", "message": "Supplied email evidence is not raw bytes."}

        email_bytes = bytes(email_bytes)
        current_email_hash = hashlib.sha256(email_bytes).hexdigest()
        current_email_size = len(email_bytes)

        if current_email_hash != manifest.get("email_sha256") or current_email_size != manifest.get("email_size"):
            return {"status": "Integrity Check Failed", "message": "Supplied email bytes do not match the manifest evidence hash."}

        return {"status": "Original Evidence Verified", "message": "Metadata and original evidence bytes mathematically verified."}

    return {"status": "Manifest Metadata Verified", "message": "Manifest structure is intact, but original evidence bytes were unavailable for re-verification."}

def extract_safe_manifest(manifest: dict) -> dict:
    """
    Creates a safe, whitelisted copy of the manifest for reporting.
    Prevents leaking raw bytes, message body, API keys, tokens, or local paths.
    """
    if not isinstance(manifest, dict) or not manifest:
        return {}

    safe_atts = []
    raw_atts = manifest.get("attachments", [])
    if not isinstance(raw_atts, list):
        raw_atts = []

    for att in raw_atts[:100]:
        if not isinstance(att, dict):
            continue

        safe_atts.append({
            "filename": _sanitize_filename(att.get("filename")),
            "sha256": _safe_sha256(att.get("sha256")),
            "size": _safe_size(att.get("size")),
            "content_type": _safe_text(att.get("content_type"), default="Unknown"),
            "risk_level": _safe_text(att.get("risk_level"), default="Unknown"),
        })

    case_id_val = manifest.get("case_id")
    safe_case_id = _safe_text(case_id_val, default=None) if case_id_val is not None else None
    if safe_case_id is not None and not safe_case_id.strip():
        safe_case_id = None

    return {
        "manifest_version": _safe_text(manifest.get("manifest_version"), default="Unknown"),
        "case_id": safe_case_id,
        "integrity_status": _safe_text(manifest.get("integrity_status"), default="Unknown"),
        "source_filename": _sanitize_filename(manifest.get("source_filename")),
        "email_sha256": _safe_sha256(manifest.get("email_sha256")),
        "manifest_sha256": _safe_sha256(manifest.get("manifest_sha256")),
        "email_size": _safe_size(manifest.get("email_size")),
        "analysis_timestamp": _safe_text(manifest.get("analysis_timestamp"), default="Unknown"),
        "scoring_version": _safe_text(manifest.get("scoring_version"), default="Unknown"),
        "attachments": safe_atts
    }
