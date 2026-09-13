import pytest
import hashlib
import json
import os
import copy
import socket
from datetime import datetime, timezone
import reportlab
from modules.evidence_integrity import (
    build_evidence_manifest,
    verify_evidence_manifest,
    update_manifest_case_id,
    generate_canonical_hash,
    extract_safe_manifest,
    _validate_manifest_schema
)
from modules.report_generator import generate_json_report, generate_html_report, generate_pdf_report
from streamlit.testing.v1 import AppTest

def test_correct_sha256_known_email_bytes():
    email_bytes = b"Subject: Test\n\nBody"
    manifest = build_evidence_manifest(email_bytes, "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    assert manifest["email_sha256"] == hashlib.sha256(email_bytes).hexdigest()
    assert manifest["email_size"] == len(email_bytes)

def test_identical_inputs_produce_identical_manifests():
    email_bytes = b"Subject: Test\n\nBody"
    ts = "2023-10-01T12:00:00+00:00"
    m1 = build_evidence_manifest(email_bytes, "file.eml", ts, "1.0", [{"filename": "a.txt", "size": 10}])
    m2 = build_evidence_manifest(email_bytes, "file.eml", ts, "1.0", [{"filename": "a.txt", "size": 10}])
    assert m1 == m2
    assert m1["manifest_sha256"] == m2["manifest_sha256"]

def test_wrong_supplied_bytes_causes_failure():
    email_bytes = b"Subject: Test\n\nBody"
    manifest = build_evidence_manifest(email_bytes, "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    res = verify_evidence_manifest(manifest, b"Subject: Tampered\n\nBody")
    assert res["status"] == "Integrity Check Failed"

def test_unicode_filenames_handled_safely():
    manifest = build_evidence_manifest(b"abc", "≡ƒÜÇ_report_├⌐.eml", "2023-10-01T12:00:00Z", "1.0", [])
    assert manifest["source_filename"] == "≡ƒÜÇ_report_├⌐.eml"
    assert "manifest_sha256" in manifest
    res = verify_evidence_manifest(manifest, b"abc")
    assert res["status"] == "Original Evidence Verified"

def test_invalid_short_nonhex_attachment_hashes_excluded():
    atts = [
        {"filename": "a.txt", "sha256": "short"},
        {"filename": "b.txt", "sha256": "z"*64},
        {"filename": "c.txt", "sha256": "a"*64}
    ]
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", atts)
    safe = extract_safe_manifest(manifest)
    assert safe["attachments"][0]["sha256"] is None
    assert safe["attachments"][1]["sha256"] is None
    assert safe["attachments"][2]["sha256"] == "a"*64

def test_negative_and_boolean_attachment_sizes_rejected():
    atts = [
        {"filename": "a.txt", "size": -5},
        {"filename": "b.txt", "size": True},
        {"filename": "c.txt", "size": 100}
    ]
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", atts)
    safe = extract_safe_manifest(manifest)
    assert safe["attachments"][0]["size"] == 0
    assert safe["attachments"][1]["size"] == 0
    assert safe["attachments"][2]["size"] == 100

def test_malformed_nonserializable_manifests_never_crash():
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    manifest["bad_field"] = object()
    safe = extract_safe_manifest(manifest)
    assert "bad_field" not in safe
    assert safe.get("manifest_version") == "1.0"

def test_scoring_version_whitespace_rejected():
    with pytest.raises(ValueError):
        build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "   ", [])

def test_reports_contain_attachment_hashes_and_no_secrets():
    good_hash = "a"*64
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [{"filename": "mal.exe", "sha256": good_hash}])

    # Add its case ID
    manifest = update_manifest_case_id(manifest, "CASE-123")

    # Confirm it verifies before generating reports
    res = verify_evidence_manifest(manifest, b"abc")
    assert res["status"] == "Original Evidence Verified"

    # Use a copied malformed version to test secret stripping during report generation
    malformed_manifest = copy.deepcopy(manifest)
    malformed_manifest["SECRET_API_KEY"] = "super-secret-manifest"
    malformed_manifest["attachments"][0]["SECRET_ATT_KEY"] = "super-secret-attachment"

    # Needs a rehash technically for report export logic, though extract_safe ignores hash correctness
    malformed_manifest["manifest_sha256"] = generate_canonical_hash(malformed_manifest)

    case_data = {
        "case_id": "CASE-123",
        "analyzer_results": {
            "evidence_manifest": malformed_manifest
        }
    }

    # Turn off compression so we can inspect PDF text
    old_comp = reportlab.rl_config.pageCompression
    reportlab.rl_config.pageCompression = 0

    try:
        j = generate_json_report(case_data)
        assert b"manifest_version" in j
        assert malformed_manifest["manifest_sha256"].encode() in j
        assert good_hash.encode() in j
        assert b"CASE-123" in j
        assert b"test.eml" in j
        assert b"SECRET_API_KEY" not in j
        assert b"super-secret-manifest" not in j
        assert b"SECRET_ATT_KEY" not in j
        assert b"super-secret-attachment" not in j

        h = generate_html_report(case_data)
        assert b"Evidence Integrity Manifest" in h
        assert malformed_manifest["manifest_sha256"].encode() in h
        assert good_hash.encode() in h
        assert b"CASE-123" in h
        assert b"test.eml" in h
        assert b"SECRET_API_KEY" not in h
        assert b"super-secret-manifest" not in h
        assert b"SECRET_ATT_KEY" not in h
        assert b"super-secret-attachment" not in h

        p = generate_pdf_report(case_data)
        assert b"Evidence Integrity Manifest" in p
        assert malformed_manifest["manifest_sha256"].encode() in p
        assert good_hash.encode() in p
        assert b"CASE-123" in p
        assert b"test.eml" in p
        assert b"SECRET_API_KEY" not in p
        assert b"super-secret-manifest" not in p
        assert b"SECRET_ATT_KEY" not in p
        assert b"super-secret-attachment" not in p
    finally:
        reportlab.rl_config.pageCompression = old_comp

def test_streamlit_app_evidence_integrity():
    at = AppTest.from_file("../../app.py", default_timeout=15)
    at.run(timeout=15)
    assert len(at.markdown) > 0
    at.button(key="demo_legitimate").click().run()
    assert not at.exception

    ui_text = " ".join([m.value for m in at.markdown])
    assert ui_text.count("Evidence Integrity") == 1
    assert "Manifest SHA-256:" in ui_text

    at.run(timeout=15)
    ui_text2 = " ".join([m.value for m in at.markdown])
    assert ui_text == ui_text2

# --- NEW TESTS for Validation ---

def test_invalid_non_byte_evidence_raises_typeerror():
    with pytest.raises(TypeError):
        build_evidence_manifest("not-bytes", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])

def test_empty_bytes_remain_valid():
    manifest = build_evidence_manifest(b"", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    assert manifest["email_size"] == 0
    assert manifest["email_sha256"] == hashlib.sha256(b"").hexdigest()
    assert verify_evidence_manifest(manifest, b"")["status"] == "Original Evidence Verified"

def test_naive_and_malformed_timestamps_raise_valueerror():
    with pytest.raises(ValueError):
        build_evidence_manifest(b"a", "t.eml", "2023-10-01T12:00:00", "1.0", [])  # Naive
    with pytest.raises(ValueError):
        build_evidence_manifest(b"a", "t.eml", "not-a-timestamp", "1.0", [])

def test_timezone_offsets_normalize_to_utc():
    manifest = build_evidence_manifest(b"a", "t.eml", "2023-10-01T12:00:00+04:00", "1.0", [])
    assert manifest["analysis_timestamp"].endswith("Z")
    assert manifest["analysis_timestamp"].startswith("2023-10-01T08:00:00")

def test_malformed_manifests_rejected_schema_validation():
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    # Force an invalid field (e.g., boolean email_size)
    manifest["email_size"] = True
    # Recompute hash so the canonical hash is technically valid for this dict
    manifest["manifest_sha256"] = generate_canonical_hash(manifest)

    res = verify_evidence_manifest(manifest)
    assert res["status"] == "Malformed Manifest"
    assert "Manifest is missing required structural fields" in res["message"]

def test_unsupported_manifest_version_remains_malformed():
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    manifest["manifest_version"] = "99.9"
    manifest["manifest_sha256"] = generate_canonical_hash(manifest)

    res = verify_evidence_manifest(manifest)
    assert res["status"] == "Malformed Manifest"
    assert "Manifest is missing required structural fields" in res["message"]

def test_invalid_top_level_hashes_rejected():
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    manifest["email_sha256"] = "short"
    safe = extract_safe_manifest(manifest)
    assert safe["email_sha256"] is None

def test_negative_and_boolean_email_sizes_sanitized():
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    manifest["email_size"] = -5
    safe = extract_safe_manifest(manifest)
    assert safe["email_size"] == 0

    manifest["email_size"] = True
    safe2 = extract_safe_manifest(manifest)
    assert safe2["email_size"] == 0

def test_non_list_attachment_collections_safely_export():
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    manifest["attachments"] = {"dict": "instead of list"}
    safe = extract_safe_manifest(manifest)
    assert safe["attachments"] == []

def test_arbitrary_objects_not_stringified():
    class Dummy:
        def __str__(self): return "DUMMY"

    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    manifest["scoring_version"] = Dummy()
    safe = extract_safe_manifest(manifest)
    assert safe["scoring_version"] == "Unknown"

def test_empty_and_whitespace_case_ids_rejected():
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    hash_before = manifest["manifest_sha256"]

    m1 = update_manifest_case_id(manifest, "")
    assert m1["manifest_sha256"] == hash_before

    m2 = update_manifest_case_id(manifest, "   ")
    assert m2["manifest_sha256"] == hash_before

def test_long_filenames_safely_limited():
    long_name = "a" * 300 + ".eml"
    manifest = build_evidence_manifest(b"abc", long_name, "2023-10-01T12:00:00Z", "1.0", [])
    assert len(manifest["source_filename"]) == 255

def test_unicode_canonical_json_is_deterministic():
    d1 = {"a": "├⌐", "b": 1}
    d2 = {"b": 1, "a": "├⌐"}
    assert generate_canonical_hash(d1) == generate_canonical_hash(d2)

@pytest.mark.parametrize("bad_val", [float("nan"), float("inf"), float("-inf")])
def test_nan_and_infinity_fail_serialization(bad_val):
    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    manifest["email_size"] = bad_val
    with pytest.raises((ValueError, TypeError, OverflowError)):
        generate_canonical_hash(manifest)

def test_manifest_operations_zero_network(monkeypatch):
    def block_network(*args, **kwargs):
        raise AssertionError("Network access is blocked")

    monkeypatch.setattr(socket, "create_connection", block_network)
    monkeypatch.setattr(socket, "getaddrinfo", block_network)
    monkeypatch.setattr(socket.socket, "connect", block_network)

    manifest = build_evidence_manifest(b"abc", "test.eml", "2023-10-01T12:00:00Z", "1.0", [])
    assert verify_evidence_manifest(manifest, b"abc")["status"] == "Original Evidence Verified"
    safe = extract_safe_manifest(manifest)
    assert safe["email_sha256"] == manifest["email_sha256"]

def test_legacy_cases_remain_supported():
    case_data = {
        "case_id": "CASE-OLD",
        "analyzer_results": {}
    }
    h = generate_html_report(case_data)
    assert b"Evidence Integrity Manifest" not in h
    p = generate_pdf_report(case_data)
    assert len(p) > 100

def test_case_store_integration_with_manifest():
    import streamlit as st
    from modules.session_case_store import save_case, get_case, _init_store

    st.session_state.clear()
    _init_store()

    email_bytes = b"Integration test"
    manifest = build_evidence_manifest(email_bytes, "integration.eml", "2023-10-01T12:00:00Z", "1.0", [])
    orig_hash = manifest["manifest_sha256"]

    case_data = {
        "email_hash": hashlib.sha256(email_bytes).hexdigest(),
        "analyzer_results": {
            "evidence_manifest": manifest
        }
    }

    case_id = save_case(case_data)
    saved = get_case(case_id)
    saved_manifest = saved["analyzer_results"]["evidence_manifest"]

    assert saved_manifest["case_id"] == case_id
    assert saved_manifest["manifest_sha256"] != orig_hash
    assert saved_manifest["email_sha256"] == manifest["email_sha256"]
    assert saved_manifest["email_size"] == manifest["email_size"]

    res = verify_evidence_manifest(saved_manifest, email_bytes)
    assert res["status"] == "Original Evidence Verified"
