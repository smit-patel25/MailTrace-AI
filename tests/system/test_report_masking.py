import json
import zlib
import re
import pytest
from modules.report_generator import generate_json_report, generate_html_report, generate_pdf_report
from modules.data_masking import mask_case_data

def extract_pdf_text_streams(pdf_bytes):
    streams = re.findall(b'stream\r?\n(.*?)endstream', pdf_bytes, re.DOTALL)
    text = ""
    for s in streams:
        s = s.strip()
        decoded = False
        try:
            import base64
            a85 = s
            if not a85.endswith(b'~>'):
                a85 += b'~>'
            decompressed = zlib.decompress(base64.a85decode(a85, adobe=True))
            text += decompressed.decode('utf-8', errors='ignore')
            decoded = True
        except Exception:
            pass

        if not decoded:
            try:
                decompressed = zlib.decompress(s)
                text += decompressed.decode('utf-8', errors='ignore')
                decoded = True
            except Exception:
                pass

        if not decoded:
            text += s.decode('utf-8', errors='ignore')

    return text

@pytest.fixture
def complex_case():
    return {
        "case_id": "CASE-999",
        "filename": "top_secret.docx",
        "email_hash": "deadbeef1234",
        "subject": "Confidential IP: 192.168.1.100 and email admin@secret.org",
        "sender_address": "attacker@evil.com",
        "sender_domain": "evil.com",
        "probable_origin_ip": "2001:0db8:85a3:0000:0000:8a2e:0370:7334",
        "fraud_score": 95,
        "risk_level": "Critical",
        "verdict": "Malicious",
        "analyzer_results": {
            "fraud_score": {
                "scoring_version": "1.2"
            },
            "header_analysis": {
                "indicators": [
                    {"severity": "high", "explanation": "Failed SPF for attacker@evil.com from 192.168.1.100"}
                ]
            },
            "content_analysis": {
                "defanged_urls": [
                    "hxxps://admin:password123@evil.com/login.php?session=abc#token",
                    "http://10.0.0.1/malware.exe"
                ],
                "sanitized_text": "MY_PRIVATE_PASSWORD_123 SSN: 000-00-0000 BANK_ACCOUNT_999",
                "indicators": [
                    {"severity": "medium", "explanation": "credential request or password mentioned"}
                ]
            },
            "attachment_analysis": {
                "attachments": [
                    {"filename": "payload.exe", "size": 1024, "sha256": "abcd"}
                ]
            },
            "evidence_manifest": {
                "manifest_version": "1.0",
                "case_id": "CASE-999",
                "email_sha256": "deadbeef1234"
            }
        },
        "body_text": "Please click http://10.0.0.1/malware.exe and email me at victim@company.com",
        "body_html": "<p>Please click http://10.0.0.1/malware.exe</p>"
    }

def test_masking_does_not_mutate_original(complex_case):
    import copy
    original_copy = copy.deepcopy(complex_case)
    masked = mask_case_data(complex_case)
    assert complex_case == original_copy
    assert masked["analyzer_results"]["content_analysis"]["sanitized_text"] == "[OMITTED]"

def test_masking_off_preserves_data(complex_case):
    json_bytes = generate_json_report(complex_case, mask_data=False)
    text = json_bytes.decode('utf-8')
    assert "admin@secret.org" in text
    assert "192.168.1.100" in text
    assert "payload.exe" in text
    assert "top_secret.docx" in text
    assert "attacker@evil.com" in text
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" in text
    assert "password123" in text
    assert "credential request or password mentioned" in text
    # Evidence manifest should be present
    assert "evidence_manifest" in text
    assert "deadbeef1234" in text

def test_masking_json_report_leakage(complex_case):
    json_bytes = generate_json_report(complex_case, mask_data=True)
    text = json_bytes.decode('utf-8')

    # Sensitive data should NOT be present
    assert "admin@secret.org" not in text
    assert "192.168.1.100" not in text
    assert "payload.exe" not in text
    assert "top_secret.docx" not in text
    assert "attacker@evil.com" not in text
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" not in text
    assert "password123" not in text
    assert "session=abc" not in text
    assert "MY_PRIVATE_PASSWORD_123" not in text
    assert "000-00-0000" not in text
    assert "BANK_ACCOUNT_999" not in text

    # Valid indicator explanations must survive masking
    assert "credential request or password mentioned" in text

    # Non-sensitive structure should be preserved
    assert "CASE-999" in text
    assert "Critical" in text
    assert "Malicious" in text
    assert "1.2" in text

    # Original manifest must be omitted
    report = json.loads(text)
    assert report.get("evidence_manifest") is None

    # Disclaimers updated
    assert any("SENSITIVE DATA MASKING ENABLED" in d for d in report["disclaimers"])

def test_masking_html_report_leakage(complex_case):
    html_bytes = generate_html_report(complex_case, mask_data=True)
    text = html_bytes.decode('utf-8')

    assert "admin@secret.org" not in text
    assert "192.168.1.100" not in text
    assert "payload.exe" not in text
    assert "top_secret.docx" not in text
    assert "attacker@evil.com" not in text
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" not in text
    assert "password123" not in text
    assert "MY_PRIVATE_PASSWORD_123" not in text
    assert "000-00-0000" not in text
    assert "BANK_ACCOUNT_999" not in text

    # Valid indicator explanations must survive masking
    assert "credential request or password mentioned" in text

    assert "CASE-999" in text
    assert "SENSITIVE DATA MASKING ENABLED" in text

def test_masking_pdf_report_leakage(complex_case):
    # Prove extraction works on unmasked PDF
    unmasked_pdf = generate_pdf_report(complex_case, mask_data=False)
    unmasked_text = extract_pdf_text_streams(unmasked_pdf)
    assert "Forensic" in unmasked_text
    assert "admin@secret.org" in unmasked_text

    pdf_bytes = generate_pdf_report(complex_case, mask_data=True)

    # Deep PDF stream check
    pdf_text = extract_pdf_text_streams(pdf_bytes)
    assert "Forensic" in pdf_text
    assert "admin@secret.org" not in pdf_text
    assert "192.168.1.100" not in pdf_text
    assert "payload.exe" not in pdf_text
    assert "attacker@evil.com" not in pdf_text
    assert "2001:0db8:85a3:0000:0000:8a2e:0370:7334" not in pdf_text
    assert "password123" not in pdf_text
    assert "MY_PRIVATE_PASSWORD_123" not in pdf_text
    assert "000-00-0000" not in pdf_text
    assert "BANK_ACCOUNT_999" not in pdf_text

    # Valid indicator explanations must survive masking
    assert "credential request or password mentioned" in pdf_text

def test_app_analysis_export_path_with_masking():
    """Verify that checking the mask option in app.py reaches all three export generators."""
    from streamlit.testing.v1 import AppTest
    import os
    from modules.case_database import initialize_database
    import tempfile
    import json
    import unittest.mock

    fd, path = tempfile.mkstemp(suffix='.sqlite3')
    os.close(fd)
    old_db_path = os.environ.get('DB_PATH')
    os.environ['DB_PATH'] = path
    initialize_database(path)

    try:
        app_path = os.path.join(os.path.dirname(__file__), "..", "..", "app.py")
        fixture_path = os.path.join(os.path.dirname(__file__), "..", "fixtures", "synthetic_wallet_phishing.eml")

        with open(fixture_path, "rb") as f:
            file_bytes = f.read()

        import modules.report_generator as rg
        import modules.evidence_integrity as ei

        calls_json = []
        calls_html = []
        calls_pdf = []

        orig_json = rg.generate_json_report
        orig_html = rg.generate_html_report
        orig_pdf = rg.generate_pdf_report

        def spy_json(case, mask_data=False):
            calls_json.append((case, mask_data))
            return orig_json(case, mask_data)
        def spy_html(case, mask_data=False):
            calls_html.append((case, mask_data))
            return orig_html(case, mask_data)
        def spy_pdf(case, mask_data=False):
            calls_pdf.append((case, mask_data))
            return orig_pdf(case, mask_data)

        # Force manifest unavailable dynamically
        def spy_build(*args, **kwargs):
            return {} # Returning empty dict makes `if evidence_manifest:` evaluate to False

        with unittest.mock.patch('modules.report_generator.generate_json_report', side_effect=spy_json), \
             unittest.mock.patch('modules.report_generator.generate_html_report', side_effect=spy_html), \
             unittest.mock.patch('modules.report_generator.generate_pdf_report', side_effect=spy_pdf), \
             unittest.mock.patch('modules.evidence_integrity.build_evidence_manifest', side_effect=spy_build), \
             unittest.mock.patch('modules.geolocation.geolocate_ip', return_value={"country": "Mock Country", "city": "Mock City"}):

            at = AppTest.from_file(app_path, default_timeout=15).run()

            at.file_uploader[0].set_value(
                ("synthetic_wallet_phishing.eml", file_bytes, "message/rfc822")
            ).run()

            # Click the Analyze Email button (which has an emoji)
            analyze_btn = [b for b in at.button if "Analyze Email" in b.label]
            if analyze_btn:
                analyze_btn[0].click().run()

            assert not at.exception

            # Verify un-nesting: export controls should be visible even with unavailable manifest
            assert any("Export Reports" in str(getattr(m, 'value', '')) for m in at.markdown)

            # Find checkbox
            mask_cb = [c for c in at.checkbox if c.label == "Mask sensitive data in exports"]
            assert len(mask_cb) == 1

            # Check it and rerun
            mask_cb[0].set_value(True).run()

            # Ensure download buttons still exist
            dls = [b for b in at.download_button if "Report" in b.label]
            assert len(dls) == 3

            # Verify the generators were called with mask_data=True
            assert len(calls_json) >= 1
            assert calls_json[-1][1] is True
            assert len(calls_html) >= 1
            assert calls_html[-1][1] is True
            assert len(calls_pdf) >= 1
            assert calls_pdf[-1][1] is True

            # Inspect captured JSON output
            captured_case = calls_json[-1][0]
            masked_json = json.loads(orig_json(captured_case, mask_data=True).decode('utf-8'))

            # Ensure expected scores and masked fields are correct in the final output
            assert masked_json["filename"].startswith("[FILE")
            assert masked_json["filename"] != "synthetic_wallet_phishing.eml"

            actual_analysis_score = captured_case.get("analyzer_results", {}).get("fraud_score", {}).get("final_score")
            assert actual_analysis_score is not None and actual_analysis_score > 0, "Expected a nonzero analysis score for this sample"
            assert masked_json["fraud_score"] == actual_analysis_score, "Exported JSON must exactly match the nonzero Analysis score"

    finally:
        if old_db_path:
            os.environ['DB_PATH'] = old_db_path
        else:
            del os.environ['DB_PATH']
        os.unlink(path)

def test_deterministic_repeated_indicator_masking(complex_case):
    json_bytes = generate_json_report(complex_case, mask_data=True)
    report = json.loads(json_bytes)

    # Check that the same IP masked in different places yields the same placeholder
    subject_val = report["subject"]
    header_val = report["key_indicators"][0]["explanation"]

    # Subject was explicitly omitted!
    assert subject_val == "[OMITTED]"

    # The header is "Failed SPF for attacker@evil.com from 192.168.1.100"
    assert "[EMAIL-" in header_val
    assert "[IPV4-" in header_val

    urls = report["defanged_urls"]
    assert "evil.com/[MASKED_PATH" in urls[0] # domain preserved, path masked
    assert "http://[IPV4-" in urls[1] # IP in URL domain is masked

def test_masking_ipv6_variants():
    case = {
        'case_id': 'V6',
        'analyzer_results': {
            'ips': [
                '::1',
                '2001:db8::',
                '2001:db8:85a3::8a2e:370:7334',
                '::ffff:192.168.1.1'
            ]
        }
    }
    from modules.data_masking import mask_case_data
    masked = mask_case_data(case)
    ips = masked['analyzer_results']['ips']
    assert all('[IPV6-' in ip for ip in ips)
    assert '::1' not in ips
    assert '2001:db8::' not in ips

def test_masking_ipv6_bare():
    case = {
        'case_id': 'V6BARE',
        'analyzer_results': {
            'ips': [
                '::'
            ]
        }
    }
    from modules.data_masking import mask_case_data
    masked = mask_case_data(case)
    ips = masked['analyzer_results']['ips']
    assert len(ips) == 1
    assert '[IPV6-' in ips[0]
    assert '::' not in ips[0]

def test_masking_preserves_assessment_structure():
    # Reproduction from prompt
    case = {
      "filename": "a",
      "verdict": "Malicious",
      "risk_level": "Moderate",
      "analyzer_results": {
        "fraud_score": {
          "component_scores": {"header_risk": 5, "attachment_risk": 50},
          "scoring_version": "1.0"
        },
        "header_analysis": {
            "indicators": [
                {"explanation": "Found a attached"}
            ]
        }
      }
    }
    from modules.data_masking import mask_case_data
    masked = mask_case_data(case)

    # Verdict, risk_level, scoring_version, and component_scores should remain completely unchanged
    assert masked["verdict"] == "Malicious"
    assert masked["risk_level"] == "Moderate"
    assert masked["analyzer_results"]["fraud_score"]["component_scores"]["header_risk"] == 5
    assert masked["analyzer_results"]["fraud_score"]["component_scores"]["attachment_risk"] == 50
    assert masked["analyzer_results"]["fraud_score"]["scoring_version"] == "1.0"

    # The filename "a" should be masked in structural field
    assert "[FILE-" in masked["filename"]
    # The filename "a" should ALSO be masked in descriptive field
    explanation = masked["analyzer_results"]["header_analysis"]["indicators"][0]["explanation"]
    assert "[FILE-" in explanation
    assert "Found [FILE-" in explanation
    assert " a " not in explanation

def test_masking_ipv6_url_credentials():
    case = {
        'case_id': 'V6URL',
        'analyzer_results': {
            'content_analysis': {
                'defanged_urls': [
                    'http://user:pass@[2001:db8::1]:8080/path?q=1'
                ]
            }
        }
    }
    from modules.data_masking import mask_case_data
    masked = mask_case_data(case)
    url = masked['analyzer_results']['content_analysis']['defanged_urls'][0]
    assert 'user:pass' not in url
    assert '2001:db8::1' not in url
    assert '/[MASKED_PATH-' in url
    assert url.startswith('http://[IPV6-') or url.startswith('http://[[IPV6-') # depending on if brackets kept

def test_masking_repeated_filenames_in_text():
    case = {
        'case_id': 'FILE',
        'filename': 'invoice.pdf',
        'analyzer_results': {
            'attachment_analysis': {
                'attachments': [
                    {'filename': 'payload.exe'}
                ]
            },
            'header_analysis': {
                'indicators': [
                    {'explanation': 'Found malicious payload.exe inside invoice.pdf attached'}
                ]
            }
        }
    }
    from modules.data_masking import mask_case_data
    masked = mask_case_data(case)
    explanation = masked['analyzer_results']['header_analysis']['indicators'][0]['explanation']
    assert 'payload.exe' not in explanation
    assert 'invoice.pdf' not in explanation
    assert '[FILE-' in explanation

def test_app_current_case_data_schema():
    # Matches the exact dictionary structure built in app.py
    current_case_data = {
        'case_id': 'Unsaved Analysis',
        'filename': 'demo_sample.eml',
        'email_hash': '1234abcd',
        'subject': 'Test Subject',
        'sender_address': 'test@example.com',
        'sender_domain': 'example.com',
        'probable_origin_ip': '10.0.0.1',
        'analyzer_results': {
            'header_analysis': {'indicators': []},
            'content_analysis': {'defanged_urls': []},
            'geo_result': {'available': True, 'location': {'country': 'US'}},
            'domain_result': {'available': True, 'domain_age_days': 100},
            'fraud_score': {'final_score': 50, 'scoring_version': '1.0'},
            'attachment_analysis': {'attachments': []},
            'evidence_manifest': {'manifest_version': '1.0'}
        },
        'risk_level': 'Moderate',
        'verdict': 'Suspicious',
        'confidence': 'High'
    }
    json_bytes = generate_json_report(current_case_data, mask_data=False)
    report = json.loads(json_bytes.decode('utf-8'))

    assert report['filename'] == 'demo_sample.eml'
    assert report['sender'] == 'test@example.com'
    assert report['probable_origin_ip'] == '10.0.0.1'
    assert report['verdict'] == 'Suspicious'
    assert report.get('scoring_version') == '1.0'
    assert report['geolocation']['country'] == 'US'
    assert report['domain_intelligence']['domain_age_days'] == 100


def test_app_analysis_export_score_preservation():
    """Ensure the numeric final_score from the UI's analyzer_results is exactly
    the score exported to JSON, HTML, and PDF, regardless of masking.
    Checking that the key merely exists is insufficient."""
    current_case_data = {
        'case_id': 'Unsaved Analysis',
        'filename': 'phishing.eml',
        'email_hash': 'abcdef123456',
        'subject': 'Urgent',
        'sender_address': 'attacker@evil.com',
        'sender_domain': 'evil.com',
        'probable_origin_ip': '1.2.3.4',
        'analyzer_results': {
            'header_analysis': {'indicators': []},
            'content_analysis': {'defanged_urls': []},
            'geo_result': {},
            'domain_result': {},
            'fraud_score': {
                'final_score': 85,
                'scoring_version': '1.1',
                'component_scores': {'header_risk': 35, 'content_risk': 20}
            },
            'attachment_analysis': {'attachments': []},
            'evidence_manifest': {}
        },
        'risk_level': 'High',
        'verdict': 'Likely Malicious',
        'confidence': 'High'
    }

    for mask in (False, True):
        # JSON
        json_bytes = generate_json_report(current_case_data, mask_data=mask)
        report = json.loads(json_bytes.decode('utf-8'))
        assert report['fraud_score'] == 85, f"JSON mask={mask} wrong score"

        # HTML
        html_bytes = generate_html_report(current_case_data, mask_data=mask).decode()
        assert "<th>Fraud Score</th><td>85</td>" in html_bytes, f"HTML mask={mask} wrong score"

        # PDF
        pdf_text = extract_pdf_text_streams(generate_pdf_report(current_case_data, mask_data=mask))
        assert "(Fraud Score:) Tj" in pdf_text, f"PDF mask={mask} missing label"
        assert "( 85) Tj" in pdf_text, f"PDF mask={mask} missing value"



# ---------------------------------------------------------------------------
# Regression: sender field mapping and display label fixes
# ---------------------------------------------------------------------------

def _make_case_with_sender(sender_address, origin_ip=None, case_id=None):
    """Build a minimal case_data dict matching the app.py current_case_data schema."""
    return {
        "case_id": case_id,
        "filename": "test.eml",
        "email_hash": "aabbccdd",
        "subject": "Hello",
        "sender_address": sender_address,
        "sender_domain": "company.example" if sender_address else "",
        "probable_origin_ip": origin_ip,
        "analyzer_results": {
            "header_analysis": {"indicators": []},
            "content_analysis": {"defanged_urls": [], "original_urls": []},
            "geo_result": {},
            "domain_result": {},
            "fraud_score": {"scoring_version": "1.0", "component_scores": {}},
            "attachment_analysis": {"attachments": []},
            "evidence_manifest": {},
        },
        "risk_level": "Low",
        "verdict": "Legitimate",
        "confidence": "High",
    }


def test_sender_from_from_header_in_all_report_formats():
    """When sender_address is populated from the From header, all three export
    formats must include it — not 'N/A'."""
    case = _make_case_with_sender("alex@company.example")
    # JSON
    report = json.loads(generate_json_report(case).decode())
    assert report["sender"] == "alex@company.example", f"JSON sender wrong: {report['sender']}"

    # HTML
    html_bytes = generate_html_report(case).decode()
    assert "alex@company.example" in html_bytes

    # PDF (text stream extraction)
    pdf_text = extract_pdf_text_streams(generate_pdf_report(case))
    assert "alex@company.example" in pdf_text


def test_missing_from_header_produces_na():
    """When sender_address is absent (empty string / None), reports must show
    'N/A', not crash or leak a raw Python 'None'."""
    for empty_val in ("", None):
        case = _make_case_with_sender(empty_val)
        report = json.loads(generate_json_report(case).decode())
        assert report["sender"] == "N/A", f"Expected N/A for sender, got: {report['sender']}"

        html_bytes = generate_html_report(case).decode()
        # Must not contain literal "None" as a sender value
        assert "<th>Sender</th><td>None</td>" not in html_bytes


def test_masked_report_replaces_sender_with_placeholder():
    """Masking must replace the sender email address in all report formats.
    The sender_address field itself must be replaced; sender_domain is a
    separate field handled by the existing domain masking path."""
    case = _make_case_with_sender("alex@company.example")
    # JSON
    report = json.loads(generate_json_report(case, mask_data=True).decode())
    assert "alex@company.example" not in json.dumps(report)
    # sender field must be a placeholder, not the real address
    assert report["sender"] != "alex@company.example"
    assert "@" not in report["sender"] or "[EMAIL-" in report["sender"]

    # HTML
    html_bytes = generate_html_report(case, mask_data=True).decode()
    assert "alex@company.example" not in html_bytes

    # PDF
    pdf_text = extract_pdf_text_streams(generate_pdf_report(case, mask_data=True))
    assert "alex@company.example" not in pdf_text


def test_display_labels_origin_ip_unavailable():
    """HTML/PDF show 'Unavailable' when probable_origin_ip is absent.
    JSON substitutes missing with 'N/A' but preserves explicit None or empty string."""
    scenarios = [
        ("missing", "N/A"),
        (None, None),
        ("", "")
    ]
    for val, expected_json in scenarios:
        case = _make_case_with_sender("alex@company.example")
        if val == "missing":
            case.pop("probable_origin_ip", None)
        else:
            case["probable_origin_ip"] = val

        # JSON: defaults or raw value
        report = json.loads(generate_json_report(case).decode())
        assert report["probable_origin_ip"] == expected_json, (
            f"JSON mismatch for {val!r}: expected {expected_json!r}, got {report['probable_origin_ip']!r}"
        )

        # HTML: display fallback applied at render time
        html_bytes = generate_html_report(case).decode()
        assert "<th>Origin IP</th><td>Unavailable</td>" in html_bytes

        # PDF: display fallback applied at render time
        pdf_text = extract_pdf_text_streams(generate_pdf_report(case))
        assert "Unavailable" in pdf_text


def test_display_labels_case_id_not_assigned():
    """HTML/PDF show 'Not assigned' when case_id is None.
    JSON substitutes missing with 'N/A' but preserves explicit None or empty string."""
    scenarios = [
        ("missing", "N/A"),
        (None, None),
        ("", "")
    ]
    for val, expected_json in scenarios:
        case = _make_case_with_sender("alex@company.example")
        if val == "missing":
            case.pop("case_id", None)
        else:
            case["case_id"] = val

        # JSON: defaults or raw value
        report = json.loads(generate_json_report(case).decode())
        assert report["case_id"] == expected_json, (
            f"JSON mismatch for {val!r}: expected {expected_json!r}, got {report['case_id']!r}"
        )

        # HTML: display fallback applied at render time
        html_bytes = generate_html_report(case).decode()
        assert "<th>Case ID</th><td>Not assigned</td>" in html_bytes

        # PDF: display fallback applied at render time
        pdf_text = extract_pdf_text_streams(generate_pdf_report(case))
        assert "Not assigned" in pdf_text


def test_display_label_email_hash_sha256():
    """General information table must label the hash 'Original Email SHA-256'."""
    case = _make_case_with_sender("alex@company.example")
    html_bytes = generate_html_report(case).decode()
    assert "Original Email SHA-256" in html_bytes

    pdf_text = extract_pdf_text_streams(generate_pdf_report(case))
    assert "Original Email SHA-256" in pdf_text
