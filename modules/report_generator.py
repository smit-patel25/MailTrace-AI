import json
import io
import uuid
import html
from datetime import datetime, timezone
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet

def generate_report_id():
    return datetime.now(timezone.utc).strftime("REPORT-%Y%m%d-") + uuid.uuid4().hex[:4].upper()

def extract_safe_data(case_data):
    timestamp = datetime.now(timezone.utc).isoformat()
    results = case_data.get('analyzer_results', {})
    header_res = results.get('header_analysis', {})
    content_res = results.get('content_analysis', {})
    geo_res = results.get('geo_result', {})
    domain_res = results.get('domain_result', {})
    f_score = results.get('fraud_score', {})
    
    safe_data = {
        "report_title": "MailTrace Forensic Analysis Report",
        "report_id": generate_report_id(),
        "case_id": case_data.get("case_id", "N/A"),
        "generated_timestamp": timestamp,
        "filename": case_data.get("filename", "N/A"),
        "email_hash": case_data.get("email_hash", "N/A"),
        "subject": case_data.get("subject", "N/A"),
        "sender": case_data.get("sender_address", "N/A"),
        "sender_domain": case_data.get("sender_domain", "N/A"),
        "probable_origin_ip": case_data.get("probable_origin_ip", "N/A"),
        "campaign_id": case_data.get("campaign_id", "N/A"),
        "fraud_score": case_data.get("fraud_score", 0),
        "corroboration_bonus": f_score.get("corroboration_bonus", 0),
        "risk_level": case_data.get("risk_level", "Unknown"),
        "verdict": case_data.get("verdict", "Unknown"),
        "confidence": case_data.get("confidence", "Unknown"),
        "component_scores": f_score.get("component_scores", {}),
        "defanged_urls": content_res.get("defanged_urls", []),
        "key_indicators": [],
        "auth_status": header_res.get("reported_auth_statuses", {}),
        "domain_intelligence": {},
        "geolocation": {},
        "disclaimers": [
            "Geolocation represents estimated infrastructure location.",
            "Authentication header values may be reported rather than independently verified.",
            "Campaign correlation is not proof of attacker identity.",
            "Assessment is for investigative support."
        ]
    }
    
    if "indicators" in header_res: safe_data["key_indicators"].extend(header_res["indicators"])
    if "indicators" in content_res: safe_data["key_indicators"].extend(content_res["indicators"])
    
    if domain_res and domain_res.get("available"):
        safe_data["domain_intelligence"] = {
            "registrar": domain_res.get("registrar"),
            "domain_age_days": domain_res.get("domain_age_days"),
            "creation_date": domain_res.get("creation_date")
        }
        
    if geo_res and geo_res.get("available"):
        loc = geo_res.get("location", {})
        safe_data["geolocation"] = {
            "country": loc.get("country"),
            "city": loc.get("city"),
            "isp": loc.get("isp"),
            "proxy": geo_res.get("proxy", False)
        }
        
    return safe_data

def generate_json_report(case_data) -> bytes:
    data = extract_safe_data(case_data)
    return json.dumps(data, indent=2).encode('utf-8')

def generate_html_report(case_data) -> bytes:
    data = extract_safe_data(case_data)
    
    html_content = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{html.escape(data['report_title'])}</title>
<style>
body {{ font-family: Arial, sans-serif; margin: 40px; color: #333; }}
h1, h2, h3 {{ color: #2c3e50; }}
.disclaimer {{ background-color: #f9f9f9; padding: 10px; border-left: 4px solid #e74c3c; margin-bottom: 20px; }}
table {{ border-collapse: collapse; width: 100%; max-width: 800px; margin-bottom: 20px; }}
th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
th {{ background-color: #f2f2f2; width: 30%; }}
.indicator {{ margin-bottom: 5px; }}
</style>
</head>
<body>
<h1>{html.escape(data['report_title'])}</h1>
<div class="disclaimer">
    <strong>Disclaimers:</strong>
    <ul>
"""
    for d in data['disclaimers']:
        html_content += f"<li>{html.escape(d)}</li>"
        
    html_content += f"""
    </ul>
</div>
<h2>General Information</h2>
<table>
<tr><th>Report ID</th><td>{html.escape(data['report_id'])}</td></tr>
<tr><th>Case ID</th><td>{html.escape(str(data['case_id']))}</td></tr>
<tr><th>Generated At (UTC)</th><td>{html.escape(data['generated_timestamp'])}</td></tr>
<tr><th>Uploaded File</th><td>{html.escape(str(data['filename']))}</td></tr>
<tr><th>SHA-256 Hash</th><td>{html.escape(str(data['email_hash']))}</td></tr>
<tr><th>Subject</th><td>{html.escape(str(data['subject']))}</td></tr>
<tr><th>Sender</th><td>{html.escape(str(data['sender']))}</td></tr>
<tr><th>Sender Domain</th><td>{html.escape(str(data['sender_domain']))}</td></tr>
<tr><th>Origin IP</th><td>{html.escape(str(data['probable_origin_ip']))}</td></tr>
<tr><th>Campaign ID</th><td>{html.escape(str(data['campaign_id']))}</td></tr>
</table>

<h2>Threat Assessment</h2>
<table>
<tr><th>Fraud Score</th><td>{html.escape(str(data['fraud_score']))}</td></tr>
"""
    if data.get('corroboration_bonus', 0) > 0:
        html_content += f"<tr><th>Corroboration Bonus</th><td>+{html.escape(str(data['corroboration_bonus']))}</td></tr>\n"
        
    html_content += f"""<tr><th>Risk Level</th><td>{html.escape(str(data['risk_level']))}</td></tr>
<tr><th>Verdict</th><td>{html.escape(str(data['verdict']))}</td></tr>
<tr><th>Confidence</th><td>{html.escape(str(data['confidence']))}</td></tr>
</table>

"""
    if data['key_indicators']:
        html_content += "<h2>Key Indicators</h2><ul>"
        for ind in data['key_indicators']:
            sev = str(ind.get('severity', 'info')).upper()
            msg = html.escape(str(ind.get('explanation', '')))
            html_content += f"<li class='indicator'><strong>[{sev}]</strong> {msg}</li>"
        html_content += "</ul>"
        
    if data['defanged_urls']:
        html_content += "<h2>Defanged URLs</h2><ul>"
        for url in data['defanged_urls']:
            html_content += f"<li>{html.escape(str(url))}</li>"
        html_content += "</ul>"
        
    html_content += "</body></html>"
    return html_content.encode('utf-8')

def generate_pdf_report(case_data) -> bytes:
    data = extract_safe_data(case_data)
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    
    body_style = styles['Normal']
    body_style.wordWrap = 'CJK'
    
    title_style = styles['Title']
    heading_style = styles['Heading2']
    
    elements = []
    
    elements.append(Paragraph(data['report_title'], title_style))
    elements.append(Spacer(1, 12))
    
    for d in data['disclaimers']:
        elements.append(Paragraph(f"<i>Disclaimer: {html.escape(d)}</i>", body_style))
    elements.append(Spacer(1, 12))
    
    elements.append(Paragraph("General Information", heading_style))
    info_lines = [
        f"<b>Report ID:</b> {html.escape(data['report_id'])}",
        f"<b>Case ID:</b> {html.escape(str(data['case_id']))}",
        f"<b>Generated At (UTC):</b> {html.escape(data['generated_timestamp'])}",
        f"<b>Uploaded File:</b> {html.escape(str(data['filename']))}",
        f"<b>SHA-256 Hash:</b> {html.escape(str(data['email_hash']))}",
        f"<b>Subject:</b> {html.escape(str(data['subject']))}",
        f"<b>Sender:</b> {html.escape(str(data['sender']))}",
        f"<b>Origin IP:</b> {html.escape(str(data['probable_origin_ip']))}",
        f"<b>Campaign ID:</b> {html.escape(str(data['campaign_id']))}"
    ]
    for line in info_lines:
        elements.append(Paragraph(line, body_style))
    elements.append(Spacer(1, 12))
    
    elements.append(Paragraph("Threat Assessment", heading_style))
    assess_lines = [
        f"<b>Fraud Score:</b> {data['fraud_score']}"
    ]
    if data.get('corroboration_bonus', 0) > 0:
        assess_lines.append(f"<b>Corroboration Bonus:</b> +{data['corroboration_bonus']}")
        
    assess_lines.extend([
        f"<b>Risk Level:</b> {data['risk_level']}",
        f"<b>Verdict:</b> {data['verdict']}",
    ])
    for line in assess_lines:
        elements.append(Paragraph(line, body_style))
    elements.append(Spacer(1, 12))
    
    if data['key_indicators']:
        elements.append(Paragraph("Key Indicators", heading_style))
        for ind in data['key_indicators']:
            sev = str(ind.get('severity', 'info')).upper()
            msg = html.escape(str(ind.get('explanation', '')))
            elements.append(Paragraph(f"<b>[{sev}]</b> {msg}", body_style))
        elements.append(Spacer(1, 12))
        
    if data['defanged_urls']:
        elements.append(Paragraph("Defanged URLs", heading_style))
        for url in data['defanged_urls']:
            elements.append(Paragraph(html.escape(str(url)), body_style))
            
    doc.build(elements)
    pdf_bytes = buffer.getvalue()
    buffer.close()
    return pdf_bytes
