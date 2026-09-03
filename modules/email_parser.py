import email
from email import policy
from email.parser import BytesParser
from bs4 import BeautifulSoup

def _extract_visible_html_text(html_content: str) -> str:
    if not html_content:
        return ""
    try:
        soup = BeautifulSoup(html_content, 'html.parser')
        for tag in soup(["script", "style", "iframe", "object", "embed", "form"]):
            tag.decompose()
        return soup.get_text(separator=' ', strip=True)
    except Exception:
        return ""


def parse_eml_bytes(raw_email: bytes) -> dict:
    """
    Parses raw email bytes into a structured dictionary.
    Handles multipart emails, character encodings, and missing headers.
    """
    try:
        msg = BytesParser(policy=policy.default).parsebytes(raw_email)
    except Exception as e:
        # Return a dict with defect if it completely fails to parse
        return {"defects": [f"Fatal parsing error: {e}"]}

    parsed_data = {
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
        "defects": [str(d) for d in msg.defects]
    }

    if msg.is_multipart():
        for part in msg.walk():
            # Skip multipart containers
            if part.get_content_type().startswith("multipart/"):
                continue
                
            content_disposition = part.get_content_disposition()
            
            # If it's an attachment
            if content_disposition == "attachment":
                parsed_data["attachments"].append({
                    "filename": part.get_filename() or "unknown",
                    "content_type": part.get_content_type(),
                    "size": len(part.get_payload(decode=True) or b"")
                })
            else:
                # Text/HTML parts
                try:
                    payload = part.get_content()
                    if part.get_content_type() == "text/plain":
                        parsed_data["body_plain"] += str(payload)
                    elif part.get_content_type() == "text/html":
                        parsed_data["body_html"] += str(payload)
                except Exception as e:
                    parsed_data["defects"].append(f"Error decoding body part: {e}")
                    raw_payload = part.get_payload(decode=True)
                    if raw_payload:
                        fallback_str = raw_payload.decode('utf-8', errors='replace')
                        if part.get_content_type() == "text/plain":
                            parsed_data["body_plain"] += fallback_str
                        elif part.get_content_type() == "text/html":
                            parsed_data["body_html"] += fallback_str
    else:
        try:
            payload = msg.get_content()
            if msg.get_content_type() == "text/plain":
                parsed_data["body_plain"] = str(payload)
            elif msg.get_content_type() == "text/html":
                parsed_data["body_html"] = str(payload)
        except Exception as e:
            parsed_data["defects"].append(f"Error decoding body: {e}")
            raw_payload = msg.get_payload(decode=True)
            if raw_payload:
                fallback_str = raw_payload.decode('utf-8', errors='replace')
                if msg.get_content_type() == "text/plain":
                    parsed_data["body_plain"] = fallback_str
                elif msg.get_content_type() == "text/html":
                    parsed_data["body_html"] = fallback_str

    if parsed_data["body_plain"].strip():
        parsed_data["analysis_text"] = parsed_data["body_plain"]
        parsed_data["used_html_fallback"] = False
    elif parsed_data["body_html"].strip():
        parsed_data["analysis_text"] = _extract_visible_html_text(parsed_data["body_html"])
        parsed_data["used_html_fallback"] = True
    else:
        parsed_data["analysis_text"] = ""
        parsed_data["used_html_fallback"] = False

    return parsed_data
