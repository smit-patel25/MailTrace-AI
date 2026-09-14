import copy
import re
import hashlib
import ipaddress
from urllib.parse import urlparse

def _hash_val(val: str, prefix: str) -> str:
    h = hashlib.sha256(val.encode('utf-8', errors='ignore')).hexdigest()[:8].upper()
    return f"[{prefix}-{h}]"

# Regexes
EMAIL_RE = re.compile(r'\b[A-Za-z0-9_.+-]+@[A-Za-z0-9-]+\.[A-Za-z0-9-.]+\b')
URL_RE = re.compile(r'(?i)\b(?:https?|hxxps?|ftp|sftp)://[^\s\'"<>]+')
IPV4_RE = re.compile(r'(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)')
IPV6_RE = re.compile(r'(?:[a-fA-F0-9]*:){2,}[a-fA-F0-9:.]*')

SCHEMA_KEYS = {
    'case_id', 'generated_timestamp', 'filename', 'source_filename', 'email_hash',
    'subject', 'sender', 'sender_address', 'sender_domain', 'probable_origin_ip',
    'campaign_id', 'fraud_score', 'corroboration_bonus', 'risk_level', 'verdict',
    'confidence', 'component_scores', 'scoring_version', 'defanged_urls',
    'key_indicators', 'auth_status', 'domain_intelligence', 'geolocation',
    'attachments', 'disclaimers', 'analyzer_results', 'header_analysis',
    'content_analysis', 'geo_result', 'domain_result', 'attachment_analysis',
    'evidence_manifest', 'ips', 'indicators', 'country', 'location', 'proxy',
    'registrar', 'domain_age_days', 'creation_date', 'size', 'human_size',
    'sha256', 'reasons', 'manifest_version', 'email_sha256', 'integrity_status',
    'analysis_timestamp', 'manifest_sha256', 'body_text', 'body_html',
    'analysis_text', 'body', 'available', 'content_type', 'final_score',
    'reported_auth_statuses', 'severity', 'explanation', 'error'
}

def is_valid_ip(val: str) -> bool:
    try:
        ipaddress.ip_address(val)
        return True
    except ValueError:
        return False

class DataMasker:
    def __init__(self, filenames=None):
        self.cache = {}
        self.filenames = filenames or set()

    def mask_text(self, text: str, mask_filenames: bool = False) -> str:
        if not isinstance(text, str):
            return text

        if mask_filenames:
            # Mask pre-collected filenames first in any free text using a single-pass longest-match regex
            valid_fnames = [f for f in self.filenames if f and f != "N/A"]
            if valid_fnames:
                sorted_fnames = sorted(valid_fnames, key=len, reverse=True)
                # Ensure we pre-populate cache deterministically
                for fname in sorted_fnames:
                    if fname not in self.cache:
                        self.cache[fname] = _hash_val(fname, "FILE")

                pattern = "|".join(map(re.escape, sorted_fnames))
                def repl_fname(m):
                    return self.cache[m.group(0)]
                text = re.sub(pattern, repl_fname, text)

        # Mask URLs
        def repl_url(m):
            val = m.group(0)
            if val not in self.cache:
                try:
                    is_defanged = False
                    parse_val = val
                    if val.lower().startswith('hxxp'):
                        is_defanged = True
                        parse_val = 'http' + val[4:]

                    parsed = urlparse(parse_val)
                    potential_ip = parsed.hostname

                    if potential_ip and is_valid_ip(potential_ip):
                        if potential_ip not in self.cache:
                            t = "IPV6" if ":" in potential_ip else "IPV4"
                            self.cache[potential_ip] = _hash_val(potential_ip, t)
                        # Replace the IP specifically, leaving port or other netloc components intact
                        # parsed.netloc includes userinfo, host, and port.
                        # We just rebuild netloc with masked hostname and original port if it exists.
                        masked_host = self.cache[potential_ip]
                        # If it was a bracketed IPv6, parsed.hostname strips brackets, but netloc keeps them.
                        if f"[{potential_ip}]" in parsed.netloc:
                            new_netloc = parsed.netloc.replace(f"[{potential_ip}]", masked_host)
                        else:
                            new_netloc = parsed.netloc.replace(potential_ip, masked_host)

                        # Strip userinfo from netloc since it contains sensitive credentials
                        if '@' in new_netloc:
                            new_netloc = new_netloc.split('@', 1)[-1]
                        netloc = new_netloc
                    else:
                        # Even if not an IP, strip credentials
                        netloc = parsed.netloc
                        if '@' in netloc:
                            netloc = netloc.split('@', 1)[-1]

                    masked_url = f"{parsed.scheme}://{netloc}"
                    if parsed.path or parsed.query or parsed.fragment:
                        path_hash = hashlib.sha256(f"{parsed.path}{parsed.query}{parsed.fragment}".encode()).hexdigest()[:8].upper()
                        masked_url += f"/[MASKED_PATH-{path_hash}]"

                    if is_defanged:
                        masked_url = masked_url.replace('http', 'hxxp', 1)

                    self.cache[val] = masked_url
                except Exception:
                    self.cache[val] = _hash_val(val, "URL")
            return self.cache[val]

        text = URL_RE.sub(repl_url, text)

        # Mask Emails
        def repl_email(m):
            val = m.group(0)
            if val not in self.cache:
                self.cache[val] = _hash_val(val, "EMAIL")
            return self.cache[val]
        text = EMAIL_RE.sub(repl_email, text)


        # Mask IPv6 FIRST to prevent IPv4-mapped addresses getting split
        def repl_ipv6(m):
            val = m.group(0)
            suffix = ''
            # Right-strip trailing punctuation like . or : to find longest valid IP
            while val and not is_valid_ip(val):
                suffix = val[-1] + suffix
                val = val[:-1]

            if not val or not is_valid_ip(val):
                return m.group(0)

            if val not in self.cache:
                self.cache[val] = _hash_val(val, "IPV6")
            return self.cache[val] + suffix

        text = IPV6_RE.sub(repl_ipv6, text)

        # Mask IPv4
        def repl_ipv4(m):
            val = m.group(0)
            if not is_valid_ip(val):
                return val
            if val not in self.cache:
                self.cache[val] = _hash_val(val, "IPV4")
            return self.cache[val]
        text = IPV4_RE.sub(repl_ipv4, text)

        return text

    def mask_dict(self, d: dict) -> dict:
        result = {}
        for k, v in d.items():
            if isinstance(k, str) and k in SCHEMA_KEYS:
                masked_k = k
            else:
                masked_k = self.walk(k, mask_filenames=False) if isinstance(k, str) else k

            if k in ('subject', 'body_text', 'body_html', 'analysis_text', 'body'):
                result[masked_k] = "[OMITTED]"
            elif k in ('filename', 'source_filename', 'sender', 'sender_address', 'sender_domain', 'probable_origin_ip'):
                if isinstance(v, str) and v and v != "N/A":
                    if k in ('filename', 'source_filename'):
                        result[masked_k] = _hash_val(v, "FILE")
                    else:
                        result[masked_k] = self.walk(v, mask_filenames=False)
                else:
                    result[masked_k] = v
            else:
                do_mask_fnames = k in ('explanation', 'reasons', 'defects', 'warnings', 'error', 'message')
                result[masked_k] = self.walk(v, mask_filenames=do_mask_fnames)
        return result

    def walk(self, obj, mask_filenames: bool = False):
        if isinstance(obj, dict):
            return self.mask_dict(obj)
        elif isinstance(obj, (list, tuple)):
            return type(obj)(self.walk(x, mask_filenames=mask_filenames) for x in obj)
        elif isinstance(obj, str):
            return self.mask_text(obj, mask_filenames=mask_filenames)
        else:
            return obj

def mask_case_data(case_data: dict) -> dict:
    """Returns a deep copy of case_data with sensitive fields and PII masked."""
    if not case_data:
        return case_data

    filenames = set()
    def collect_filenames(obj):
        if isinstance(obj, dict):
            for k, v in obj.items():
                if k in ('filename', 'source_filename') and isinstance(v, str) and v != "N/A":
                    filenames.add(v)
                collect_filenames(v)
        elif isinstance(obj, (list, tuple)):
            for item in obj:
                collect_filenames(item)

    collect_filenames(case_data)
    masker = DataMasker(filenames=filenames)
    return masker.walk(copy.deepcopy(case_data))
