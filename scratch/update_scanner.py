import re

with open("backend/app/scanner.py", "r") as f:
    text = f.read()

helper = """
def generate_analysis_id(msg: EmailMessage, raw_bytes: Optional[bytes] = None, raw_text: Optional[str] = None, subject: Optional[str] = None, sender: Optional[str] = None, headers_text: Optional[str] = None, body_text: Optional[str] = None) -> str:
    message_id = msg.get("Message-ID")
    if message_id:
        base_str = f"MSGID:{message_id.strip()}"
    else:
        raw_payload = raw_bytes if raw_bytes else (raw_text.encode('utf-8', errors='ignore') if raw_text else b"")
        if not raw_payload:
            base_str = f"FALLBACK:{subject}:{sender}:{headers_text}:{body_text}"
        else:
            base_str = f"RAW:{hashlib.sha256(raw_payload).hexdigest()}"
    return hashlib.sha256(base_str.encode('utf-8')).hexdigest()

def get_parsed_message(raw_bytes=None, raw_text=None, subject=None, sender=None, recipient=None, headers_text=None, body_text=None) -> EmailMessage:
    if raw_bytes or raw_text:
        return parse_raw_message(raw_bytes=raw_bytes, raw_text=raw_text)
    else:
        msg = EmailMessage()
        if sender: msg["From"] = sender
        if recipient: msg["To"] = recipient
        if subject: msg["Subject"] = subject
        if headers_text:
            for line in headers_text.strip().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    msg[k.strip()] = v.strip()
        msg.set_content(body_text or "")
        return msg
"""

if "def generate_analysis_id" not in text:
    text = text.replace("def scan_email(", helper + "\ndef scan_email(")

scan_email_old = """def scan_email(
    raw_bytes: Optional[bytes] = None,
    raw_text: Optional[str] = None,
    subject: Optional[str] = None,
    sender: Optional[str] = None,
    recipient: Optional[str] = None,
    headers_text: Optional[str] = None,
    body_text: Optional[str] = None
) -> FullAnalysisResult:
    \"\"\"Main scanning pipeline.\"\"\"
    analysis_id = str(hashlib.md5(f"{datetime.now()}{subject}{sender}".encode()).hexdigest())
    timestamp = datetime.now(timezone.utc).isoformat()

    if raw_bytes or raw_text:
        msg = parse_raw_message(raw_bytes=raw_bytes, raw_text=raw_text)
    else:
        msg = EmailMessage()
        if sender: msg["From"] = sender
        if recipient: msg["To"] = recipient
        if subject: msg["Subject"] = subject
        if headers_text:
            for line in headers_text.strip().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    msg[k.strip()] = v.strip()
        msg.set_content(body_text or "")"""

scan_email_new = """def scan_email(
    raw_bytes: Optional[bytes] = None,
    raw_text: Optional[str] = None,
    subject: Optional[str] = None,
    sender: Optional[str] = None,
    recipient: Optional[str] = None,
    headers_text: Optional[str] = None,
    body_text: Optional[str] = None,
    pre_parsed_msg: Optional[EmailMessage] = None,
    force_id: Optional[str] = None
) -> FullAnalysisResult:
    \"\"\"Main scanning pipeline.\"\"\"
    timestamp = datetime.now(timezone.utc).isoformat()
    
    msg = pre_parsed_msg if pre_parsed_msg else get_parsed_message(raw_bytes, raw_text, subject, sender, recipient, headers_text, body_text)
    analysis_id = force_id if force_id else generate_analysis_id(msg, raw_bytes, raw_text, subject, sender, headers_text, body_text)"""

text = text.replace(scan_email_old, scan_email_new)

with open("backend/app/scanner.py", "w") as f:
    f.write(text)
