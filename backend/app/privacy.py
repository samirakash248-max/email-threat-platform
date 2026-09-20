import re
from typing import Set, Dict, Any, Optional
from datetime import datetime, timezone, timedelta
import os

# Simple regexes for common PII patterns
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.(?:[a-zA-Z0-9-]+\.)*[a-zA-Z0-9-]+')
PHONE_REGEX = re.compile(r'\+?\d{1,3}?[-.\s]?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}')

def mask_text(text: str, allowed_iocs: Set[str] = frozenset()) -> str:
    if not text:
        return text
    
    def repl_email(match):
        val = match.group(0)
        return val if val in allowed_iocs else "[REDACTED_EMAIL]"

    def repl_phone(match):
        val = match.group(0)
        return val if val in allowed_iocs else "[REDACTED_PHONE]"
        
    masked = EMAIL_REGEX.sub(repl_email, text)
    masked = PHONE_REGEX.sub(repl_phone, masked)
    return masked

def gather_iocs(analysis_result: Dict[str, Any]) -> Set[str]:
    """Gather forensic indicators that should NOT be masked."""
    iocs = set()
    metadata = analysis_result.get("metadata", {})
    
    for key in ["from_address", "reply_to", "return_path"]:
        val = metadata.get(key)
        if val: iocs.add(val)
    
    urls = analysis_result.get("extracted_urls", [])
    for u in urls:
        url_val = u if isinstance(u, str) else u.get("url")
        if url_val: iocs.add(url_val)
        if isinstance(u, dict) and u.get("domain"):
            iocs.add(u.get("domain"))
            
    relays = analysis_result.get("relays", [])
    for r in relays:
        ip = r if isinstance(r, str) else r.get("ip_address")
        if ip: iocs.add(ip)
        
    extracted_iocs = analysis_result.get("iocs", [])
    for ioc in extracted_iocs:
        val = ioc if isinstance(ioc, str) else ioc.get("value")
        if val: iocs.add(val)
        
    return iocs

def apply_privacy_masking(analysis_result: Dict[str, Any], drop_raw: bool = False) -> Dict[str, Any]:
    """Generates a privacy-safe presentation copy of the analysis result."""
    import copy
    safe_data = copy.deepcopy(analysis_result)
    
    iocs = gather_iocs(safe_data)
    
    meta = safe_data.get("metadata", {})
    if "body_plain" in meta and meta["body_plain"]:
        meta["masked_body_plain"] = mask_text(meta["body_plain"], iocs)
    if "body_html" in meta and meta["body_html"]:
        meta["masked_body_html"] = mask_text(meta["body_html"], iocs)
        
    if drop_raw:
        meta.pop("body_plain", None)
        meta.pop("body_html", None)
        # Headers might also contain sensitive info, but we'll mask specific presentation ones 
        # while keeping all_headers if needed, or drop it if strictly minimizing.
        
    return safe_data

def get_retention_days() -> int:
    try:
        return int(os.environ.get("EVIDENCE_RETENTION_DAYS", "30"))
    except ValueError:
        return 30

def calculate_retention_expiry(created_at: datetime) -> datetime:
    days = get_retention_days()
    return created_at + timedelta(days=days)

def purge_expired_evidence(db) -> int:
    """
    Identifies and deletes only records covered by the retention policy.
    Never deletes blockchain anchors, configurations, or operational metadata.
    """
    from app.models import EmailRecord
    now = datetime.now(timezone.utc)
    days = get_retention_days()
    cutoff = now - timedelta(days=days)
    
    # We only delete the raw EmailRecord payload for privacy compliance. 
    # Custody events, Blockchain anchors, and abstract Cases remain.
    expired_records = db.query(EmailRecord).filter(EmailRecord.created_at < cutoff).all()
    count = len(expired_records)
    for r in expired_records:
        # We can either delete the entire record or just nullify data_json's raw content.
        # Deleting the record is standard for purging if cases extract IOCs.
        db.delete(r)
    
    db.commit()
    return count
