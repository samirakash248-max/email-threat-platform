import os
import requests
import dns.resolver
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field

class DNSRecords(BaseModel):
    a: List[str] = []
    aaaa: List[str] = []
    mx: List[str] = []
    ns: List[str] = []
    txt: List[str] = []
    cname: List[str] = []

class WhoisRDAPInfo(BaseModel):
    registrar: Optional[str] = None
    creation_date: Optional[str] = None
    expiration_date: Optional[str] = None
    updated_date: Optional[str] = None
    domain_status: List[str] = []
    nameservers: List[str] = []
    privacy_protected: bool = False
    status: str = "unavailable" # success, unavailable, timeout
    source: str = "None"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

class DomainRiskEnrichment(BaseModel):
    newly_registered: bool = False
    suspicious_tld: bool = False
    lookalike: bool = False
    unusual_nameservers: bool = False
    mx_inconsistency: bool = False
    risk_factors: List[str] = []

class DomainIntelligence(BaseModel):
    domain: str
    dns_records: DNSRecords = Field(default_factory=DNSRecords)
    dns_resolution_status: str = "success"
    whois_rdap: WhoisRDAPInfo = Field(default_factory=WhoisRDAPInfo)
    risk: DomainRiskEnrichment = Field(default_factory=DomainRiskEnrichment)
    is_sender_domain: bool = False
    mx_third_party: bool = False
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# Known suspicious TLDs for basic heuristics
SUSPICIOUS_TLDS = {".xyz", ".top", ".club", ".online", ".site", ".tk", ".ml", ".ga", ".cf", ".gq"}

# Local mock data for deterministic fallback and offline testing
MOCK_DOMAINS = {
    "trustd-bank.com": {
        "dns": {"a": ["192.168.1.100"], "mx": ["mail.trustd-bank.com"]},
        "whois": {"registrar": "Mock Registrar LLC", "creation_date": "2026-01-01T00:00:00Z", "status": "success", "privacy_protected": False}
    },
    "evil.com": {
        "dns": {"a": ["104.238.193.134"], "mx": ["mx.evil.com"]},
        "whois": {"registrar": "Shady Domains Inc", "creation_date": "2026-09-15T00:00:00Z", "status": "success", "privacy_protected": True}
    }
}

def resolve_dns(domain: str) -> (DNSRecords, str):
    use_live = os.environ.get("USE_LIVE_DNS_API", "false").lower() == "true"
    records = DNSRecords()
    
    if not use_live:
        if domain in MOCK_DOMAINS:
            md = MOCK_DOMAINS[domain]["dns"]
            records.a = md.get("a", [])
            records.mx = md.get("mx", [])
            return records, "success"
        return records, "unavailable"

    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.0
    
    status = "success"
    
    try:
        # A records
        try:
            ans = resolver.resolve(domain, 'A')
            records.a = [rdata.to_text() for rdata in ans]
        except Exception as e:
            if isinstance(e, dns.exception.Timeout): raise e
        
        # AAAA records
        try:
            ans = resolver.resolve(domain, 'AAAA')
            records.aaaa = [rdata.to_text() for rdata in ans]
        except Exception as e:
            if isinstance(e, dns.exception.Timeout): raise e
        
        # MX records
        try:
            ans = resolver.resolve(domain, 'MX')
            records.mx = [rdata.exchange.to_text().strip('.') for rdata in ans]
        except Exception as e:
            if isinstance(e, dns.exception.Timeout): raise e
        
        # NS records
        try:
            ans = resolver.resolve(domain, 'NS')
            records.ns = [rdata.to_text().strip('.') for rdata in ans]
        except Exception as e:
            if isinstance(e, dns.exception.Timeout): raise e
        
        # TXT records
        try:
            ans = resolver.resolve(domain, 'TXT')
            records.txt = [rdata.to_text() for rdata in ans]
        except Exception as e:
            if isinstance(e, dns.exception.Timeout): raise e
        
        # CNAME records
        try:
            ans = resolver.resolve(domain, 'CNAME')
            records.cname = [rdata.to_text().strip('.') for rdata in ans]
        except Exception as e:
            if isinstance(e, dns.exception.Timeout): raise e
        
    except dns.exception.Timeout:
        status = "timeout"
    except Exception:
        status = "failed"
        
    return records, status

def lookup_whois_rdap(domain: str) -> WhoisRDAPInfo:
    use_live = os.environ.get("USE_LIVE_WHOIS_API", "false").lower() == "true"
    info = WhoisRDAPInfo()
    
    if not use_live:
        if domain in MOCK_DOMAINS:
            mw = MOCK_DOMAINS[domain]["whois"]
            info.registrar = mw.get("registrar")
            info.creation_date = mw.get("creation_date")
            info.status = mw.get("status", "success")
            info.privacy_protected = mw.get("privacy_protected", False)
            info.source = "Local Mock RDAP"
        else:
            info.status = "unavailable"
        return info
        
    # Attempt live RDAP lookup via public API (e.g. rdap.org)
    try:
        res = requests.get(f"https://rdap.org/domain/{domain}", timeout=3.0)
        if res.status_code == 200:
            data = res.json()
            info.status = "success"
            info.source = "Live RDAP (rdap.org)"
            
            # Extract basic RDAP fields
            events = data.get("events", [])
            for e in events:
                if e.get("eventAction") == "registration":
                    info.creation_date = e.get("eventDate")
                elif e.get("eventAction") == "expiration":
                    info.expiration_date = e.get("eventDate")
                elif e.get("eventAction") == "last changed":
                    info.updated_date = e.get("eventDate")
                    
            entities = data.get("entities", [])
            for ent in entities:
                roles = ent.get("roles", [])
                if "registrar" in roles:
                    vcard = ent.get("vcardArray", [])
                    if len(vcard) > 1:
                        for item in vcard[1]:
                            if item[0] == "fn":
                                info.registrar = item[3]
                                
            nameservers = data.get("nameservers", [])
            info.nameservers = [ns.get("ldhName") for ns in nameservers]
            info.domain_status = data.get("status", [])
            
            # Privacy heuristic
            raw_data = str(data).lower()
            if "privacy" in raw_data or "redacted" in raw_data or "protected" in raw_data:
                info.privacy_protected = True
        else:
            info.status = "unavailable"
    except requests.exceptions.Timeout:
        info.status = "timeout"
    except Exception:
        info.status = "unavailable"
        
    return info

def get_domain_intelligence(domain: str, is_sender_domain: bool = False, observed_ips: List[str] = None) -> DomainIntelligence:
    domain = domain.lower().strip()
    
    # Internal/Private domains check
    if domain.endswith(".local") or domain.endswith(".lan") or "." not in domain:
        return DomainIntelligence(
            domain=domain,
            dns_resolution_status="unavailable",
            whois_rdap=WhoisRDAPInfo(status="unavailable", source="Internal Domain")
        )
        
    intel = DomainIntelligence(domain=domain, is_sender_domain=is_sender_domain)
    
    # DNS 
    intel.dns_records, intel.dns_resolution_status = resolve_dns(domain)
    
    # RDAP / WHOIS
    intel.whois_rdap = lookup_whois_rdap(domain)
    
    # Risk Enrichment Heuristics
    # 1. Suspicious TLD
    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            intel.risk.suspicious_tld = True
            intel.risk.risk_factors.append(f"Suspicious TLD ({tld})")
            break
            
    # 2. Newly Registered Domain (within 30 days)
    if intel.whois_rdap.creation_date:
        try:
            # Parse ISO date roughly
            creation_str = intel.whois_rdap.creation_date.split("T")[0]
            creation_dt = datetime.strptime(creation_str, "%Y-%m-%d")
            delta = datetime.now(timezone.utc).replace(tzinfo=None) - creation_dt
            if delta.days <= 30:
                intel.risk.newly_registered = True
                intel.risk.risk_factors.append(f"Newly registered domain ({delta.days} days old)")
        except Exception:
            pass
            
    # 3. Privacy protection on shady TLD
    if intel.risk.suspicious_tld and intel.whois_rdap.privacy_protected:
        intel.risk.risk_factors.append("Privacy protected registration on suspicious TLD")
        
    # 4. MX Inconsistency / Third-party
    if is_sender_domain:
        if not intel.dns_records.mx:
            intel.risk.mx_inconsistency = True
            intel.risk.risk_factors.append("Sender domain has no MX records (cannot receive mail)")
        else:
            # Check if MX is third party (doesn't share base domain)
            base_domain_parts = domain.split(".")[-2:]
            base_domain = ".".join(base_domain_parts)
            
            mx_third_party = True
            for mx in intel.dns_records.mx:
                if base_domain in mx:
                    mx_third_party = False
                    break
            
            intel.mx_third_party = mx_third_party
            if mx_third_party:
                intel.risk.risk_factors.append("Uses third-party mail infrastructure")
                
            # If we have observed IPs, see if they match the MX IPs (if we could resolve them)
            # This is a very loose check since we'd need to resolve the MX hosts to IPs.
            # For simplicity, we just note if there's no obvious overlap when we have data.
            
    # 5. Lookalike check (simple heuristic: hyphenated bank/paypal/microsoft etc)
    suspicious_keywords = ["bank", "paypal", "microsoft", "apple", "google", "login", "secure", "update"]
    for kw in suspicious_keywords:
        if kw in domain and domain != f"{kw}.com":
            # Simple heuristic
            intel.risk.lookalike = True
            if f"Lookalike domain keyword ({kw})" not in intel.risk.risk_factors:
                intel.risk.risk_factors.append(f"Lookalike domain keyword ({kw})")
            
    return intel
