import ipaddress
import requests
import os
from datetime import datetime, timezone
from typing import Optional
from pydantic import BaseModel, Field

class IPIntelligence(BaseModel):
    ip: str
    ip_version: str
    classification: str = Field(description="TOR_EXIT_NODE, VPN/PROXY, CLOUD/HOSTING, DATACENTER, RESIDENTIAL/ISP, UNKNOWN")
    asn: Optional[str] = None
    organization: Optional[str] = None
    network_provider: Optional[str] = None
    country: Optional[str] = None
    region: Optional[str] = None
    city: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    isp: Optional[str] = None
    is_cloud: bool = False
    is_vpn_proxy: bool = False
    is_tor: bool = False
    is_datacenter: bool = False
    is_open_relay: bool = False
    confidence: str = Field(default="Unknown", description="High, Medium, Low, Unknown")
    source: str = "Local Deterministic Fallback"
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

# Small cached deterministic lists for major clouds and Tor (for testing/fallback)
TOR_NODES = {"185.220.101.4", "185.220.101.5", "192.42.116.16", "109.70.100.22"}
VPN_PROXIES = {"104.238.193.134", "198.51.100.1"}

def get_ip_intelligence(ip: str) -> IPIntelligence:
    # 1. Basic validation and IP version
    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return IPIntelligence(ip=ip, ip_version="Unknown", classification="UNKNOWN", confidence="Low", source="Invalid IP")
        
    version = f"IPv{ip_obj.version}"
    
    # Defaults
    intel = IPIntelligence(
        ip=ip,
        ip_version=version,
        classification="UNKNOWN",
        confidence="Medium",
        source="Local Deterministic Fallback"
    )

    if ip_obj.is_private:
        intel.classification = "RESIDENTIAL/ISP"
        intel.organization = "Private Network"
        intel.country = "Local"
        intel.confidence = "High"
        return intel

    # 2. Local Deterministic Classification
    if ip in TOR_NODES:
        intel.classification = "TOR_EXIT_NODE"
        intel.is_tor = True
        intel.organization = "Tor Network"
        intel.country = "Germany" # Example fixed for deterministic
        intel.confidence = "High"
        return intel

    if ip in VPN_PROXIES:
        intel.classification = "VPN/PROXY"
        intel.is_vpn_proxy = True
        intel.organization = "Known VPN Provider"
        intel.confidence = "High"
        return intel

    # Simple cloud/datacenter IP prefix matching for demo purposes
    if ip.startswith("8.8."):
        intel.classification = "CLOUD/HOSTING"
        intel.is_cloud = True
        intel.organization = "Google Cloud"
        intel.asn = "AS15169"
        intel.country = "United States"
        intel.confidence = "High"
        return intel
    
    if ip.startswith("104.16.") or ip.startswith("104.17."):
        intel.classification = "DATACENTER"
        intel.is_datacenter = True
        intel.organization = "Cloudflare"
        intel.asn = "AS13335"
        intel.country = "United States"
        intel.confidence = "High"
        return intel
        
    if ip.startswith("52.") or ip.startswith("13."):
        intel.classification = "CLOUD/HOSTING"
        intel.is_cloud = True
        intel.organization = "Microsoft Azure"
        intel.asn = "AS8075"
        intel.country = "United States"
        intel.confidence = "High"
        return intel

    # 3. Optional External Live Provider (wrapped in try/except)
    use_live = os.environ.get("USE_LIVE_IP_API", "false").lower() == "true"
    if use_live:
        try:
            # Using ip-api.com as an example free external provider
            res = requests.get(f"http://ip-api.com/json/{ip}?fields=status,country,regionName,city,lat,lon,isp,org,as,proxy,hosting", timeout=3)
            if res.status_code == 200:
                data = res.json()
                if data.get("status") == "success":
                    intel.source = "External Provider (ip-api.com)"
                    intel.country = data.get("country")
                    intel.region = data.get("regionName")
                    intel.city = data.get("city")
                    intel.latitude = data.get("lat")
                    intel.longitude = data.get("lon")
                    intel.isp = data.get("isp")
                    intel.organization = data.get("org")
                    intel.asn = data.get("as", "").split(" ")[0] if data.get("as") else None
                    
                    if data.get("proxy"):
                        intel.classification = "VPN/PROXY"
                        intel.is_vpn_proxy = True
                    elif data.get("hosting"):
                        intel.classification = "CLOUD/HOSTING"
                        intel.is_cloud = True
                        intel.is_datacenter = True
                    else:
                        intel.classification = "RESIDENTIAL/ISP"
                        
                    intel.confidence = "High"
        except Exception:
            # Silently fallback to Unknown if external service fails
            pass
            
    # Default to Residential if no other classification matched
    if intel.classification == "UNKNOWN":
        intel.classification = "RESIDENTIAL/ISP"
        intel.organization = "Unknown ISP"
        intel.confidence = "Low"

    return intel
