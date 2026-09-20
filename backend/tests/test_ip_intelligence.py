import pytest
from app.ip_intelligence import get_ip_intelligence, IPIntelligence

def test_ip_intelligence_normal_isp():
    # Private IP falls back to RESIDENTIAL/ISP
    intel = get_ip_intelligence("192.168.1.100")
    assert intel.classification == "RESIDENTIAL/ISP"
    assert intel.confidence == "High"
    assert intel.organization == "Private Network"

def test_ip_intelligence_tor_node():
    intel = get_ip_intelligence("185.220.101.4")
    assert intel.classification == "TOR_EXIT_NODE"
    assert intel.is_tor is True
    assert intel.organization == "Tor Network"

def test_ip_intelligence_cloud_datacenter():
    intel = get_ip_intelligence("8.8.8.8")
    assert intel.classification == "CLOUD/HOSTING"
    assert intel.is_cloud is True
    assert intel.organization == "Google Cloud"

def test_ip_intelligence_cloudflare():
    intel = get_ip_intelligence("104.16.1.1")
    assert intel.classification == "DATACENTER"
    assert intel.is_datacenter is True
    assert intel.organization == "Cloudflare"

def test_ip_intelligence_vpn_proxy():
    intel = get_ip_intelligence("104.238.193.134")
    assert intel.classification == "VPN/PROXY"
    assert intel.is_vpn_proxy is True

def test_ip_intelligence_unknown():
    intel = get_ip_intelligence("93.184.216.34")
    assert intel.classification == "RESIDENTIAL/ISP" # default fallback
    assert intel.confidence == "Low"
    assert intel.organization == "Unknown ISP"

def test_ip_intelligence_malformed_ip():
    intel = get_ip_intelligence("not_an_ip")
    assert intel.classification == "UNKNOWN"
    assert intel.confidence == "Low"

def test_ip_intelligence_ipv6():
    intel = get_ip_intelligence("2001:db8::1")
    assert intel.classification == "RESIDENTIAL/ISP"
    assert intel.ip_version == "IPv6"

def test_ip_intelligence_provider_unavailable(monkeypatch):
    import os
    monkeypatch.setenv("USE_LIVE_IP_API", "true")
    import requests
    class MockResponse:
        status_code = 500
        def json(self): return {}
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: MockResponse())
    intel = get_ip_intelligence("93.184.216.34")
    assert intel.classification == "RESIDENTIAL/ISP"
    assert intel.confidence == "Low"

def test_ip_intelligence_provider_timeout(monkeypatch):
    import os
    monkeypatch.setenv("USE_LIVE_IP_API", "true")
    import requests
    def mock_timeout(*args, **kwargs):
        raise requests.exceptions.Timeout("Timeout")
    monkeypatch.setattr(requests, "get", mock_timeout)
    intel = get_ip_intelligence("93.184.216.34")
    assert intel.classification == "RESIDENTIAL/ISP"
    assert intel.confidence == "Low"

def test_ip_intelligence_missing_geolocation(monkeypatch):
    import os
    monkeypatch.setenv("USE_LIVE_IP_API", "true")
    import requests
    class MockResponse:
        status_code = 200
        def json(self): return {"status": "success", "org": "Some Org"} # Missing country/city
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: MockResponse())
    intel = get_ip_intelligence("93.184.216.34")
    assert intel.organization == "Some Org"
    assert intel.country is None
