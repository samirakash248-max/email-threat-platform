import pytest
from app.domain_intelligence import get_domain_intelligence, DomainIntelligence

def test_domain_intel_mock_success():
    intel = get_domain_intelligence("trustd-bank.com")
    assert intel.domain == "trustd-bank.com"
    assert "192.168.1.100" in intel.dns_records.a
    assert intel.whois_rdap.registrar == "Mock Registrar LLC"

def test_domain_intel_mock_evil():
    intel = get_domain_intelligence("evil.com", is_sender_domain=True)
    assert intel.domain == "evil.com"
    assert intel.whois_rdap.privacy_protected is True
    # evil.com mock has 2026-09-15 creation date which should trigger newly registered risk
    assert intel.risk.newly_registered is True

def test_domain_intel_internal():
    intel = get_domain_intelligence("internal.local")
    assert intel.dns_resolution_status == "unavailable"
    assert intel.whois_rdap.status == "unavailable"
    assert intel.whois_rdap.source == "Internal Domain"

def test_domain_intel_suspicious_tld():
    intel = get_domain_intelligence("phish.xyz")
    assert intel.risk.suspicious_tld is True
    assert "Suspicious TLD (.xyz)" in intel.risk.risk_factors

def test_domain_intel_lookalike():
    intel = get_domain_intelligence("paypal-update.com")
    assert intel.risk.lookalike is True

def test_domain_intel_mx_inconsistency():
    intel = get_domain_intelligence("nomx.com", is_sender_domain=True)
    assert intel.risk.mx_inconsistency is True

def test_domain_intel_provider_timeout(monkeypatch):
    import os
    monkeypatch.setenv("USE_LIVE_DNS_API", "true")
    monkeypatch.setenv("USE_LIVE_WHOIS_API", "true")
    import requests
    def mock_timeout(*args, **kwargs):
        raise requests.exceptions.Timeout("Timeout")
    monkeypatch.setattr(requests, "get", mock_timeout)
    import dns.resolver
    class MockResolver:
        def resolve(self, *args, **kwargs):
            raise dns.exception.Timeout("Timeout")
    monkeypatch.setattr(dns.resolver, "Resolver", lambda: MockResolver())
    
    intel = get_domain_intelligence("timeout.com")
    assert intel.dns_resolution_status == "timeout"
    assert intel.whois_rdap.status == "timeout"

def test_domain_intel_provider_unavailable(monkeypatch):
    import os
    monkeypatch.setenv("USE_LIVE_WHOIS_API", "true")
    import requests
    class MockResponse:
        status_code = 500
        def json(self): return {}
    monkeypatch.setattr(requests, "get", lambda *args, **kwargs: MockResponse())
    
    intel = get_domain_intelligence("unavailable.com")
    assert intel.whois_rdap.status == "unavailable"
