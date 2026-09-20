import pytest
from app.models import ExtractedURL
from app.url_analyzer import analyze_url

def create_extracted_url(url: str) -> ExtractedURL:
    return ExtractedURL(url=url, domain="", source="test")

def test_normal_https_url():
    u = create_extracted_url("https://example.com/about")
    res = analyze_url(u)
    assert res.risk_score == 0
    assert res.risk_level == "LOW"

def test_http_url():
    u = create_extracted_url("http://example.com")
    res = analyze_url(u)
    assert "Insecure Scheme" in res.suspicious_features
    assert res.risk_score >= 10

def test_ip_based_url():
    u = create_extracted_url("https://192.168.1.1/admin")
    res = analyze_url(u)
    assert "IP-based URL" in res.suspicious_features
    assert res.risk_score >= 30

def test_userinfo_trick():
    u = create_extracted_url("https://microsoft.com@evil.example/login")
    res = analyze_url(u)
    assert "Userinfo (@) Trick" in res.suspicious_features
    assert res.hostname == "evil.example"
    assert res.risk_score >= 40

def test_lookalike_domain():
    u = create_extracted_url("https://micros0ft.com/verify")
    res = analyze_url(u)
    assert "Brand Typosquatting" in res.suspicious_features or "Brand Impersonation" in res.suspicious_features
    assert res.risk_score >= 25

def test_punycode_domain():
    u = create_extracted_url("https://xn--e1awd7f.com/")
    res = analyze_url(u)
    assert "Punycode / IDN" in res.suspicious_features
    assert res.risk_score >= 35

def test_suspicious_login_path():
    u = create_extracted_url("https://unknown-domain.com/secure/login/verify")
    res = analyze_url(u)
    assert "Suspicious Path Keywords" in res.suspicious_features
    assert res.risk_score >= 15

def test_long_encoded_url():
    u = create_extracted_url("https://example.com/redirect?val=" + ("%20" * 80))
    res = analyze_url(u)
    assert "Suspicious URL Length" in res.suspicious_features
    assert "Excessive URL Encoding" in res.suspicious_features
    assert res.risk_score >= 25

def test_benign_url_no_excessive_risk():
    u = create_extracted_url("https://github.com/pulls")
    res = analyze_url(u)
    assert res.risk_score == 0
    assert res.risk_level == "LOW"
