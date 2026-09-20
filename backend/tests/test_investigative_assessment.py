from app.models import ThreatScore, AuthResults, AuthStatus
from app.assessment_engine import calculate_investigative_assessment

class FakeParsedEmail:
    def __init__(self, sender="anon@anon.com", reply_to="anon@anon.com"):
        self.sender = sender
        self.reply_to = reply_to

def test_assessment_spoofed_domain():
    auth = AuthResults(
        spf=AuthStatus(status="softfail"),
        dkim=AuthStatus(status="fail"),
        dmarc=AuthStatus(status="fail", domain="trustd-bank.com", explanation="failed")
    )
    threat = ThreatScore(overall_score=80, risk_level="High", explanation="Bad", risk_color="red")
    dom = {"trustd-bank.com": {"is_lookalike_typosquat": False}}
    pe = FakeParsedEmail("ceo@trustd-bank.com", "attacker@evil.com")
    
    res = calculate_investigative_assessment(auth, threat, {}, dom, pe)
    assert res.vector == "SPOOFED_DOMAIN"
    assert "Authentication failures are consistent with domain spoofing." in res.reasons
    assert res.assessment_type == "INVESTIGATIVE_ASSESSMENT"

def test_assessment_anonymized():
    # Neither strong spoof nor strong compromised
    auth = AuthResults(spf=AuthStatus(status="none"), dkim=AuthStatus(status="none"), dmarc=AuthStatus(status="none"))
    threat = ThreatScore(overall_score=45, risk_level="Medium", explanation="Sus", risk_color="yellow")
    ip_intel = {"1.2.3.4": {"is_tor": True, "is_vpn_proxy": True, "is_datacenter": False}}
    
    res = calculate_investigative_assessment(auth, threat, ip_intel, {}, FakeParsedEmail())
    assert res.vector == "ANONYMIZED_INFRASTRUCTURE"
    assert res.confidence > 50

def test_assessment_direct_malicious():
    auth = AuthResults(spf=AuthStatus(status="none"), dkim=AuthStatus(status="none"), dmarc=AuthStatus(status="none"))
    threat = ThreatScore(overall_score=85, risk_level="High", explanation="Malicious content", risk_color="red")
    dom_intel = {"evil.com": {"risk": {"newly_registered": True, "suspicious_tld": True}}}
    
    res = calculate_investigative_assessment(auth, threat, {}, dom_intel, FakeParsedEmail())
    assert res.vector == "DIRECT_MALICIOUS_INFRASTRUCTURE"

def test_assessment_compromised():
    auth = AuthResults(spf=AuthStatus(status="pass"), dkim=AuthStatus(status="pass"), dmarc=AuthStatus(status="pass", domain="test.com", explanation="pass"))
    threat = ThreatScore(overall_score=95, risk_level="Critical", explanation="Malware", risk_color="red")
    
    res = calculate_investigative_assessment(auth, threat, {}, {}, FakeParsedEmail("good@test.com", "good@test.com"))
    assert res.vector == "COMPROMISED_ACCOUNT"

def test_assessment_insufficient():
    threat = ThreatScore(overall_score=20, risk_level="Low", explanation="Nothing", risk_color="green")
    res = calculate_investigative_assessment(None, threat, {}, {}, FakeParsedEmail())
    assert res.vector == "INSUFFICIENT_EVIDENCE"
    assert res.confidence == 0

def test_assessment_reproducibility():
    auth = AuthResults(spf=AuthStatus(status="softfail"), dkim=AuthStatus(status="fail"), dmarc=AuthStatus(status="fail", domain="trustd-bank.com", explanation="failed"))
    threat = ThreatScore(overall_score=80, risk_level="High", explanation="Bad", risk_color="red")
    dom = {"trustd-bank.com": {"is_lookalike_typosquat": False}}
    pe = FakeParsedEmail("ceo@trustd-bank.com", "attacker@evil.com")
    
    res1 = calculate_investigative_assessment(auth, threat, {}, dom, pe)
    res2 = calculate_investigative_assessment(auth, threat, {}, dom, pe)
    
    assert res1.vector == res2.vector
    assert res1.confidence == res2.confidence
