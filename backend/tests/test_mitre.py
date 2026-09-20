from app.mitre_mapper import map_findings_to_mitre, MITRE_CATALOG
from app.models import ThreatFinding

def test_mitre_benign():
    findings = [
        ThreatFinding(rule_id="RULE-01", description="SPF Pass", explanation="SPF aligned", severity="LOW", evidence="v=spf1", rule_name="x", category="x", points=0)
    ]
    mappings = map_findings_to_mitre(findings)
    assert len(mappings) == 0

def test_mitre_attachment():
    findings = [
        ThreatFinding(rule_id="RULE-09", description="Dangerous Attachment", explanation="Found exe", severity="CRITICAL", evidence="evil.exe", rule_name="x", category="x", points=30)
    ]
    mappings = map_findings_to_mitre(findings)
    techs = [m.technique_id for m in mappings]
    assert "T1566.001" in techs
    assert "T1204.002" in techs
    assert mappings[0].reason != ""

def test_mitre_malicious_link():
    findings = [
        ThreatFinding(rule_id="RULE-13", description="URL Risk", explanation="Suspicious link", severity="CRITICAL", evidence="http://evil.com", rule_name="x", category="x", points=25)
    ]
    mappings = map_findings_to_mitre(findings)
    techs = [m.technique_id for m in mappings]
    assert "T1566.002" in techs

def test_mitre_credential_phishing():
    findings = [
        ThreatFinding(rule_id="RULE-08", description="Credential Phishing", explanation="login page fake", severity="CRITICAL", evidence="login", rule_name="x", category="x", points=20)
    ]
    mappings = map_findings_to_mitre(findings)
    techs = [m.technique_id for m in mappings]
    assert "T1598.003" in techs

def test_mitre_duplicate_prevention():
    findings = [
        ThreatFinding(rule_id="RULE-09", description="Dangerous Attachment", explanation="Found exe", severity="CRITICAL", evidence="evil.exe", rule_name="x", category="x", points=30),
        ThreatFinding(rule_id="RULE-09", description="Dangerous Attachment 2", explanation="Found bat", severity="CRITICAL", evidence="bad.bat", rule_name="x", category="x", points=30)
    ]
    mappings = map_findings_to_mitre(findings)
    # Should only have one T1566.001 and one T1204.002, but with multiple indicators
    techs = [m.technique_id for m in mappings]
    assert len(techs) == 2
    assert techs.count("T1566.001") == 1
    t1566_001 = [m for m in mappings if m.technique_id == "T1566.001"][0]
    assert len(t1566_001.supporting_indicators) == 2
    assert "evil.exe" in t1566_001.supporting_indicators
    assert "bad.bat" in t1566_001.supporting_indicators
