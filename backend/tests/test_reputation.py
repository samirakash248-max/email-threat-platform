from app.reputation_intelligence import check_ip_reputation
import os

# Ensure mock is enabled for deterministic tests
os.environ["USE_MOCK_REPUTATION"] = "true"

def test_rbl_listed_ip():
    res = check_ip_reputation("203.0.113.10")
    assert res.listed is True
    assert res.botnet_association == "KNOWN_BOTNET_ASSOCIATION"
    assert res.provider_status == "CONFIGURED"

def test_rbl_not_listed_ip():
    res = check_ip_reputation("198.51.100.100")
    assert res.listed is False
    assert res.botnet_association == "NONE_OBSERVED"

def test_rbl_provider_unavailable():
    res = check_ip_reputation("203.0.113.40") # Hardcoded mock sim for unavailable
    assert res.listed is False
    assert res.provider_status == "UNAVAILABLE"

def test_rbl_timeout():
    res = check_ip_reputation("203.0.113.30") # Hardcoded mock sim for timeout
    assert res.listed is False
    assert res.source_results[0].status == "TIMEOUT"

def test_invalid_ip():
    res = check_ip_reputation("not.an.ip")
    assert res.listed is False
    assert res.provider_status == "UNAVAILABLE"

def test_blacklist_does_not_equal_botnet():
    res = check_ip_reputation("203.0.113.20") # listed but not botnet
    assert res.listed is True
    assert res.botnet_association == "REPUTATION_LISTED"

def test_explicit_botnet_provider_association():
    res = check_ip_reputation("203.0.113.10") # botnet ip
    assert res.botnet_association == "KNOWN_BOTNET_ASSOCIATION"

def test_mock_provider_is_not_default_production_provider():
    os.environ["USE_MOCK_REPUTATION"] = "false"
    # Empty config
    os.environ["REPUTATION_DNSBLS"] = ""
    res = check_ip_reputation("203.0.113.10")
    assert res.provider_status == "NOT_CONFIGURED"
    assert res.listed is False

    # Mock cleanup
    os.environ["USE_MOCK_REPUTATION"] = "true"
    os.environ["REPUTATION_DNSBLS"] = ""

def test_reputation_does_not_break_ip_intelligence():
    from app.ip_intelligence import get_ip_intelligence
    res = get_ip_intelligence("8.8.8.8")
    assert res.ip == "8.8.8.8"
    assert hasattr(res, 'reputation')

def test_reputation_evidence_reaches_investigative_assessment():
    from app.assessment_engine import calculate_investigative_assessment
    from app.models import AuthResults, ThreatScore
    
    class FakeParsedEmail:
        sender = "good@test.com"
        reply_to = "good@test.com"
        
    auth = AuthResults()
    threat = ThreatScore(overall_score=85, risk_level="High", explanation="Malicious content", risk_color="red")
    
    ip_intel_dict = {
        "203.0.113.10": {
            "reputation": {
                "listed": True,
                "botnet_association": "KNOWN_BOTNET_ASSOCIATION"
            }
        }
    }
    
    res = calculate_investigative_assessment(auth, threat, ip_intel_dict, {}, FakeParsedEmail())
    assert "Explicit botnet-associated indicator observed (203.0.113.10)." in res.reasons
