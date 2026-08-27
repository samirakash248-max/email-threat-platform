import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.models import get_db, ThreatIntelRecord, EmailRecord
from app.blockchain import blockchain_service

client = TestClient(app)

def test_register_and_verify_threat_indicator():
    # 1. Register a new malicious domain
    payload = {
        "indicator_type": "DOMAIN",
        "indicator_value": "secure-paypal-login-alert.com",
        "threat_category": "CREDENTIAL_HARVESTER",
        "severity": "CRITICAL",
        "confidence_score": 98,
        "source_org": "CERT-In-Node-01",
        "description": "Observed in mass banking spear-phishing attack against employee portals."
    }
    res = client.post("/api/intel/indicators", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["indicator_type"] == "DOMAIN"
    assert data["indicator_value"] == "secure-paypal-login-alert.com"
    assert data["is_verified_onchain"] is True
    assert data["observation_count"] == 1
    assert data["tx_id"].startswith("0x")

    # 2. Verify indicator
    v_res = client.get("/api/intel/verify?type=DOMAIN&value=secure-paypal-login-alert.com")
    assert v_res.status_code == 200
    v_data = v_res.json()
    assert v_data["is_known_threat"] is True
    assert v_data["threat_category"] == "CREDENTIAL_HARVESTER"
    assert v_data["status"] == "VERIFIED_ON_CHAIN"
    assert v_data["source_org"] == "CERT-In-Node-01"


def test_prevent_duplicate_and_aggregate_observations():
    # 1. First registration from Node Alpha
    p1 = {
        "indicator_type": "IP_ADDRESS",
        "indicator_value": "185.220.101.5",
        "threat_category": "MALWARE_C2",
        "severity": "HIGH",
        "confidence_score": 80,
        "source_org": "ThreatSentinel-Org-Alpha"
    }
    r1 = client.post("/api/intel/indicators", json=p1)
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["observation_count"] == 1

    # 2. Second registration of same IP from Node Beta with higher confidence
    p2 = {
        "indicator_type": "IP_ADDRESS",
        "indicator_value": "185.220.101.5",
        "threat_category": "MALWARE_C2",
        "severity": "CRITICAL",
        "confidence_score": 95,
        "source_org": "ThreatSentinel-Org-Beta"
    }
    r2 = client.post("/api/intel/indicators", json=p2)
    assert r2.status_code == 200
    d2 = r2.json()

    # Observation count should increment to 2 and confidence updated to 95
    assert d2["observation_count"] == 2
    assert d2["confidence_score"] == 95


def test_verify_clean_indicator():
    res = client.get("/api/intel/verify?type=DOMAIN&value=google.com")
    assert res.status_code == 200
    data = res.json()
    assert data["is_known_threat"] is False
    assert data["status"] == "CLEAN_OR_NOT_FOUND"


def test_auto_publish_iocs_from_dossier():
    # 1. Reset demo fixtures
    client.post("/api/demo/reset")

    # 2. Check threat indicators count
    db = next(get_db())
    count = db.query(ThreatIntelRecord).count()
    assert count > 0  # Sample synthetic threats automatically broadcasted IoCs

    # Check a published indicator
    ind = db.query(ThreatIntelRecord).first()
    assert ind is not None
    assert ind.indicator_type in ("DOMAIN", "FILE_HASH", "IP_ADDRESS", "SENDER_DOMAIN")
    assert ind.tx_id.startswith("0x")
    db.close()


def test_threat_intel_zero_pii():
    db = next(get_db())
    indicators = db.query(ThreatIntelRecord).all()
    for ind in indicators:
        # Check that indicator value is an IoC, not an email body
        assert len(ind.indicator_value) < 500
        assert "password" not in ind.indicator_value.lower()
        assert "dear user" not in ind.indicator_value.lower()
    db.close()
