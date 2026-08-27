import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.models import get_db, EmailRecord
from app.blockchain import blockchain_service
import app.main as main_module

client = TestClient(app)

def test_zero_pii_in_canonical_evidence():
    test_email = {
        "analysis_id": "audit-test-01",
        "subject": "Confidential Salary Report - DO NOT FORWARD",
        "from_address": "ceo@corp.com",
        "threat_score": {"overall_score": 85, "risk_level": "High"},
        "ai_assessment": {"threat_category": "CREDENTIAL_HARVESTER"},
        "authentication": {"spf": {"status": "pass"}, "dkim": {"status": "fail"}, "dmarc": {"status": "fail"}},
        "relays": [{"hop_number": 1, "ip_address": "198.51.100.1"}],
        "detection_findings": [{"rule_id": "AUTH_FAIL"}],
        "attachments": [{"filename": "secret_passwords.xlsx", "sha256": "abcdef1234567890"}],
        "body_text": "Sensitive body with passwords and financial records."
    }

    canon_payload, canon_hash = blockchain_service.canonicalize_evidence(test_email)

    # Assert that no PII exists in the canonical hash material
    assert "body_text" not in canon_payload
    assert "Confidential Salary" not in str(canon_payload)
    assert "secret_passwords" not in str(canon_payload)
    assert "ceo@corp.com" not in str(canon_payload)
    assert len(canon_hash) == 64


def test_production_gating_on_demo_endpoints():
    # Simulate Production Mode
    main_module.DEMO_MODE = False

    try:
        r1 = client.post("/api/demo/simulate-tamper/any-id")
        assert r1.status_code == 403
        assert "disabled in production" in r1.json()["detail"].lower()

        r2 = client.post("/api/demo/restore-evidence/any-id")
        assert r2.status_code == 403
        assert "disabled in production" in r2.json()["detail"].lower()

        r3 = client.post("/api/demo/reset")
        assert r3.status_code == 403
        assert "disabled in production" in r3.json()["detail"].lower()

        r4 = client.post("/api/demo/seed")
        assert r4.status_code == 403
        assert "disabled in production" in r4.json()["detail"].lower()
    finally:
        main_module.DEMO_MODE = True


def test_oversized_file_upload_rejection():
    # Create oversized dummy bytes (16MB > 15MB limit)
    oversized_data = b"X" * (16 * 1024 * 1024)
    res = client.post(
        "/api/analyze-file",
        files={"file": ("huge_attack.eml", oversized_data, "message/rfc822")}
    )
    assert res.status_code == 413
    assert "exceeds maximum allowed size" in res.json()["detail"].lower()


def test_blockchain_graceful_failure_no_engine_crash():
    blockchain_service.enabled = False

    res = client.post("/api/analyze-email", json={
        "subject": "Graceful Fallback Test",
        "sender": "sender@test.com",
        "body": "Normal body content."
    })
    assert res.status_code == 200
    data = res.json()
    assert data["threat_score"]["overall_score"] is not None

    blockchain_service.enabled = True


def test_no_private_keys_or_secrets_in_responses():
    res = client.get("/api/blockchain/stats")
    assert res.status_code == 200
    text = res.text.lower()
    assert "private" not in text
    assert "secret" not in text
    assert "mnemonic" not in text
