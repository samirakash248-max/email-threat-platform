import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.models import get_db, EmailRecord
import app.main as main_module

client = TestClient(app)

def test_full_controlled_tamper_demonstration_flow():
    # Step 1 & 2: Ingest email and seed demo
    reset_res = client.post("/api/demo/reset")
    assert reset_res.status_code == 200

    db = next(get_db())
    record = db.query(EmailRecord).first()
    assert record is not None
    evidence_id = record.id
    db.close()

    # Step 3 & 4: Initial Verification (Authentic State)
    initial_verify = client.get(f"/api/blockchain/verify/{evidence_id}")
    assert initial_verify.status_code == 200
    init_data = initial_verify.json()
    assert init_data["verification_status"] == "VERIFIED_AUTHENTIC"
    assert init_data["payload_hash_intact"] is True
    assert init_data["tamper_detected"] is False

    # Step 5: Controlled Tamper Attack Simulation
    tamper_res = client.post(f"/api/demo/simulate-tamper/{evidence_id}")
    assert tamper_res.status_code == 200
    tamper_data = tamper_res.json()
    assert tamper_data["status"] == "TAMPER_SIMULATED"

    # Step 6, 7 & 8: Re-verify after off-chain alteration
    post_tamper_verify = client.get(f"/api/blockchain/verify/{evidence_id}")
    assert post_tamper_verify.status_code == 200
    pt_data = post_tamper_verify.json()

    # Step 9: Verify Tamper is Detected
    assert pt_data["verification_status"] == "TAMPER_DETECTED"
    assert pt_data["payload_hash_intact"] is False
    assert pt_data["tamper_detected"] is True
    assert "TAMPER" in pt_data["verification_details"].upper()

    # Verify Custody also catches modification
    custody_verify = client.get(f"/api/custody/{evidence_id}/verify")
    assert custody_verify.status_code == 200
    c_data = custody_verify.json()
    assert c_data["status"] == "MODIFIED"
    assert c_data["is_intact"] is False

    # Step 10: Restore Evidence Back to Authentic
    restore_res = client.post(f"/api/demo/restore-evidence/{evidence_id}")
    assert restore_res.status_code == 200
    rest_data = restore_res.json()
    assert rest_data["status"] == "RESTORED"

    # Re-verify after restoration
    restored_verify = client.get(f"/api/blockchain/verify/{evidence_id}")
    assert restored_verify.status_code == 200
    assert restored_verify.json()["verification_status"] == "VERIFIED_AUTHENTIC"
    assert restored_verify.json()["tamper_detected"] is False


def test_tamper_endpoint_disabled_in_production():
    # Simulate Production Mode
    main_module.DEMO_MODE = False

    try:
        tamper_res = client.post("/api/demo/simulate-tamper/test-id-123")
        assert tamper_res.status_code == 403
        assert "disabled in production" in tamper_res.json()["detail"].lower()

        restore_res = client.post("/api/demo/restore-evidence/test-id-123")
        assert restore_res.status_code == 403
    finally:
        # Revert back to demo mode for subsequent tests
        main_module.DEMO_MODE = True
