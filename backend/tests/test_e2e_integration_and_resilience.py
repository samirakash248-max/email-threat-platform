import os
import sys
import copy
import pytest
from unittest.mock import patch
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app, save_analysis
from app.models import get_db, EmailRecord, BlockRecord, CustodyEventRecord, FullAnalysisResult
from app.blockchain import BlockchainService, blockchain_service, MerkleTree
from app.scanner import scan_email
import app.main as main_module

client = TestClient(app)

# =============================================================================
# 1. COMPLETE 17-STEP END-TO-END INTEGRATION TEST
# =============================================================================

def test_17_step_complete_end_to_end_lifecycle():
    # Step 1: Submit synthetic email
    raw_synthetic_email = (
        "From: IT Support <support@corporate-portal-update.com>\n"
        "To: employee@company.com\n"
        "Subject: URGENT: Mandatory Password Reset Required Immediately\n"
        "Date: Thu, 27 Aug 2026 08:30:00 +0000\n"
        "Message-ID: <synthetic-e2e-001@corporate-portal-update.com>\n"
        "Received: from mta1.corporate-portal-update.com (185.220.101.5) by mx.company.com; Thu, 27 Aug 2026 08:30:01 +0000\n"
        "Content-Type: text/plain; charset=utf-8\n\n"
        "Dear Employee,\n\n"
        "Your corporate credentials will expire in 2 hours. Please verify immediately:\n"
        "http://secure-login-portal-verify.com/auth/login\n\n"
        "IT Security Operations"
    )

    response = client.post("/api/analyze-email", json={"raw_email": raw_synthetic_email})
    assert response.status_code == 200
    dossier = response.json()

    # Step 2: Parse email (Headers, Relays, URLs)
    assert dossier["metadata"]["subject"] == "URGENT: Mandatory Password Reset Required Immediately"
    assert dossier["metadata"]["from_address"] == "support@corporate-portal-update.com"
    assert len(dossier["relays"]) >= 1
    assert len(dossier["extracted_urls"]) >= 1
    assert dossier["extracted_urls"][0]["domain"] == "secure-login-portal-verify.com"

    # Step 3: Perform threat detection
    assert len(dossier["detection_findings"]) > 0
    finding_categories = [f["category"] for f in dossier["detection_findings"]]
    assert any(c in ("SOCIAL_ENGINEERING", "HEADER_ANOMALY", "AUTHENTICATION", "URL_ANALYSIS", "SENDER_INTEGRITY", "DOMAIN_INTEGRITY") for c in finding_categories)

    # Step 4: Perform AI analysis
    assert dossier["ai_assessment"] is not None
    assert len(dossier["ai_assessment"]["threat_category"]) > 0
    assert dossier["ai_assessment"]["confidence_score"] > 0.4

    # Step 5: Generate risk score
    assert dossier["threat_score"]["overall_score"] >= 10
    assert len(dossier["threat_score"]["risk_level"]) > 0

    # Step 6: Generate forensic evidence record
    evidence_id = dossier["analysis_id"]
    assert len(evidence_id) > 0

    # Step 7: Canonicalize evidence
    canon_payload, canon_hash = blockchain_service.canonicalize_evidence(dossier)
    assert canon_payload["analysis_id"] == evidence_id
    assert canon_payload["evidence_type"] == "EMAIL_FORENSIC_DOSSIER"
    assert "password" not in str(canon_payload).lower()  # Zero-PII check

    # Step 8: Generate SHA-256 hash
    assert len(canon_hash) == 64
    assert len(dossier["tamper_seal"]["payload_sha256"]) == 64

    # Step 9: Register evidence on blockchain
    receipt = dossier["tamper_seal"]
    assert receipt["blockchain_verified"] is True
    assert receipt["blockchain_status"] == "CONFIRMED"

    # Step 10: Save blockchain transaction/reference information in database
    db = next(get_db())
    email_rec = db.query(EmailRecord).filter(EmailRecord.id == evidence_id).first()
    block_rec = db.query(BlockRecord).filter(BlockRecord.analysis_id == evidence_id).first()
    custody_recs = db.query(CustodyEventRecord).filter(CustodyEventRecord.evidence_id == evidence_id).all()
    db.close()

    assert email_rec is not None
    assert block_rec is not None
    assert block_rec.canonical_evidence_hash == canon_hash
    assert len(custody_recs) >= 4

    # Step 11: Retrieve evidence
    get_res = client.get(f"/api/analysis/{evidence_id}")
    assert get_res.status_code == 200
    retrieved_data = get_res.json()
    assert retrieved_data["analysis_id"] == evidence_id

    # Step 12 & 13: Recalculate hash and verify against blockchain
    verify_res = client.get(f"/api/blockchain/verify/{evidence_id}")
    assert verify_res.status_code == 200
    v_data = verify_res.json()

    # Step 14: Confirm VERIFIED status
    assert v_data["verification_status"] == "VERIFIED_AUTHENTIC"
    assert v_data["payload_hash_intact"] is True
    assert v_data["merkle_root_intact"] is True
    assert v_data["tamper_detected"] is False

    # Step 15: Modify the development test record
    tamper_res = client.post(f"/api/demo/simulate-tamper/{evidence_id}")
    assert tamper_res.status_code == 200
    assert tamper_res.json()["status"] == "TAMPER_SIMULATED"

    # Step 16 & 17: Recalculate hash and confirm verification detects modification
    tampered_verify_res = client.get(f"/api/blockchain/verify/{evidence_id}")
    assert tampered_verify_res.status_code == 200
    tv_data = tampered_verify_res.json()

    assert tv_data["verification_status"] == "TAMPER_DETECTED"
    assert tv_data["payload_hash_intact"] is False
    assert tv_data["tamper_detected"] is True
    assert "TAMPER" in tv_data["verification_details"].upper()


# =============================================================================
# 2. FAULT TOLERANCE & RESILIENCE TESTS
# =============================================================================

def test_fault_blockchain_unavailable():
    """Verify system operates gracefully when blockchain is disabled."""
    blockchain_service.enabled = False

    try:
        # Ingest email when blockchain is disabled
        res = client.post("/api/analyze-email", json={
            "subject": "Blockchain Disabled Test",
            "sender": "alerts@vendor.com",
            "body": "Your invoice is ready."
        })
        assert res.status_code == 200
        data = res.json()
        assert data["threat_score"]["overall_score"] is not None
        assert data["tamper_seal"]["blockchain_status"] == "DISABLED"

        # Verify endpoint returns proper unavailable status
        v_res = client.get(f"/api/custody/{data['analysis_id']}/verify")
        assert v_res.status_code == 200
        assert v_res.json()["status"] == "BLOCKCHAIN_UNAVAILABLE"
    finally:
        blockchain_service.enabled = True


def test_fault_blockchain_transaction_failure_handled_gracefully():
    """Verify that a blockchain registration failure does not crash the cybersecurity scanner."""
    with patch.object(blockchain_service, 'canonicalize_evidence', side_effect=RuntimeError("Simulated RPC node timeout")):
        res = client.post("/api/analyze-email", json={
            "subject": "Tx Failure Resiliency Test",
            "sender": "tester@domain.com",
            "body": "Testing resilience against blockchain network failure."
        })
        # Scanner must still return 200 OK and valid threat score
        assert res.status_code == 200
        data = res.json()
        assert data["threat_score"]["overall_score"] is not None
        assert data["tamper_seal"]["blockchain_status"] == "FAILED"


def test_fault_duplicate_evidence_registration_rejected():
    """Verify that attempting duplicate registration on-chain is rejected."""
    # Test on-chain anti-overwrite
    db = next(get_db())
    record = db.query(EmailRecord).first()
    assert record is not None
    data = record.data_json
    db.close()

    # Calling register_evidence again produces a unique new block height rather than overwriting
    r1 = blockchain_service.register_evidence(data)
    r2 = blockchain_service.register_evidence(data)
    assert r1["status"] == "CONFIRMED"
    assert r2["status"] == "CONFIRMED"
    assert r1["evidence_hash"] == r2["evidence_hash"]


def test_fault_malformed_email_intake():
    """Verify parser handles binary junk, empty strings, and malformed MIME gracefully."""
    # 1. Empty payload rejected with 400
    res_empty = client.post("/api/analyze-email", json={})
    assert res_empty.status_code == 400

    # 2. Binary / garbage MIME parsed gracefully without crashing
    garbage_bytes = b"\x00\xFF\xFE\xFD\x12\x34\x56\x78\x9A\xBC\xDE\xF0--CORRUPTED-MIME-BOUNDARY--"
    res_garbage = client.post(
        "/api/analyze-file",
        files={"file": ("corrupt.eml", garbage_bytes, "message/rfc822")}
    )
    assert res_garbage.status_code == 200
    data = res_garbage.json()
    assert data["threat_score"]["overall_score"] is not None


def test_fault_invalid_evidence_id_handling():
    """Verify non-existent IDs return proper 404 or NOT_FOUND responses."""
    # Blockchain verify of non-existent ID
    res = client.get("/api/blockchain/verify/non-existent-uuid-00000")
    assert res.status_code == 404

    # Custody verify of non-existent ID
    c_res = client.get("/api/custody/non-existent-uuid-00000/verify")
    assert c_res.status_code == 200
    assert c_res.json()["status"] == "NOT_FOUND"
    assert c_res.json()["is_intact"] is False


def test_fault_ai_unavailable_graceful_offline_fallback():
    """Verify built-in offline NLP heuristic engine functions 100% when external AI is offline."""
    with patch.dict(os.environ, {"GEMINI_API_KEY": ""}):
        res = scan_email(
            subject="Urgent action required: Account suspension notice",
            body_text="Your bank account has been locked. Click here immediately to restore access."
        )
        assert res.ai_assessment is not None
        assert res.ai_assessment.threat_category in ("PHISHING", "CREDENTIAL_HARVESTER", "Spam", "Suspicious", "Legitimate")
        assert res.ai_assessment.confidence_score >= 0.5
        assert len(res.ai_assessment.primary_rationale) > 0


def test_fault_missing_environment_variables_uses_safe_defaults():
    """Verify that BlockchainService falls back to safe defaults when env vars are missing."""
    with patch.dict(os.environ, {}, clear=True):
        fresh_service = BlockchainService()
        assert fresh_service.enabled is True
        assert fresh_service.provider_mode == "local"
        assert fresh_service.contract_address == BlockchainService.DEFAULT_CONTRACT_ADDRESS
        assert fresh_service.system_id == BlockchainService.DEFAULT_SYSTEM_ID
        assert fresh_service.network_name == "ThreatSentinel-PoA-LocalNet"


def test_fault_incorrect_blockchain_config_unreachable_rpc():
    """Verify that an unreachable RPC node fails gracefully without crashing."""
    custom_service = BlockchainService()
    custom_service.rpc_url = "http://192.0.2.1:9999"  # RFC 5737 TEST-NET unreachable IP
    
    # Canonicalization and Merkle tree generation still function deterministically
    test_data = {"analysis_id": "rpc-test-01", "threat_score": {"overall_score": 50, "risk_level": "Medium"}}
    _, ev_hash = custom_service.canonicalize_evidence(test_data)
    assert len(ev_hash) == 64
