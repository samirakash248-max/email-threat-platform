import os
import sys
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.models import get_db, EmailRecord, BlockRecord
from app.blockchain import MerkleTree, blockchain_service

client = TestClient(app)

def test_merkle_tree_basics():
    leaves = [
        "AUTH_SPF:pass",
        "AUTH_DKIM:pass",
        "SCORE:0",
        "TIER:Low"
    ]
    tree = MerkleTree(leaves)
    assert len(tree.root) == 64
    assert tree.root != "0" * 64

    # Test inclusion proof
    proof = tree.get_proof(0)
    leaf_hash = tree._hash_leaf(leaves[0])
    is_valid = MerkleTree.verify_proof(leaf_hash, proof, tree.root)
    assert is_valid is True

    # Tampered leaf should fail verification
    tampered_hash = tree._hash_leaf("AUTH_SPF:fail")
    assert MerkleTree.verify_proof(tampered_hash, proof, tree.root) is False


def test_deterministic_canonical_hashing_non_sensitive():
    evidence_data = {
        "analysis_id": "test-analysis-123",
        "metadata": {
            "subject": "Sensitive Company Payroll Password Discussion",
            "from_address": "ceo@company.com",
            "to_addresses": ["finance@company.com"],
            "raw_body": "Top secret confidential text that should NEVER be on-chain!"
        },
        "threat_score": {"overall_score": 85, "risk_level": "Critical"},
        "ai_assessment": {"threat_category": "CREDENTIAL_THEFT"},
        "authentication": {
            "spf": {"status": "fail"},
            "dkim": {"status": "fail"},
            "dmarc": {"status": "fail"}
        },
        "relays": [{"hop_number": 1, "ip_address": "198.51.100.1"}],
        "detection_findings": [{"rule_id": "RULE-001"}],
        "attachments": []
    }

    non_sensitive, evidence_hash = blockchain_service.canonicalize_evidence(evidence_data)

    # Verify that NO raw body text or email passwords exist in the on-chain payload
    assert "raw_body" not in non_sensitive
    assert "Top secret confidential" not in str(non_sensitive)
    assert non_sensitive["threat_classification"] == "CREDENTIAL_THEFT"
    assert non_sensitive["risk_score"] == 85
    assert len(evidence_hash) == 64

    # Verify deterministic output (same input produces exact same hash)
    _, evidence_hash_2 = blockchain_service.canonicalize_evidence(evidence_data)
    assert evidence_hash == evidence_hash_2


def test_blockchain_registration_and_chaining():
    evidence_1 = {
        "analysis_id": "test-email-01",
        "threat_score": {"overall_score": 10, "risk_level": "Low"},
        "ai_assessment": {"threat_category": "BENIGN_COMMUNICATION"},
        "authentication": {"spf": {"status": "pass"}, "dkim": {"status": "pass"}, "dmarc": {"status": "pass"}},
        "relays": [],
        "detection_findings": [],
        "attachments": []
    }
    receipt_1 = blockchain_service.register_evidence(evidence_1)
    assert receipt_1["status"] == "CONFIRMED"
    assert receipt_1["block_number"] == 1
    assert receipt_1["previous_hash"] == blockchain_service.GENESIS_PREV_HASH
    assert receipt_1["tx_id"].startswith("0x")
    assert len(receipt_1["block_hash"]) == 64
    assert len(receipt_1["merkle_root"]) == 64

    evidence_2 = {
        "analysis_id": "test-email-02",
        "threat_score": {"overall_score": 75, "risk_level": "High"},
        "ai_assessment": {"threat_category": "BEC_FRAUD"},
        "authentication": {"spf": {"status": "fail"}, "dkim": {"status": "fail"}, "dmarc": {"status": "fail"}},
        "relays": [],
        "detection_findings": [],
        "attachments": []
    }
    receipt_2 = blockchain_service.register_evidence(evidence_2, previous_block=receipt_1)
    assert receipt_2["status"] == "CONFIRMED"
    assert receipt_2["block_number"] == 2
    assert receipt_2["previous_hash"] == receipt_1["block_hash"]
    assert receipt_2["block_hash"] != receipt_1["block_hash"]


def test_blockchain_api_workflow_and_tamper_detection():
    # 1. Reset Demo and Ledger
    r = client.post("/api/demo/reset")
    assert r.status_code == 200

    # 2. Check Blockchain Stats
    stats_res = client.get("/api/blockchain/stats")
    assert stats_res.status_code == 200
    stats = stats_res.json()
    assert stats["total_blocks"] >= 10
    assert stats["chain_integrity_status"] == "INTACT"
    assert stats["contract_address"].startswith("0x")

    # 3. Check Contract Info
    contract_res = client.get("/api/blockchain/contract")
    assert contract_res.status_code == 200
    contract_info = contract_res.json()
    assert contract_info["contract_name"] == "EvidenceRegistry"
    assert len(contract_info["abi"]) > 0

    # 4. Check Ledger Explorer
    ledger_res = client.get("/api/blockchain/ledger")
    assert ledger_res.status_code == 200
    ledger = ledger_res.json()
    assert len(ledger) >= 10
    first_block = ledger[0]
    assert first_block["block_number"] == 1
    assert first_block["previous_hash"] == blockchain_service.GENESIS_PREV_HASH

    # 5. Verify authentic analysis
    target_id = first_block["analysis_id"]
    verify_res = client.get(f"/api/blockchain/verify/{target_id}")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["verification_status"] == "VERIFIED_AUTHENTIC"
    assert v_data["tamper_detected"] is False
    assert v_data["payload_hash_intact"] is True
    assert v_data["merkle_root_intact"] is True
    assert v_data["tx_id"].startswith("0x")

    # 6. Check Status Endpoint
    status_res = client.get(f"/api/blockchain/status/{target_id}")
    assert status_res.status_code == 200
    s_data = status_res.json()
    assert s_data["is_registered"] is True
    assert s_data["status"] == "CONFIRMED"

    # 7. Tamper Test: Directly mutate the database record in SQLite
    from sqlalchemy.orm.attributes import flag_modified
    import copy

    db = next(get_db())
    record = db.query(EmailRecord).filter(EmailRecord.id == target_id).first()
    assert record is not None
    tampered_json = copy.deepcopy(record.data_json)
    tampered_json["threat_score"]["overall_score"] = 99
    record.data_json = tampered_json
    flag_modified(record, "data_json")
    db.commit()
    db.close()

    # 8. Verify that Blockchain Instantly Detects the Tampering!
    tamper_verify_res = client.get(f"/api/blockchain/verify/{target_id}")
    assert tamper_verify_res.status_code == 200
    tv_data = tamper_verify_res.json()
    assert tv_data["verification_status"] == "TAMPER_DETECTED"
    assert tv_data["tamper_detected"] is True
    assert tv_data["payload_hash_intact"] is False
    assert "tampering detected" in tv_data["verification_details"].lower()


def test_blockchain_graceful_failure_handling():
    # Test that scan succeeds even if blockchain is disabled
    blockchain_service.enabled = False

    scan_res = client.post("/api/analyze-email", json={
        "sender": "external@domain.com",
        "subject": "Resilience Test Email",
        "body": "Testing graceful fallback when blockchain is offline."
    })

    assert scan_res.status_code == 200
    data = scan_res.json()
    assert "analysis_id" in data
    assert data["tamper_seal"] is not None

    # Re-enable blockchain for other tests
    blockchain_service.enabled = True
