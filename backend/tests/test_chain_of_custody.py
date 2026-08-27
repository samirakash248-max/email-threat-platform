import os
import sys
import copy
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.models import get_db, EmailRecord, CustodyEventRecord
from app.blockchain import blockchain_service

client = TestClient(app)

def test_initial_custody_chain_creation():
    # 1. Reset demo fixtures
    reset_res = client.post("/api/demo/reset")
    assert reset_res.status_code == 200

    # 2. Get first analysis ID
    db = next(get_db())
    record = db.query(EmailRecord).first()
    assert record is not None
    evidence_id = record.id
    db.close()

    # 3. Retrieve custody chain
    res = client.get(f"/api/custody/{evidence_id}")
    assert res.status_code == 200
    data = res.json()

    assert data["status"] == "VERIFIED"
    assert data["is_intact"] is True
    assert data["total_events"] >= 4

    event_types = [e["event_type"] for e in data["events"]]
    assert "EVIDENCE_CREATED" in event_types
    assert "EVIDENCE_ANALYZED" in event_types
    assert "AI_ANALYSIS_COMPLETED" in event_types
    assert "THREAT_CLASSIFICATION_ASSIGNED" in event_types

    # Check hash-chain integrity
    for i in range(1, len(data["events"])):
        assert data["events"][i]["previous_event_hash"] == data["events"][i-1]["event_hash"]


def test_append_custody_lifecycle_events():
    db = next(get_db())
    record = db.query(EmailRecord).first()
    evidence_id = record.id
    db.close()

    # 1. Add Analyst Review Event
    review_res = client.post(f"/api/custody/event/{evidence_id}", json={
        "event_type": "ANALYST_REVIEW",
        "actor": "Lead-SOC-Analyst",
        "details": {
            "summary": "Analyst performed deep inspection of DKIM signature header.",
            "action_code": "HEADER_DEEP_DIVE"
        }
    })
    assert review_res.status_code == 200
    rev_data = review_res.json()
    assert rev_data["event_type"] == "ANALYST_REVIEW"
    assert rev_data["sequence_number"] >= 5
    assert len(rev_data["event_hash"]) == 64

    # 2. Export Report (triggers REPORT_GENERATED)
    report_res = client.get(f"/api/analysis/{evidence_id}/report")
    assert report_res.status_code == 200

    # 3. Verify Chain Integrity after additions
    verify_res = client.get(f"/api/custody/{evidence_id}/verify")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    assert v_data["status"] == "VERIFIED"
    assert v_data["is_intact"] is True
    assert v_data["total_events"] >= 6

    types = [e["event_type"] for e in v_data["events"]]
    assert "REPORT_GENERATED" in types


def test_custody_tamper_detection():
    db = next(get_db())
    record = db.query(EmailRecord).first()
    evidence_id = record.id

    # Find second event in the chain
    event_rec = (
        db.query(CustodyEventRecord)
        .filter(CustodyEventRecord.evidence_id == evidence_id, CustodyEventRecord.sequence_number == 2)
        .first()
    )
    assert event_rec is not None

    # Directly mutate event data in SQLite to simulate tampering
    from sqlalchemy.orm.attributes import flag_modified
    tampered_data = copy.deepcopy(event_rec.event_data_json)
    tampered_data["summary"] = "HACKER TAMPERED SUMMARY"
    event_rec.event_data_json = tampered_data
    flag_modified(event_rec, "event_data_json")
    db.commit()
    db.close()

    # Verify that Custody Verification Flags MODIFIED
    tamper_res = client.get(f"/api/custody/{evidence_id}/verify")
    assert tamper_res.status_code == 200
    t_data = tamper_res.json()

    assert t_data["status"] == "MODIFIED"
    assert t_data["is_intact"] is False
    assert t_data["broken_event_index"] == 2
    assert "TAMPER ALERT" in t_data["verification_details"]


def test_custody_not_found():
    res = client.get("/api/custody/non-existent-id-99999")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "NOT_FOUND"
    assert data["is_intact"] is False


def test_custody_blockchain_unavailable():
    blockchain_service.enabled = False

    res = client.get("/api/custody/any-id")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "BLOCKCHAIN_UNAVAILABLE"
    assert data["is_intact"] is False

    # Re-enable
    blockchain_service.enabled = True
