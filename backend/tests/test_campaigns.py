from app.models import SessionLocal, CaseRecord, EmailRecord, CampaignRecord
from app.graph_builder import build_graph_for_email, build_graph_for_case
from app.correlator import correlate_case

def setup_case(db_session, case_id, email_id, sender, hash_val, technique):
    e = EmailRecord(id=email_id, sender=sender, data_json={
        "attachments": [{"filename": "bad.exe", "sha256": hash_val}] if hash_val else [],
        "mitre_attack_mappings": [{"technique_id": technique}] if technique else []
    })
    c = CaseRecord(id=case_id, title=f"Case {case_id}", attached_analysis_ids=[email_id])
    db_session.add(e)
    db_session.add(c)
    db_session.commit()
    build_graph_for_email(e, db_session)
    build_graph_for_case(c, db_session)
    return c

def test_campaign_creation_and_merging():
    db = SessionLocal()
    # Cleanup before test
    db.query(CampaignRecord).delete()
    db.query(CaseRecord).delete()
    db.query(EmailRecord).delete()
    db.commit()
    # Case A: hash=ABC
    ca = setup_case(db, "case-a", "email-a", "bad@evil.com", "ABC", "T1566")
    correlate_case(ca, db)
    
    # Should create a new campaign
    camps = db.query(CampaignRecord).all()
    assert len(camps) == 1
    camp1 = camps[0]
    assert "case-a" in camp1.related_cases
    assert camp1.correlation_level in ["LOW", "MEDIUM", "HIGH"]
    
    # Case B: hash=ABC (strong correlation -> merge)
    cb = setup_case(db, "case-b", "email-b", "other@evil.com", "ABC", None)
    correlate_case(cb, db)
    
    db.refresh(camp1)
    assert "case-b" in camp1.related_cases
    assert camp1.correlation_level == "HIGH"  # Hash is +50
    
    # Check explanations
    assert any("Shared attachment SHA256" in r for r in camp1.correlation_reasons)

def test_campaign_unrelated():
    db = SessionLocal()
    db.query(CampaignRecord).delete()
    db.query(CaseRecord).delete()
    db.query(EmailRecord).delete()
    db.commit()
    # Case C: totally unrelated
    cc = setup_case(db, "case-c", "email-c", "clean@good.com", "XYZ", "T1566.001")
    correlate_case(cc, db)
    
    # Should create a NEW campaign for Case C
    camps = db.query(CampaignRecord).all()
    camp_c = [c for c in camps if "case-c" in c.related_cases][0]
    assert "case-a" not in camp_c.related_cases

def test_campaign_weak_correlation():
    db = SessionLocal()
    db.query(CampaignRecord).delete()
    db.query(CaseRecord).delete()
    db.query(EmailRecord).delete()
    db.commit()
    # Case D: only shares technique with Case A (weak)
    cd = setup_case(db, "case-d", "email-d", "anon@anon.com", "123", "T1566")
    correlate_case(cd, db)
    
    # Technique is +5, so it shouldn't merge into Case A's campaign
    camps = db.query(CampaignRecord).all()
    camp_d = [c for c in camps if "case-d" in c.related_cases][0]
    assert "case-a" not in camp_d.related_cases
    assert camp_d.correlation_level == "LOW"


def test_campaign_api_returns_related_cases():
    from fastapi.testclient import TestClient
    from app.main import app
    client = TestClient(app)
    
    db = SessionLocal()
    db.query(CampaignRecord).delete()
    db.query(CaseRecord).delete()
    db.query(EmailRecord).delete()
    db.commit()
    
    c = setup_case(db, "case-api", "email-api", "bad@evil.com", "API-HASH", "T1566")
    correlate_case(c, db)
    
    res = client.get("/api/campaigns")
    assert res.status_code == 200
    data = res.json()
    assert len(data) >= 1
    
    # Regression check: the API MUST return related_cases list, not just cases_count
    assert "related_cases" in data[0], "related_cases field missing from API response!"
    assert "case-api" in data[0]["related_cases"]
