with open('backend/tests/test_campaigns.py', 'a') as f:
    f.write("\n\n")
    f.write("""def test_campaign_api_returns_related_cases():
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
""")
