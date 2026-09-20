with open('backend/tests/test_campaigns.py', 'r', encoding='utf-8') as f:
    text = f.read()

cleanup_code = """
def test_campaign_creation_and_merging():
    db = SessionLocal()
    # Cleanup before test
    db.query(CampaignRecord).delete()
    db.query(CaseRecord).delete()
    db.query(EmailRecord).delete()
    db.commit()
"""

text = text.replace('def test_campaign_creation_and_merging():\n    db = SessionLocal()', cleanup_code.strip())

cleanup_unrelated = """
def test_campaign_unrelated():
    db = SessionLocal()
    db.query(CampaignRecord).delete()
    db.query(CaseRecord).delete()
    db.query(EmailRecord).delete()
    db.commit()
"""
text = text.replace('def test_campaign_unrelated():\n    db = SessionLocal()', cleanup_unrelated.strip())

cleanup_weak = """
def test_campaign_weak_correlation():
    db = SessionLocal()
    db.query(CampaignRecord).delete()
    db.query(CaseRecord).delete()
    db.query(EmailRecord).delete()
    db.commit()
"""
text = text.replace('def test_campaign_weak_correlation():\n    db = SessionLocal()', cleanup_weak.strip())

with open('backend/tests/test_campaigns.py', 'w', encoding='utf-8') as f:
    f.write(text)
