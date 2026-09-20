import os

with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Add imports
if "CampaignRecord" not in text:
    text = text.replace("from app.models import (", "from app.models import (\\n    CampaignRecord,")
    
if "correlate_case" not in text:
    text = text.replace("from app.graph_builder import build_graph_for_email, build_graph_for_case", "from app.graph_builder import build_graph_for_email, build_graph_for_case\\nfrom app.correlator import correlate_case")

# 2. Modify create_case
create_old = '''    db.add(c)
    db.commit()
    return get_case_by_id(case_id, db)'''
    
create_new = '''    db.add(c)
    db.commit()
    
    # Generate graph and correlate
    build_graph_for_case(c, db)
    correlate_case(c, db)
    
    return get_case_by_id(case_id, db)'''

if "correlate_case(c, db)" not in text:
    text = text.replace(create_old, create_new)

# 3. Add API Endpoints
endpoints = '''
@app.get("/api/campaigns")
def list_campaigns(db: Session = Depends(get_db)):
    camps = db.query(CampaignRecord).order_by(CampaignRecord.updated_at.desc()).all()
    return [{
        "id": c.id,
        "name": c.name,
        "status": c.status,
        "correlation_level": c.correlation_level,
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_seen": c.last_seen.isoformat() if c.last_seen else None,
        "cases_count": len(c.related_cases or []),
        "indicators_count": len(c.related_indicators or []),
        "techniques_count": len(c.techniques or []),
        "correlation_reasons": c.correlation_reasons
    } for c in camps]

@app.get("/api/campaigns/{camp_id}")
def get_campaign(camp_id: str, db: Session = Depends(get_db)):
    c = db.query(CampaignRecord).filter_by(id=camp_id).first()
    if not c: raise HTTPException(status_code=404, detail="Campaign not found")
    return {
        "id": c.id,
        "name": c.name,
        "status": c.status,
        "correlation_level": c.correlation_level,
        "first_seen": c.first_seen.isoformat() if c.first_seen else None,
        "last_seen": c.last_seen.isoformat() if c.last_seen else None,
        "related_cases": c.related_cases,
        "related_indicators": c.related_indicators,
        "techniques": c.techniques,
        "correlation_reasons": c.correlation_reasons
    }
'''

if "/api/campaigns" not in text:
    text = text.replace('if __name__ == "__main__":', endpoints + '\\nif __name__ == "__main__":')

# 4. Modify Dashboard Stats
stats_old = '''    active_cases = db.query(CaseRecord).filter(CaseRecord.status != "CLOSED").count()

    return DashboardStats('''

stats_new = '''    active_cases = db.query(CaseRecord).filter(CaseRecord.status != "CLOSED").count()
    active_campaigns = db.query(CampaignRecord).filter(CampaignRecord.status == "ACTIVE").count()

    return DashboardStats(
        active_campaigns=active_campaigns,'''

if "active_campaigns=active_campaigns" not in text:
    text = text.replace(stats_old, stats_new)

with open('backend/app/main.py', 'w', encoding='utf-8') as f:
    f.write(text)