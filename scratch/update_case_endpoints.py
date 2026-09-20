import os

with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Update Case Create to use "NEW" instead of "OPEN"
if 'status="OPEN"' in text:
    text = text.replace('status="OPEN",', 'status="NEW",')

# 2. Update PATCH Case logic to enforce lifecycle and assignment
patch_old = '''@app.patch("/api/cases/{case_id}", response_model=CaseResponse)
def update_case(case_id: str, payload: dict, db: Session = Depends(get_db)):
    c = db.query(CaseRecord).filter(CaseRecord.id == case_id).first()
    if not c: raise HTTPException(status_code=404, detail="Case not found")
    if "status" in payload:
        c.status = payload["status"]
        if payload["status"] in ("RESOLVED", "CLOSED"):
            for aid in (c.attached_analysis_ids or []):
                blockchain_service.append_custody_event(
                    evidence_id=aid,
                    event_type="EVIDENCE_ARCHIVED",
                    actor="Lead-Investigator",
                    details={"summary": f"Investigation Case {case_id} concluded and archived.", "action_code": "CASE_ARCHIVED"},
                    db=db
                )
    if "priority" in payload: c.priority = payload["priority"]
    c.updated_at = datetime.now(timezone.utc)
    db.commit()
    return get_case_by_id(case_id, db)'''

patch_new = '''@app.patch("/api/cases/{case_id}", response_model=CaseResponse)
def update_case(case_id: str, payload: dict, db: Session = Depends(get_db)):
    c = db.query(CaseRecord).filter(CaseRecord.id == case_id).first()
    if not c: raise HTTPException(status_code=404, detail="Case not found")
    
    # State Machine Definition
    VALID_TRANSITIONS = {
        "OPEN": ["NEW", "TRIAGED", "INVESTIGATING", "CLOSED"], # Legacy handling
        "NEW": ["TRIAGED", "CLOSED"],
        "TRIAGED": ["INVESTIGATING", "CLOSED"],
        "INVESTIGATING": ["CONTAINMENT_RECOMMENDED", "RESOLVED", "CLOSED"],
        "CONTAINMENT_RECOMMENDED": ["RESOLVED", "CLOSED"],
        "RESOLVED": ["CLOSED", "INVESTIGATING"],
        "CLOSED": ["INVESTIGATING"]
    }
    
    if "status" in payload:
        new_status = payload["status"].upper()
        current = c.status.upper() if c.status else "NEW"
        if new_status != current:
            if new_status not in VALID_TRANSITIONS.get(current, []):
                raise HTTPException(status_code=400, detail=f"Invalid transition from {current} to {new_status}")
            
            c.status = new_status
            actor = payload.get("actor", "SOC-Analyst")
            # Audit event
            for aid in (c.attached_analysis_ids or []):
                blockchain_service.append_custody_event(
                    evidence_id=aid,
                    event_type="STATUS_CHANGE",
                    actor=actor,
                    details={"summary": f"Case {case_id} status changed: {current} -> {new_status}", "action_code": "CASE_STATUS_UPDATED"},
                    db=db
                )
                
            if new_status in ("RESOLVED", "CLOSED"):
                for aid in (c.attached_analysis_ids or []):
                    blockchain_service.append_custody_event(
                        evidence_id=aid,
                        event_type="EVIDENCE_ARCHIVED",
                        actor=actor,
                        details={"summary": f"Investigation Case {case_id} {new_status.lower()}.", "action_code": "CASE_ARCHIVED"},
                        db=db
                    )
                    
    if "assigned_analyst" in payload:
        c.assigned_analyst = payload["assigned_analyst"]
        actor = payload.get("actor", "SOC-Analyst")
        for aid in (c.attached_analysis_ids or []):
            blockchain_service.append_custody_event(
                evidence_id=aid,
                event_type="ANALYST_ASSIGNED",
                actor=actor,
                details={"summary": f"Case {case_id} assigned to {c.assigned_analyst}", "action_code": "CASE_ASSIGNED"},
                db=db
            )
            
    if "priority" in payload: c.priority = payload["priority"]
    c.updated_at = datetime.now(timezone.utc)
    db.commit()
    return get_case_by_id(case_id, db)'''

if "VALID_TRANSITIONS = {" not in text:
    text = text.replace(patch_old, patch_new)

# 3. Add Export API Endpoint
export_api = '''
@app.get("/api/cases/{case_id}/export")
def export_case(case_id: str, db: Session = Depends(get_db)):
    c = db.query(CaseRecord).filter(CaseRecord.id == case_id).first()
    if not c: raise HTTPException(status_code=404, detail="Case not found")
    
    from app.correlator import extract_case_indicators
    inds = extract_case_indicators(case_id, db)
    
    techs = [r.technique_id for r in db.query(CaseAttackTechniqueRecord).filter_by(case_id=case_id).all()]
    
    # Fetch related campaigns
    camps = db.query(CampaignRecord).all()
    case_camps = [{"id": camp.id, "name": camp.name} for camp in camps if case_id in (camp.related_cases or [])]
    
    emails_meta = []
    for aid in (c.attached_analysis_ids or []):
        em = db.query(EmailRecord).filter_by(id=aid).first()
        if em:
            emails_meta.append({
                "id": em.id,
                "subject": em.subject,
                "threat_score": em.threat_score,
                "risk_level": em.risk_level,
                "triggered_rules": [f["rule_name"] for f in (em.data_json or {}).get("detection_findings", [])]
            })

    report = {
        "case_id": c.id,
        "title": c.title,
        "status": c.status,
        "priority": c.priority,
        "assigned_analyst": c.assigned_analyst,
        "created_at": c.created_at.isoformat() if c.created_at else None,
        "indicators": inds,
        "mitre_techniques": techs,
        "campaign_relationships": case_camps,
        "emails": emails_meta,
        "analyst_notes": c.notes_json
    }
    
    return report
'''

if "/api/cases/{case_id}/export" not in text:
    target = 'if __name__ == "__main__":'
    text = text.replace(target, export_api + "\\n" + target)

with open('backend/app/main.py', 'w', encoding='utf-8') as f:
    f.write(text)