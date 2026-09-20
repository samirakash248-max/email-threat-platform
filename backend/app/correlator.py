import uuid
from datetime import datetime, timezone
from sqlalchemy.orm import Session
from app.models import CaseRecord, EmailRecord, CampaignRecord, GraphEdgeRecord

def extract_case_indicators(case_id: str, db: Session):
    # Extracts all indicators related to this case by traversing case -> email -> indicators
    edges = db.query(GraphEdgeRecord).filter_by(source_type="case", source_id=case_id).all()
    email_ids = [e.target_id for e in edges if e.target_type == "email"]
    
    indicators = {}
    for eid in email_ids:
        iedges = db.query(GraphEdgeRecord).filter_by(source_type="email", source_id=eid).all()
        for ie in iedges:
            indicators.setdefault(ie.target_type, set()).add(ie.target_id)
    return indicators

def correlate_case(new_case: CaseRecord, db: Session):
    new_inds = extract_case_indicators(new_case.id, db)
    if not new_inds: return
    
    # We want to find overlap with other cases.
    # To avoid N^2, we could just look up the target_ids in GraphEdgeRecord
    # target_id -> email -> case.
    
    case_scores = {}
    case_reasons = {}
    
    # Reverse lookup map
    # tgt_type -> tgt_id -> set(case_ids)
    
    for t_type, t_vals in new_inds.items():
        for val in t_vals:
            # Find emails with this indicator
            hitting_edges = db.query(GraphEdgeRecord).filter_by(target_type=t_type, target_id=val, source_type="email").all()
            email_ids = {he.source_id for he in hitting_edges}
            
            # Find cases containing these emails
            for eid in email_ids:
                c_edges = db.query(GraphEdgeRecord).filter_by(target_type="email", target_id=eid, source_type="case").all()
                for ce in c_edges:
                    other_case_id = ce.source_id
                    if other_case_id != new_case.id:
                        score_inc = 0
                        reason = ""
                        if t_type == "hash": score_inc, reason = 50, f"Shared attachment SHA256 ({val})"
                        elif t_type == "url": score_inc, reason = 40, f"Shared exact URL ({val})"
                        elif t_type == "ip": score_inc, reason = 30, f"Shared infrastructure IP ({val})"
                        elif t_type == "domain": score_inc, reason = 30, f"Shared domain ({val})"
                        elif t_type == "sender": score_inc, reason = 20, f"Shared sender address ({val})"
                        elif t_type == "technique": score_inc, reason = 5, f"Shared MITRE ATT&CK technique ({val})"
                        
                        if score_inc > 0:
                            case_scores[other_case_id] = case_scores.get(other_case_id, 0) + score_inc
                            case_reasons.setdefault(other_case_id, set()).add(reason)

    best_match_id = None
    best_score = 0
    for cid, score in case_scores.items():
        if score > best_score:
            best_score = score
            best_match_id = cid
            
    if best_score >= 25:
        # Find if best_match_id belongs to a campaign
        camps = db.query(CampaignRecord).all()
        target_camp = None
        for c in camps:
            if best_match_id in (c.related_cases or []):
                target_camp = c
                break
                
        if target_camp:
            # Add to existing
            rc = set(target_camp.related_cases or [])
            rc.add(new_case.id)
            target_camp.related_cases = list(rc)
            
            # Update reasons & indicators
            cr = set(target_camp.correlation_reasons or [])
            cr.update(case_reasons[best_match_id])
            target_camp.correlation_reasons = list(cr)
            
            # Add new indicators
            inds = target_camp.related_indicators or []
            existing_inds = {f"{i['type']}:{i['value']}" for i in inds}
            for t_type, t_vals in new_inds.items():
                if t_type == 'technique': continue
                for val in t_vals:
                    if f"{t_type}:{val}" not in existing_inds:
                        inds.append({"type": t_type, "value": val})
                        existing_inds.add(f"{t_type}:{val}")
            target_camp.related_indicators = inds
            
            # Update techniques
            techs = set(target_camp.techniques or [])
            techs.update(new_inds.get("technique", set()))
            target_camp.techniques = list(techs)
            
            # Update score
            target_camp.correlation_level = "HIGH" if best_score >= 50 else "MEDIUM"
            target_camp.updated_at = datetime.now(timezone.utc)
            db.commit()
            return
            
    # Create new campaign candidate
    camp_num = db.query(CampaignRecord).count() + 1
    new_camp = CampaignRecord(
        id=f"TS-CAMP-{camp_num:04d}",
        name=f"Campaign TS-CAMP-{camp_num:04d}",
        status="ACTIVE",
        correlation_level="LOW" if best_score < 25 else ("HIGH" if best_score >= 50 else "MEDIUM"),
        related_cases=[new_case.id],
        correlation_reasons=list(case_reasons.get(best_match_id, set())) if best_match_id else []
    )
    if best_match_id and best_score >= 25:
        new_camp.related_cases.append(best_match_id)
        
    inds = []
    for t_type, t_vals in new_inds.items():
        if t_type == 'technique': continue
        for val in t_vals:
            inds.append({"type": t_type, "value": val})
            
    new_camp.related_indicators = inds
    new_camp.techniques = list(new_inds.get("technique", set()))
    
    db.add(new_camp)
    db.commit()
