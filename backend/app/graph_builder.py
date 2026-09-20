import uuid
from sqlalchemy.orm import Session
from app.models import EmailRecord, CaseRecord, GraphEdgeRecord

def build_graph_for_email(email: EmailRecord, db: Session):
    # clear existing
    db.query(GraphEdgeRecord).filter(GraphEdgeRecord.source_type == "email", GraphEdgeRecord.source_id == email.id).delete()
    
    edges = []
    def add_edge(tgt_type, tgt_id, rel):
        if not tgt_id: return
        edges.append(GraphEdgeRecord(
            source_type="email", source_id=email.id,
            target_type=tgt_type, target_id=tgt_id, relation=rel
        ))
        
    d = email.data_json or {}
    
    # Sender
    if email.sender:
        add_edge("sender", email.sender, "SENT_BY")
        if "@" in email.sender:
            add_edge("domain", email.sender.split("@")[-1].lower(), "REFERENCES")
            
    # URLs and Domains
    for url in d.get("extracted_urls", []):
        add_edge("url", url.get("url"), "CONTAINS_URL")
        add_edge("domain", url.get("domain"), "REFERENCES")
        if url.get("is_ip_host"):
            add_edge("ip", url.get("domain"), "CONNECTS_TO")
            
    # Relays (IPs)
    for r in d.get("relays", []):
        add_edge("ip", r.get("ip_address"), "CONNECTS_TO")
        if r.get("hostname"):
            add_edge("domain", r.get("hostname"), "REFERENCES")
            
    # Attachments
    for a in d.get("attachments", []):
        add_edge("attachment", a.get("filename"), "CONTAINS_ATTACHMENT")
        add_edge("hash", a.get("sha256"), "HAS_HASH")
        
    # MITRE Techniques
    for m in d.get("mitre_attack_mappings", []):
        add_edge("technique", m.get("technique_id"), "MAPS_TO")
        
    if edges:
        db.bulk_save_objects(edges)
        db.commit()

def build_graph_for_case(case: CaseRecord, db: Session):
    db.query(GraphEdgeRecord).filter(GraphEdgeRecord.source_type == "case", GraphEdgeRecord.source_id == case.id).delete()
    
    edges = []
    for aid in (case.attached_analysis_ids or []):
        edges.append(GraphEdgeRecord(
            source_type="case", source_id=case.id,
            target_type="email", target_id=aid, relation="CONTAINS_EMAIL"
        ))
    if edges:
        db.bulk_save_objects(edges)
        db.commit()