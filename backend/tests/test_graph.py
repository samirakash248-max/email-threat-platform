from app.graph_builder import build_graph_for_email, build_graph_for_case
from app.models import EmailRecord, CaseRecord, GraphEdgeRecord

def test_graph_email():
    from app.models import SessionLocal
    setup_test_database = SessionLocal()
    e = EmailRecord(id="test-graph-email-1", sender="bad@evil.com", data_json={
        "extracted_urls": [{"url": "http://evil.com/login", "domain": "evil.com", "is_ip_host": False}],
        "relays": [{"ip_address": "1.1.1.1"}],
        "attachments": [{"filename": "bad.exe", "sha256": "abcdef"}],
        "mitre_attack_mappings": [{"technique_id": "T1566"}]
    })
    setup_test_database.add(e)
    setup_test_database.commit()
    
    build_graph_for_email(e, setup_test_database)
    
    edges = setup_test_database.query(GraphEdgeRecord).filter_by(source_id=e.id).all()
    targets = [(edge.target_type, edge.target_id) for edge in edges]
    
    assert ("sender", "bad@evil.com") in targets
    assert ("domain", "evil.com") in targets
    assert ("url", "http://evil.com/login") in targets
    assert ("ip", "1.1.1.1") in targets
    assert ("attachment", "bad.exe") in targets
    assert ("hash", "abcdef") in targets
    assert ("technique", "T1566") in targets

def test_graph_case():
    from app.models import SessionLocal
    setup_test_database = SessionLocal()
    c = CaseRecord(id="test-case-1", title="Test Graph Case", attached_analysis_ids=["test-graph-email-1"])
    setup_test_database.add(c)
    setup_test_database.commit()
    
    build_graph_for_case(c, setup_test_database)
    
    edges = setup_test_database.query(GraphEdgeRecord).filter_by(source_id=c.id).all()
    assert len(edges) == 1
    assert edges[0].target_type == "email"
    assert edges[0].target_id == "test-graph-email-1"