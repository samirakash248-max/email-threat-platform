from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from app.models import Base, GraphEdgeRecord, CampaignRecord

engine = create_engine("sqlite:///threatsentinel_demo.db")
SessionLocal = sessionmaker(bind=engine)
db = SessionLocal()

print("Campaigns:")
camps = db.query(CampaignRecord).all()
for c in camps:
    print(c.id, c.related_cases)

print("\nEdges for 192.168.1.100:")
edges = db.query(GraphEdgeRecord).filter_by(target_id="192.168.1.100").all()
for e in edges:
    print(e.source_type, e.source_id, e.target_type, e.target_id, e.relation)

print("\nAll IP Edges:")
ip_edges = db.query(GraphEdgeRecord).filter_by(target_type="ip").all()
for e in ip_edges:
    print(e.source_type, e.source_id, e.target_type, e.target_id, e.relation)
