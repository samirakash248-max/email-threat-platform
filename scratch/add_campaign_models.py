import os

with open('backend/app/models.py', 'r', encoding='utf-8') as f:
    text = f.read()

campaign_model = """
class CampaignRecord(Base):
    __tablename__ = "campaigns"
    
    id = Column(String, primary_key=True) # e.g. TS-CAMP-0001
    name = Column(String)
    status = Column(String, default="ACTIVE")
    correlation_level = Column(String) # LOW, MEDIUM, HIGH
    created_at = Column(DateTime(timezone=True), default=func.now())
    updated_at = Column(DateTime(timezone=True), default=func.now(), onupdate=func.now())
    first_seen = Column(DateTime(timezone=True), default=func.now())
    last_seen = Column(DateTime(timezone=True), default=func.now())
    
    related_cases = Column(JSON, default=list)
    related_indicators = Column(JSON, default=list) # {"type": "ip", "value": "1.1.1.1"}
    techniques = Column(JSON, default=list)
    correlation_reasons = Column(JSON, default=list)
"""

if "class CampaignRecord" not in text:
    text = text.replace("Base.metadata.create_all(bind=engine)", campaign_model + "\\nBase.metadata.create_all(bind=engine)")
    with open('backend/app/models.py', 'w', encoding='utf-8') as f:
        f.write(text)
