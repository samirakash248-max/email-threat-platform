import os
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, Column, String, Integer, DateTime, JSON, Text
from sqlalchemy.orm import declarative_base, sessionmaker

# Database Setup
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DB_PATH = os.path.join(BASE_DIR, "email_threat_platform.db")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DB_PATH.replace(os.sep, '/')}")

engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False} if DATABASE_URL.startswith("sqlite") else {}
)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# SQLAlchemy Models
class EmailRecord(Base):
    __tablename__ = "email_analyses"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    subject = Column(String, nullable=True)
    sender = Column(String, nullable=True, index=True)
    recipient = Column(String, nullable=True)
    threat_score = Column(Integer, default=0, index=True)
    risk_level = Column(String, default="Low", index=True)
    risk_color = Column(String, default="#10B981")
    data_json = Column(JSON, nullable=False)

class CaseRecord(Base):
    __tablename__ = "investigation_cases"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String, default="OPEN", index=True)
    priority = Column(String, default="HIGH", index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    attached_analysis_ids = Column(JSON, default=list)
    notes_json = Column(JSON, default=list)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic Schemas
class EmailInput(BaseModel):
    raw_email: Optional[str] = None
    headers: Optional[str] = None
    body: Optional[str] = None
    subject: Optional[str] = None
    sender: Optional[str] = None
    recipient: Optional[str] = None

class AuthStatus(BaseModel):
    status: str = "none"
    domain: Optional[str] = None
    explanation: str = "Not evaluated"

class AuthResults(BaseModel):
    spf: AuthStatus = Field(default_factory=AuthStatus)
    dkim: AuthStatus = Field(default_factory=AuthStatus)
    dmarc: AuthStatus = Field(default_factory=AuthStatus)
    raw_header: Optional[str] = None

class RelayHop(BaseModel):
    hop_number: int
    from_host: Optional[str] = None
    by_host: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp_utc: Optional[str] = None
    is_private_ip: bool = False
    organization: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    latitude: Optional[float] = None
    longitude: Optional[float] = None
    delay_seconds: Optional[float] = None
    role: str = "transit MTA"

class ExtractedURL(BaseModel):
    url: str
    domain: str
    is_ip_host: bool = False
    anchor_text: Optional[str] = None
    has_anchor_mismatch: bool = False
    source: str = "body"

class AttachmentInfo(BaseModel):
    filename: str
    content_type: str
    size_bytes: int
    md5: str
    sha256: str
    is_suspicious: bool = False

class ThreatFinding(BaseModel):
    rule_id: str
    rule_name: str
    category: str
    severity: str
    points: int
    explanation: str
    evidence: Optional[str] = None

class ThreatScore(BaseModel):
    overall_score: int
    risk_level: str
    risk_color: str
    explanation: str
    findings: List[ThreatFinding] = []

class IOCItem(BaseModel):
    type: str
    value: str
    source: str
    context: Optional[str] = None

class AIAssessment(BaseModel):
    threat_category: str
    confidence_score: float = 0.90
    primary_rationale: str
    key_contributing_factors: List[str] = []
    observed_evidence: List[str] = []
    inferred_evidence: List[str] = []
    unknown_gaps: List[str] = []
    recommended_analyst_actions: List[str] = []
    investigation_priority_score: int = 50
    priority_explanation: str = ""

class TamperSeal(BaseModel):
    seal_id: str
    timestamp_utc: str
    payload_sha256: str
    current_seal_hash: str
    previous_seal_hash: str = "0000000000000000000000000000000000000000000000000000000000000000"
    signer_identity: str = "ThreatSentinel-Ledger"
    is_valid: bool = True

class FullAnalysisResult(BaseModel):
    analysis_id: str
    timestamp: str
    metadata: Dict[str, Any]
    authentication: AuthResults
    relays: List[RelayHop] = []
    relay_graph: Dict[str, Any] = {}
    extracted_urls: List[ExtractedURL] = []
    url_forensics: List[Dict[str, Any]] = []
    ip_intelligence: Dict[str, Any] = {}
    domain_intelligence: Dict[str, Any] = {}
    attachments: List[AttachmentInfo] = []
    detection_findings: List[ThreatFinding] = []
    threat_score: ThreatScore
    investigation_summary: Dict[str, Any] = {}
    timeline: List[Dict[str, Any]] = []
    iocs: List[IOCItem] = []
    ai_assessment: Optional[AIAssessment] = None
    tamper_seal: Optional[TamperSeal] = None

class CaseCreate(BaseModel):
    title: str
    description: Optional[str] = None
    priority: str = "HIGH"
    initial_analysis_id: Optional[str] = None

class CaseNoteCreate(BaseModel):
    author: Optional[str] = "SOC Analyst"
    content: str

class CaseResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    status: str = "OPEN"
    priority: str = "HIGH"
    created_at: str
    updated_at: str
    attached_analyses: List[FullAnalysisResult] = []
    notes: List[Dict[str, Any]] = []

class DashboardStats(BaseModel):
    total_analyzed_emails: int
    high_critical_threats: int
    active_cases: int
    suspicious_domains_count: int
    suspicious_ips_count: int
    threat_distribution: Dict[str, int]
    top_categories: Dict[str, int]
    recent_analyses: List[Dict[str, Any]]
