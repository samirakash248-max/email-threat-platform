import os
import uuid
from datetime import datetime, timezone
from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, func, Column, String, Integer, DateTime, JSON, Text
from sqlalchemy.orm import declarative_base, sessionmaker

# Database Setup - Fixed Absolute Path to ensure persistent data across restarts
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
DEFAULT_DB_FILE = os.path.join(ROOT_DIR, "email_threat_platform.db")

env_db_url = os.getenv("DATABASE_URL")
if not env_db_url or env_db_url.strip() in ("sqlite:///./email_threat_platform.db", "sqlite:///:memory:"):
    DATABASE_URL = f"sqlite:///{DEFAULT_DB_FILE.replace(os.sep, '/')}"
else:
    DATABASE_URL = env_db_url

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
    status = Column(String, default="NEW", index=True)
    priority = Column(String, default="HIGH", index=True)
    assigned_analyst = Column(String, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    attached_analysis_ids = Column(JSON, default=list)
    notes_json = Column(JSON, default=list)

class BlockRecord(Base):
    __tablename__ = "blockchain_ledger"

    block_number = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    block_hash = Column(String, nullable=False, unique=True, index=True)
    previous_hash = Column(String, nullable=False)
    analysis_id = Column(String, nullable=False, index=True)
    merkle_root = Column(String, nullable=False)
    canonical_evidence_hash = Column(String, nullable=False)
    block_data_json = Column(JSON, nullable=False)

class CustodyEventRecord(Base):
    __tablename__ = "chain_of_custody_events"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    evidence_id = Column(String, nullable=False, index=True)
    sequence_number = Column(Integer, nullable=False)
    event_type = Column(String, nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    actor = Column(String, nullable=False)
    event_hash = Column(String, nullable=False)
    previous_event_hash = Column(String, nullable=False)
    tx_id = Column(String, nullable=True)
    block_number = Column(Integer, nullable=True)
    event_data_json = Column(JSON, nullable=False)

class ThreatIntelRecord(Base):
    __tablename__ = "threat_intel_indicators"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    indicator_type = Column(String, nullable=False, index=True)  # DOMAIN, URL_HASH, IP_ADDRESS, FILE_HASH, SENDER_DOMAIN
    indicator_value = Column(String, nullable=False, index=True)
    indicator_hash = Column(String, nullable=False, unique=True, index=True)
    threat_category = Column(String, nullable=False)
    severity = Column(String, nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score = Column(Integer, default=85)
    source_org = Column(String, nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    tx_id = Column(String, nullable=True)
    block_number = Column(Integer, nullable=True)
    observation_count = Column(Integer, default=1)
    details_json = Column(JSON, default=dict)

class AttackTechniqueRecord(Base):
    __tablename__ = "attack_techniques"
    id = Column(String, primary_key=True)
    name = Column(String, nullable=False)
    tactic = Column(String, nullable=False)
    description = Column(Text, nullable=True)

class CaseAttackTechniqueRecord(Base):
    __tablename__ = "case_attack_techniques"
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    case_id = Column(String, index=True)
    technique_id = Column(String, index=True)
    confidence = Column(String)
    reason = Column(Text)
    supporting_indicators = Column(JSON, default=list)

class GraphEdgeRecord(Base):
    __tablename__ = "graph_edges"
    
    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    source_type = Column(String, index=True) # "email", "case"
    source_id = Column(String, index=True)
    target_type = Column(String, index=True) # "ip", "domain", "url", "hash", "sender", "technique", "email", "case"
    target_id = Column(String, index=True)
    relation = Column(String, index=True) # "CONNECTS_TO", "REFERENCES", "CONTAINS_URL", "HAS_HASH", "MAPS_TO", "SENT_BY", "BELONGS_TO"


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

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Pydantic Schemas
class EmailInput(BaseModel):
    raw_email: Optional[str] = Field(None, max_length=15_000_000, description="Max 15MB RFC 5322 payload")
    headers: Optional[str] = Field(None, max_length=1_000_000)
    body: Optional[str] = Field(None, max_length=15_000_000)
    subject: Optional[str] = Field(None, max_length=1000)
    sender: Optional[str] = Field(None, max_length=500)
    recipient: Optional[str] = Field(None, max_length=500)


class ReputationSourceResult(BaseModel):
    provider: str
    listed: bool
    response: Optional[str] = None
    status: str

class ReputationResult(BaseModel):
    indicator: str
    indicator_type: str = "IP"
    listed: bool
    sources: List[str] = []
    source_results: List[ReputationSourceResult] = []
    confidence: int = 0
    checked_at: str
    provider_status: str
    botnet_association: str = "UNKNOWN"

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

class URLRiskSignal(BaseModel):
    rule_name: str
    description: str
    score_contribution: int

class ExtractedURL(BaseModel):
    url: str
    domain: str
    is_ip_host: bool = False
    anchor_text: Optional[str] = None
    has_anchor_mismatch: bool = False
    source: str = "body"
    
    # URL Intelligence Enhanced Fields
    normalized_url: Optional[str] = None
    hostname: Optional[str] = None
    scheme: Optional[str] = None
    path: Optional[str] = None
    query: Optional[str] = None
    port: Optional[int] = None
    risk_score: int = 0
    risk_level: str = "Safe"
    suspicious_features: List[str] = Field(default_factory=list)
    triggered_rules: List[URLRiskSignal] = Field(default_factory=list)

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
    block_number: Optional[int] = None
    block_hash: Optional[str] = None
    tx_id: Optional[str] = None
    contract_address: Optional[str] = None
    merkle_root: Optional[str] = None
    blockchain_status: str = "CONFIRMED"
    blockchain_verified: bool = True

class MitreAttackMapping(BaseModel):
    technique_id: str
    technique_name: str
    tactic: str
    reason: str
    supporting_indicators: List[str] = Field(default_factory=list)
    confidence: str

class InvestigativeAssessment(BaseModel):
    vector: str
    confidence: int
    reasons: List[str] = []
    supporting_indicators: List[str] = []
    evidence_basis: List[str] = []
    assessment_type: str = "INVESTIGATIVE_ASSESSMENT"

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
    mitre_attack_mappings: List[MitreAttackMapping] = Field(default_factory=list)

class CaseCreate(BaseModel):
    title: str = Field(..., min_length=1, max_length=256)
    description: Optional[str] = Field(None, max_length=5000)
    priority: str = Field("HIGH", max_length=32)
    initial_analysis_id: Optional[str] = Field(None, max_length=128)

class CaseNoteCreate(BaseModel):
    author: Optional[str] = Field("SOC Analyst", max_length=128)
    content: str = Field(..., min_length=1, max_length=5000)

class CaseResponse(BaseModel):
    id: str
    title: str
    description: Optional[str] = None
    status: str = "OPEN"
    priority: str = "HIGH"
    assigned_analyst: Optional[str] = None
    created_at: str
    updated_at: str
    attached_analyses: List[FullAnalysisResult] = []
    notes: List[Dict[str, Any]] = []

class DashboardStats(BaseModel):
    total_analyzed_emails: int
    high_critical_threats: int
    active_cases: int
    active_campaigns: Optional[int] = 0
    suspicious_domains_count: int
    suspicious_ips_count: int
    threat_distribution: Dict[str, int]
    top_categories: Dict[str, int]
    recent_analyses: List[Dict[str, Any]]

class CustodyEventInput(BaseModel):
    event_type: str = Field("ANALYST_REVIEW", max_length=64)  # e.g., ANALYST_REVIEW, REPORT_GENERATED, EVIDENCE_ARCHIVED
    actor: str = Field("SOC-Analyst", max_length=128)
    details: Optional[Dict[str, Any]] = None

class CustodyEventItem(BaseModel):
    id: str
    evidence_id: str
    sequence_number: int
    event_type: str
    timestamp: str
    actor: str
    event_hash: str
    previous_event_hash: str
    tx_id: Optional[str] = None
    block_number: Optional[int] = None
    event_data: Dict[str, Any] = {}

class CustodyVerificationResponse(BaseModel):
    evidence_id: str
    status: str # VERIFIED, MODIFIED, NOT_FOUND, BLOCKCHAIN_UNAVAILABLE
    is_intact: bool
    total_events: int
    events: List[CustodyEventItem] = []
    verification_details: str
    broken_event_index: Optional[int] = None
    contract_address: Optional[str] = None

class ThreatIndicatorCreate(BaseModel):
    indicator_type: str = Field("DOMAIN", max_length=32)  # DOMAIN, URL_HASH, IP_ADDRESS, FILE_HASH, SENDER_DOMAIN
    indicator_value: str = Field(..., min_length=1, max_length=512)
    threat_category: str = Field("PHISHING", max_length=64)
    severity: str = Field("HIGH", max_length=16)  # LOW, MEDIUM, HIGH, CRITICAL
    confidence_score: int = Field(default=85, ge=1, le=100)
    source_org: Optional[str] = Field("ThreatSentinel-SOC-01", max_length=128)
    description: Optional[str] = Field(None, max_length=2000)

class ThreatIndicatorItem(BaseModel):
    id: str
    indicator_type: str
    indicator_value: str
    indicator_hash: str
    threat_category: str
    severity: str
    confidence_score: int
    source_org: str
    timestamp: str
    tx_id: Optional[str] = None
    block_number: Optional[int] = None
    observation_count: int = 1
    is_verified_onchain: bool = True
    description: Optional[str] = None

class ThreatIndicatorVerifyResponse(BaseModel):
    indicator_type: str
    indicator_value: str
    indicator_hash: str
    is_known_threat: bool
    threat_category: str
    severity: str
    confidence_score: int
    source_org: str
    timestamp: str
    tx_id: Optional[str] = None
    observation_count: int = 0
    status: str  # VERIFIED_ON_CHAIN, CLEAN_OR_NOT_FOUND, BLOCKCHAIN_UNAVAILABLE
    verification_details: str
    contract_address: Optional[str] = None
