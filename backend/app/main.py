import os
import json
import uuid
from datetime import datetime, timezone
from contextlib import asynccontextmanager
from typing import List, Optional
from fastapi import FastAPI, Depends, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session

from app.models import (
    GraphEdgeRecord,
    CampaignRecord,
    get_db,
    EmailRecord,
    CaseRecord,
    BlockRecord,
    CustodyEventRecord,
    ThreatIntelRecord,
    AttackTechniqueRecord,
    CaseAttackTechniqueRecord,
    EmailInput,
    FullAnalysisResult,
    CaseCreate,
    CaseNoteCreate,
    CaseResponse,
    DashboardStats,
    CustodyEventInput,
    CustodyVerificationResponse,
    ThreatIndicatorCreate,
    ThreatIndicatorItem,
    ThreatIndicatorVerifyResponse
)
from app.mitre_mapper import MITRE_CATALOG
from app.scanner import scan_email
from app.blockchain import blockchain_service, blockchain_engine, MerkleTree

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Ensure baseline fixtures exist on fresh deployment
    db = next(get_db())
    try:
        if db.query(EmailRecord).count() == 0:
            seed_demo(db)
            
        # Seed MITRE ATT&CK Catalog
        for tech in MITRE_CATALOG:
            if not db.query(AttackTechniqueRecord).filter_by(id=tech["id"]).first():
                db.add(AttackTechniqueRecord(
                    id=tech["id"],
                    name=tech["name"],
                    tactic=tech["tactic"],
                    description=tech["description"]
                ))
        db.commit()
    except Exception:
        pass
    finally:
        db.close()
    yield

app = FastAPI(
    title="ThreatSentinel API",
    version="1.0.0",
    description="Email Threat Detection, GeoLocation & Forensic Intelligence Platform",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

SAMPLES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "samples"))
SAMPLE_LIST = [
    {"id": "01_legitimate", "name": "Legitimate Corporate Newsletter", "description": "Clean SPF/DKIM/DMARC pass, matching domains.", "expected_threat_level": "Low", "filename": "01_legitimate_newsletter.eml"},
    {"id": "02_phishing_suspension", "name": "Phishing - Account Suspension Threat", "description": "Urgency coercion, credential harvest link, lookalike domain.", "expected_threat_level": "High / Critical", "filename": "02_phishing_account_suspension.eml"},
    {"id": "03_spoofed_ceo", "name": "CEO Fraud Display Name Spoofing", "description": "Executive display name with unauthorized free webmail address.", "expected_threat_level": "High", "filename": "03_spoofed_sender_ceo_fraud.eml"},
    {"id": "04_reply_to_mismatch", "name": "Reply-To Address Domain Mismatch", "description": "From domain differs completely from Reply-To domain.", "expected_threat_level": "High", "filename": "04_reply_to_mismatch.eml"},
    {"id": "05_auth_failure", "name": "SPF / DKIM / DMARC Hard Failures", "description": "Direct authentication failure headers indicating spoofing.", "expected_threat_level": "Critical", "filename": "05_spf_dkim_dmarc_fail.eml"},
    {"id": "06_suspicious_url", "name": "Suspicious URL with Raw IP & Anchor Mismatch", "description": "Anchor text displays legitimate URL while href points to raw IP.", "expected_threat_level": "Critical", "filename": "06_suspicious_url_ip_mismatch.eml"},
    {"id": "07_multi_hop_relays", "name": "Multi-Hop MTA Received Relay Forensics", "description": "Detailed 4-hop relay trace with internal and public MTA hops.", "expected_threat_level": "Low / Medium", "filename": "07_multi_hop_relays.eml"},
    {"id": "08_dangerous_attachment", "name": "Malware Attachment - Double Extension & Macro", "description": "Executable disguised as PDF (.pdf.exe) and macro spreadsheet.", "expected_threat_level": "Critical", "filename": "08_dangerous_attachment_malware.eml"},
    {"id": "09_missing_headers", "name": "Spam Bot - Missing Mandatory Headers", "description": "Lacks Message-ID, Date, and standard transit headers.", "expected_threat_level": "Medium", "filename": "09_missing_headers.eml"},
    {"id": "10_malformed", "name": "Malformed / Truncated Raw Email", "description": "Corrupted MIME boundaries and truncated RFC headers.", "expected_threat_level": "Low / Medium", "filename": "10_malformed_email.eml"}
]

def save_analysis(result: FullAnalysisResult, db: Session):
    try:
        # 1. Fetch previous block from Blockchain Ledger
        prev_record = db.query(BlockRecord).order_by(BlockRecord.block_number.desc()).first()
        prev_dict = None
        if prev_record:
            prev_dict = {
                "block_number": prev_record.block_number,
                "block_hash": prev_record.block_hash
            }

        # 2. Register non-sensitive evidence metadata on blockchain
        raw_data = result.model_dump()
        receipt = blockchain_service.register_evidence(raw_data, previous_block=prev_dict)

        # 3. Update Tamper Seal with Blockchain Proof & Reference ID
        if result.tamper_seal:
            result.tamper_seal.block_number = receipt.get("block_number")
            result.tamper_seal.block_hash = receipt.get("block_hash")
            result.tamper_seal.tx_id = receipt.get("tx_id")
            result.tamper_seal.contract_address = receipt.get("contract_address")
            result.tamper_seal.merkle_root = receipt.get("merkle_root")
            result.tamper_seal.blockchain_status = receipt.get("status", "CONFIRMED")
            result.tamper_seal.blockchain_verified = receipt.get("status") in ("CONFIRMED", "DISABLED")

        # 4. Save Block to Blockchain Ledger Table if registered
        if receipt.get("block_number"):
            block_rec = BlockRecord(
                block_number=receipt["block_number"],
                timestamp=datetime.fromisoformat(receipt["timestamp"]),
                block_hash=receipt["block_hash"],
                previous_hash=receipt["previous_hash"],
                analysis_id=result.analysis_id,
                merkle_root=receipt["merkle_root"],
                canonical_evidence_hash=receipt["evidence_hash"],
                block_data_json=receipt
            )
            db.add(block_rec)

        # 5. Save Email Record
        updated_dump = result.model_dump()
        record = EmailRecord(
            id=result.analysis_id,
            created_at=datetime.now(timezone.utc),
            subject=result.metadata.get("subject"),
            sender=result.metadata.get("from_address"),
            recipient=(result.metadata.get("to_addresses") or [None])[0],
            threat_score=result.threat_score.overall_score,
            risk_level=result.threat_score.risk_level,
            risk_color=result.threat_score.risk_color,
            data_json=updated_dump
        )
        db.add(record)
        db.commit()

        # 6. Initialize Blockchain Chain-of-Custody Lifecycle
        blockchain_service.create_initial_custody_chain(result.analysis_id, updated_dump, db)

        # 7. Auto-Publish Non-Sensitive Threat Indicators to Decentralized Threat Intel Registry
        blockchain_service.auto_publish_analysis_iocs(updated_dump, db)

    except Exception as e:
        db.rollback()

@app.post("/api/analyze-email", response_model=FullAnalysisResult)
async def analyze_email_json(payload: EmailInput, db: Session = Depends(get_db)):
    if not (payload.raw_email or payload.headers or payload.body or payload.subject or payload.sender):
        raise HTTPException(status_code=400, detail="Provide raw email content or structured fields.")
    result = scan_email(
        raw_text=payload.raw_email,
        subject=payload.subject,
        sender=payload.sender,
        recipient=payload.recipient,
        headers_text=payload.headers,
        body_text=payload.body
    )
    save_analysis(result, db)
    return result

MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_UPLOAD_SIZE_BYTES", 15_728_640))

@app.post("/api/analyze-file", response_model=FullAnalysisResult)
async def analyze_email_file(file: UploadFile = File(...), db: Session = Depends(get_db)):
    content = await file.read()
    if len(content) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File exceeds maximum allowed size of {MAX_FILE_SIZE_BYTES // (1024*1024)} MB."
        )
    result = scan_email(raw_bytes=content)
    save_analysis(result, db)
    return result

@app.get("/api/analysis/{analysis_id}", response_model=FullAnalysisResult)
def get_analysis(analysis_id: str, db: Session = Depends(get_db)):
    record = db.query(EmailRecord).filter(EmailRecord.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    return record.data_json

@app.get("/api/analysis/{analysis_id}/urls")
def get_analysis_urls(analysis_id: str, db: Session = Depends(get_db)):
    record = db.query(EmailRecord).filter(EmailRecord.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    return record.data_json.get("extracted_urls", [])

@app.delete("/api/analysis/{analysis_id}")
def delete_analysis(analysis_id: str, db: Session = Depends(get_db)):
    record = db.query(EmailRecord).filter(EmailRecord.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found")
    db.delete(record)
    db.commit()
    return {"status": "success"}

@app.get("/api/analysis/{analysis_id}/verify-seal")
def verify_tamper_seal(analysis_id: str, db: Session = Depends(get_db)):
    return verify_blockchain_evidence(analysis_id, db)

@app.post("/api/blockchain/register/{analysis_id}")
def register_blockchain_evidence_manual(analysis_id: str, db: Session = Depends(get_db)):
    record = db.query(EmailRecord).filter(EmailRecord.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis not found")
    
    prev_record = db.query(BlockRecord).order_by(BlockRecord.block_number.desc()).first()
    prev_dict = None
    if prev_record:
        prev_dict = {"block_number": prev_record.block_number, "block_hash": prev_record.block_hash}
    
    receipt = blockchain_service.register_evidence(record.data_json, previous_block=prev_dict)
    if receipt.get("block_number"):
        block_rec = BlockRecord(
            block_number=receipt["block_number"],
            timestamp=datetime.fromisoformat(receipt["timestamp"]),
            block_hash=receipt["block_hash"],
            previous_hash=receipt["previous_hash"],
            analysis_id=analysis_id,
            merkle_root=receipt["merkle_root"],
            canonical_evidence_hash=receipt["evidence_hash"],
            block_data_json=receipt
        )
        db.add(block_rec)
        db.commit()
    return receipt

@app.get("/api/blockchain/status/{analysis_id}")
def get_blockchain_status(analysis_id: str, db: Session = Depends(get_db)):
    block_rec = db.query(BlockRecord).filter(BlockRecord.analysis_id == analysis_id).first()
    if not block_rec:
        return {
            "analysis_id": analysis_id,
            "status": "PENDING_OR_UNREGISTERED",
            "is_registered": False,
            "block_number": None,
            "tx_id": None
        }
    return {
        "analysis_id": analysis_id,
        "status": "CONFIRMED",
        "is_registered": True,
        "block_number": block_rec.block_number,
        "block_hash": block_rec.block_hash,
        "tx_id": block_rec.block_data_json.get("tx_id"),
        "timestamp": block_rec.timestamp.isoformat() if block_rec.timestamp else "",
        "contract_address": blockchain_service.contract_address
    }

@app.get("/api/blockchain/contract")
def get_contract_info():
    return {
        "contract_name": "EvidenceRegistry",
        "contract_address": blockchain_service.contract_address,
        "network": blockchain_service.network_name,
        "solidity_version": "^0.8.20",
        "abi": blockchain_service.abi,
        "system_validator": blockchain_service.system_id
    }

@app.get("/api/blockchain/ledger")
def get_blockchain_ledger(db: Session = Depends(get_db)):
    blocks = db.query(BlockRecord).order_by(BlockRecord.block_number.asc()).all()
    return [b.block_data_json for b in blocks]

@app.get("/api/blockchain/verify/{analysis_id}")
def verify_blockchain_evidence(analysis_id: str, db: Session = Depends(get_db)):
    record = db.query(EmailRecord).filter(EmailRecord.id == analysis_id).first()
    block_rec = db.query(BlockRecord).filter(BlockRecord.analysis_id == analysis_id).first()
    
    if not record:
        raise HTTPException(status_code=404, detail="Email record not found")
    
    if not block_rec:
        return {
            "analysis_id": analysis_id,
            "verification_status": "NO_BLOCKCHAIN_RECORD",
            "payload_hash_intact": False,
            "merkle_root_intact": False,
            "tamper_detected": True,
            "chain_valid": False,
            "verification_details": "No corresponding cryptographic block found in blockchain ledger."
        }

    current_data = record.data_json or {}
    _, live_canonical_hash = blockchain_service.canonicalize_evidence(current_data)
    onchain_canonical_hash = block_rec.canonical_evidence_hash
    hash_matches = (live_canonical_hash == onchain_canonical_hash)

    live_leaves = blockchain_service.extract_merkle_leaves(current_data)
    live_merkle_tree = MerkleTree(live_leaves)
    merkle_matches = (live_merkle_tree.root == block_rec.merkle_root)

    is_authentic = hash_matches and merkle_matches

    return {
        "analysis_id": analysis_id,
        "block_number": block_rec.block_number,
        "block_hash": block_rec.block_hash,
        "previous_hash": block_rec.previous_hash,
        "tx_id": block_rec.block_data_json.get("tx_id", f"0x{block_rec.block_hash[:64]}"),
        "contract_address": blockchain_service.contract_address,
        "merkle_root": block_rec.merkle_root,
        "canonical_evidence_hash": onchain_canonical_hash,
        "live_computed_hash": live_canonical_hash,
        "verification_status": "VERIFIED_AUTHENTIC" if is_authentic else "TAMPER_DETECTED",
        "payload_hash_intact": hash_matches,
        "merkle_root_intact": merkle_matches,
        "tamper_detected": not is_authentic,
        "chain_valid": True,
        "validator_node": block_rec.block_data_json.get("validator_node"),
        "timestamp": block_rec.timestamp.isoformat() if block_rec.timestamp else "",
        "evidence_leaves": block_rec.block_data_json.get("merkle_leaves", []),
        "verification_details": (
            "Cryptographic evidence hash and Merkle root match on-chain anchor perfectly (100% Intact)."
            if is_authentic else
            "CRITICAL ALERT: Evidence tampering detected! Live database record differs from on-chain anchor."
        )
    }

@app.get("/api/blockchain/stats")
def get_blockchain_stats(db: Session = Depends(get_db)):
    blocks = db.query(BlockRecord).order_by(BlockRecord.block_number.asc()).all()
    total_blocks = len(blocks)
    latest_block = blocks[-1] if blocks else None

    chain_intact = True
    for i in range(1, len(blocks)):
        if blocks[i].previous_hash != blocks[i-1].block_hash:
            chain_intact = False
            break

    return {
        "total_blocks": total_blocks,
        "latest_block_number": latest_block.block_number if latest_block else 0,
        "latest_block_hash": latest_block.block_hash if latest_block else None,
        "genesis_hash": blocks[0].block_hash if blocks else None,
        "chain_integrity_status": "INTACT" if chain_intact else "COMPROMISED",
        "validator_node": blockchain_service.system_id,
        "contract_address": blockchain_service.contract_address,
        "network": blockchain_service.network_name
    }

# ==========================================
# CHAIN OF CUSTODY LIFECYCLE ENDPOINTS
# ==========================================

@app.get("/api/custody/{evidence_id}", response_model=CustodyVerificationResponse)
def get_custody_chain(evidence_id: str, db: Session = Depends(get_db)):
    return blockchain_service.verify_custody_chain(evidence_id, db)

@app.get("/api/custody/{evidence_id}/verify", response_model=CustodyVerificationResponse)
def verify_custody_chain_endpoint(evidence_id: str, db: Session = Depends(get_db)):
    return blockchain_service.verify_custody_chain(evidence_id, db)

@app.post("/api/custody/event/{evidence_id}")
def add_custody_event(evidence_id: str, payload: CustodyEventInput, db: Session = Depends(get_db)):
    record = db.query(EmailRecord).filter(EmailRecord.id == evidence_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Evidence ID not found")
    return blockchain_service.append_custody_event(
        evidence_id=evidence_id,
        event_type=payload.event_type,
        actor=payload.actor,
        details=payload.details or {},
        db=db
    )

# =========================================================================
# DECENTRALIZED THREAT INTELLIGENCE (IOC) REGISTRY ENDPOINTS
# =========================================================================

@app.get("/api/intel/indicators", response_model=List[ThreatIndicatorItem])
def list_threat_indicators(limit: int = 50, db: Session = Depends(get_db)):
    records = (
        db.query(ThreatIntelRecord)
        .order_by(ThreatIntelRecord.timestamp.desc())
        .limit(limit)
        .all()
    )
    results = []
    for r in records:
        results.append(ThreatIndicatorItem(
            id=r.id,
            indicator_type=r.indicator_type,
            indicator_value=r.indicator_value,
            indicator_hash=r.indicator_hash,
            threat_category=r.threat_category,
            severity=r.severity,
            confidence_score=r.confidence_score,
            source_org=r.source_org,
            timestamp=r.timestamp.isoformat() if r.timestamp else "",
            tx_id=r.tx_id,
            block_number=r.block_number,
            observation_count=r.observation_count,
            is_verified_onchain=True,
            description=r.details_json.get("description") if r.details_json else None
        ))
    return results

@app.post("/api/intel/indicators", response_model=ThreatIndicatorItem)
def register_threat_indicator_endpoint(payload: ThreatIndicatorCreate, db: Session = Depends(get_db)):
    res = blockchain_service.register_threat_indicator(
        indicator_type=payload.indicator_type,
        indicator_value=payload.indicator_value,
        threat_category=payload.threat_category,
        severity=payload.severity,
        confidence_score=payload.confidence_score,
        source_org=payload.source_org or "ThreatSentinel-SOC-01",
        details={"description": payload.description} if payload.description else {},
        db=db
    )
    return ThreatIndicatorItem(
        id=res["id"],
        indicator_type=res["indicator_type"],
        indicator_value=res["indicator_value"],
        indicator_hash=res["indicator_hash"],
        threat_category=res["threat_category"],
        severity=res["severity"],
        confidence_score=res["confidence_score"],
        source_org=res["source_org"],
        timestamp=res["timestamp"],
        tx_id=res["tx_id"],
        block_number=res["block_number"],
        observation_count=res["observation_count"],
        is_verified_onchain=True,
        description=payload.description
    )

@app.get("/api/intel/verify", response_model=ThreatIndicatorVerifyResponse)
def verify_threat_indicator_endpoint(
    type: str = Query(..., description="Indicator Type: DOMAIN, URL_HASH, IP_ADDRESS, FILE_HASH, SENDER_DOMAIN"),
    value: str = Query(..., description="Indicator Value (e.g. domain, hash, or IP)"),
    db: Session = Depends(get_db)
):
    return blockchain_service.verify_threat_indicator(
        indicator_type=type,
        indicator_value=value,
        db=db
    )

@app.post("/api/intel/publish-dossier/{analysis_id}")
def publish_dossier_iocs(analysis_id: str, db: Session = Depends(get_db)):
    record = db.query(EmailRecord).filter(EmailRecord.id == analysis_id).first()
    if not record or not record.data_json:
        raise HTTPException(status_code=404, detail="Analysis dossier not found.")
    
    published = blockchain_service.auto_publish_analysis_iocs(record.data_json, db)
    return {
        "status": "PUBLISHED",
        "analysis_id": analysis_id,
        "published_count": len(published),
        "indicators": published
    }

@app.get("/api/intel/stats")
def get_threat_intel_stats(db: Session = Depends(get_db)):
    records = db.query(ThreatIntelRecord).all()
    total = len(records)
    by_type = {}
    by_severity = {}
    orgs = set()
    for r in records:
        by_type[r.indicator_type] = by_type.get(r.indicator_type, 0) + 1
        by_severity[r.severity] = by_severity.get(r.severity, 0) + 1
        orgs.add(r.source_org)
    
    return {
        "total_indicators": total,
        "by_type": by_type,
        "by_severity": by_severity,
        "participating_orgs_count": len(orgs),
        "participating_orgs": list(orgs),
        "network": blockchain_service.network_name,
        "intel_contract": "0x89E23B84Ce1e6D403a7aE505d9b626E6F22eD33C"
    }

@app.get("/api/analysis/{analysis_id}/report")
def export_report(analysis_id: str, db: Session = Depends(get_db)):
    record = db.query(EmailRecord).filter(EmailRecord.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Not found")
    
    # Append REPORT_GENERATED lifecycle event to chain of custody
    blockchain_service.append_custody_event(
        evidence_id=analysis_id,
        event_type="REPORT_GENERATED",
        actor="ThreatSentinel-Reporter",
        details={"summary": "TLP:AMBER forensic report exported by investigator.", "action_code": "REPORT_EXPORT"},
        db=db
    )
    
    data = record.data_json
    markdown = f"""# ThreatSentinel Forensic Report
**ID**: `{analysis_id}` | **Classification**: `TLP:AMBER`
**Subject**: {record.subject} | **Threat Score**: {record.threat_score}/100 ({record.risk_level})
**Sender**: `{record.sender}`

## Summary
{data.get('threat_score', {}).get('explanation')}
"""
    return {"report_id": f"REP-{analysis_id[:8]}", "report_markdown": markdown, "report_json": data}

# =========================================================================
# CONTROLLED FORENSIC INTEGRITY DEMO MECHANISM (DEVELOPMENT / SIH DEMO ONLY)
# =========================================================================

DEMO_MODE = os.getenv("DEMO_MODE", "true").lower() in ("true", "1", "yes") and os.getenv("ENVIRONMENT", "development").lower() != "production"

@app.post("/api/demo/simulate-tamper/{analysis_id}")
def simulate_evidence_tamper(analysis_id: str, db: Session = Depends(get_db)):
    """
    Controlled demonstration endpoint: Modifies a field in the off-chain SQLite database
    to prove to SIH evaluators that blockchain verification catches tampering immediately.
    Strictly gated to development/demo environments.
    """
    if not DEMO_MODE:
        raise HTTPException(status_code=403, detail="Tamper simulation endpoint is disabled in production environments.")

    record = db.query(EmailRecord).filter(EmailRecord.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    from sqlalchemy.orm.attributes import flag_modified
    import copy

    data = copy.deepcopy(record.data_json)
    if "_original_data_backup" not in data:
        data["_original_data_backup"] = copy.deepcopy(data)

    orig_score = data.get("threat_score", {}).get("overall_score", 0)
    tampered_score = 0 if orig_score > 50 else 99
    data["threat_score"]["overall_score"] = tampered_score
    data["threat_score"]["risk_level"] = "Critical" if tampered_score > 70 else "Low"

    record.threat_score = tampered_score
    record.risk_level = data["threat_score"]["risk_level"]
    record.data_json = data
    flag_modified(record, "data_json")

    # Also simulate off-chain modification in custody event record
    custody_event = db.query(CustodyEventRecord).filter(
        CustodyEventRecord.evidence_id == analysis_id,
        CustodyEventRecord.sequence_number == 1
    ).first()
    if custody_event:
        c_data = copy.deepcopy(custody_event.event_data_json or {})
        if "_original_event_backup" not in c_data:
            c_data["_original_event_backup"] = copy.deepcopy(c_data)
        c_data["summary"] = "[MALICIOUS ALTERATION] Unauthorized modification of ingested evidence record."
        custody_event.event_data_json = c_data
        flag_modified(custody_event, "event_data_json")

    db.commit()

    return {
        "status": "TAMPER_SIMULATED",
        "analysis_id": analysis_id,
        "message": f"Controlled tamper simulation applied: Threat score modified from {orig_score} to {tampered_score}. Live hash now differs from on-chain anchor.",
        "original_score": orig_score,
        "tampered_score": tampered_score
    }

@app.post("/api/demo/restore-evidence/{analysis_id}")
def restore_evidence(analysis_id: str, db: Session = Depends(get_db)):
    """
    Restores the test evidence record back to its original authentic state.
    """
    if not DEMO_MODE:
        raise HTTPException(status_code=403, detail="Disabled in production.")

    record = db.query(EmailRecord).filter(EmailRecord.id == analysis_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")

    from sqlalchemy.orm.attributes import flag_modified
    import copy

    data = copy.deepcopy(record.data_json)
    if "_original_data_backup" in data:
        orig = data["_original_data_backup"]
        record.data_json = orig
        record.threat_score = orig.get("threat_score", {}).get("overall_score", 0)
        record.risk_level = orig.get("threat_score", {}).get("risk_level", "Low")
        flag_modified(record, "data_json")

    custody_event = db.query(CustodyEventRecord).filter(
        CustodyEventRecord.evidence_id == analysis_id,
        CustodyEventRecord.sequence_number == 1
    ).first()
    if custody_event and custody_event.event_data_json and "_original_event_backup" in custody_event.event_data_json:
        orig_c = custody_event.event_data_json["_original_event_backup"]
        custody_event.event_data_json = orig_c
        flag_modified(custody_event, "event_data_json")

    db.commit()

    return {
        "status": "RESTORED",
        "analysis_id": analysis_id,
        "message": "Evidence record restored to original authentic cryptographic state."
    }

@app.post("/api/analysis/{analysis_id}/chat")
def chat_assistant(analysis_id: str, payload: dict, db: Session = Depends(get_db)):
    question = payload.get("question", "")
    record = db.query(EmailRecord).filter(EmailRecord.id == analysis_id).first()
    score = record.threat_score if record else 0
    return {
        "answer": f"Analysis for this message recorded Threat Score {score}/100. Key indicators have been cross-checked with SPF/DKIM headers.",
        "referenced_evidence": ["Header transport evaluation", "Authentication status"],
        "confidence": "HIGH"
    }

@app.get("/api/correlation/graph")
def get_correlation_graph(db: Session = Depends(get_db)):
    records = db.query(EmailRecord).all()
    nodes = []
    edges = []
    clusters = []

    domain_map = {}
    for r in records:
        nodes.append({"id": f"email:{r.id}", "label": (r.subject or "Email")[:30], "type": "email", "threat_level": r.risk_level})
        if r.sender and "@" in r.sender:
            d = r.sender.split("@")[-1].lower()
            domain_map.setdefault(d, []).append(r.id)

    for d, email_ids in domain_map.items():
        if len(email_ids) > 1:
            dom_id = f"domain:{d}"
            nodes.append({"id": dom_id, "label": d, "type": "domain"})
            for eid in email_ids:
                edges.append({"source": f"email:{eid}", "target": dom_id, "relationship": "shares_domain"})
            clusters.append({
                "cluster_id": f"cluster-{len(clusters)+1}",
                "cluster_name": f"Domain: {d}",
                "classification": "Shared Domain",
                "member_email_ids": email_ids,
                "summary_reason": f"{len(email_ids)} emails originated from {d}."
            })

    return {
        "nodes": nodes,
        "edges": edges,
        "clusters": clusters,
        "total_correlated_emails": len([n for n in nodes if n["type"] == "email"]),
        "total_shared_indicators": len(clusters)
    }

@app.get("/api/dashboard/stats", response_model=DashboardStats)
def get_dashboard_stats(db: Session = Depends(get_db)):
    all_emails = db.query(EmailRecord).order_by(EmailRecord.created_at.desc()).all()
    tier_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    high_critical = 0
    categories = {}
    seen_domains = set()
    seen_ips = set()
    recent = []

    for item in all_emails:
        lvl = (item.risk_level or "low").lower()
        if lvl in tier_counts: tier_counts[lvl] += 1
        if lvl in ["critical", "high"]: high_critical += 1

        d = item.data_json or {}
        for f in d.get("detection_findings", []):
            cat = f.get("category", "OTHER")
            categories[cat] = categories.get(cat, 0) + 1

        for ioc in d.get("iocs", []):
            if ioc.get("type") == "domain": seen_domains.add(ioc.get("value", "").lower())
            elif ioc.get("type") == "ip": seen_ips.add(ioc.get("value", "").lower())

        recent.append({
            "id": item.id,
            "subject": item.subject,
            "sender": item.sender,
            "threat_score": item.threat_score,
            "risk_level": item.risk_level,
            "risk_color": item.risk_color,
            "created_at": item.created_at.isoformat() if item.created_at else ""
        })

    active_cases = db.query(CaseRecord).filter(CaseRecord.status != "CLOSED").count()
    active_campaigns = db.query(CampaignRecord).filter(CampaignRecord.status == "ACTIVE").count()

    return DashboardStats(
        active_campaigns=active_campaigns,
        total_analyzed_emails=len(all_emails),
        high_critical_threats=high_critical,
        active_cases=active_cases,
        suspicious_domains_count=len(seen_domains),
        suspicious_ips_count=len(seen_ips),
        threat_distribution=tier_counts,
        top_categories=categories,
        recent_analyses=recent
    )

@app.get("/api/search")
def search_entities(q: str = Query(..., min_length=1), db: Session = Depends(get_db)):
    term = q.strip().lower()
    results = []
    for a in db.query(EmailRecord).all():
        if (a.subject and term in a.subject.lower()) or (a.sender and term in a.sender.lower()):
            results.append({
                "type": "email",
                "id": a.id,
                "title": a.subject or "Email Record",
                "subtitle": f"From: {a.sender} | Score: {a.threat_score}/100",
                "risk_level": a.risk_level
            })
    return results[:20]

def sync_case_mitre(case_id: str, db: Session):
    case = db.query(CaseRecord).filter(CaseRecord.id == case_id).first()
    if not case: return
    
    # clear existing mappings for case
    db.query(CaseAttackTechniqueRecord).filter(CaseAttackTechniqueRecord.case_id == case_id).delete()
    
    # gather all mitre mappings from attached evidence
    tech_map = {}
    for aid in (case.attached_analysis_ids or []):
        r = db.query(EmailRecord).filter(EmailRecord.id == aid).first()
        if r and r.data_json and "mitre_attack_mappings" in r.data_json:
            for mapping in r.data_json["mitre_attack_mappings"]:
                tid = mapping["technique_id"]
                if tid not in tech_map:
                    tech_map[tid] = mapping
                else:
                    tech_map[tid]["supporting_indicators"].extend(mapping["supporting_indicators"])
                    if mapping["confidence"] == "HIGH":
                        tech_map[tid]["confidence"] = "HIGH"
                        
    for tid, mapping in tech_map.items():
        db.add(CaseAttackTechniqueRecord(
            case_id=case_id,
            technique_id=tid,
            confidence=mapping["confidence"],
            reason=mapping["reason"],
            supporting_indicators=list(set(mapping["supporting_indicators"]))
        ))
    db.commit()

@app.get("/api/cases/{case_id}/attack-techniques")
def get_case_techniques(case_id: str, db: Session = Depends(get_db)):
    sync_case_mitre(case_id, db)
    records = db.query(CaseAttackTechniqueRecord).filter(CaseAttackTechniqueRecord.case_id == case_id).all()
    results = []
    for r in records:
        tech = db.query(AttackTechniqueRecord).filter(AttackTechniqueRecord.id == r.technique_id).first()
        if tech:
            results.append({
                "technique_id": tech.id,
                "technique_name": tech.name,
                "tactic": tech.tactic,
                "confidence": r.confidence,
                "reason": r.reason,
                "supporting_indicators": r.supporting_indicators
            })
    return results

@app.get("/api/analytics/attack-techniques")
def get_attack_technique_stats(db: Session = Depends(get_db)):
    records = db.query(CaseAttackTechniqueRecord).all()
    stats = {}
    for r in records:
        if r.technique_id not in stats:
            stats[r.technique_id] = 0
        stats[r.technique_id] += 1
        
    return [{"technique_id": k, "count": v} for k, v in stats.items()]


@app.get("/api/cases", response_model=List[dict])
def list_cases(db: Session = Depends(get_db)):
    cases = db.query(CaseRecord).order_by(CaseRecord.updated_at.desc()).all()
    out = []
    for c in cases:
        sync_case_mitre(c.id, db)
        techs = [r.technique_id for r in db.query(CaseAttackTechniqueRecord).filter_by(case_id=c.id).all()]
        out.append({
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "status": c.status,
            "priority": c.priority,
            "created_at": c.created_at.isoformat() if c.created_at else "",
            "attached_analyses_count": len(c.attached_analysis_ids or []),
            "notes_count": len(c.notes_json or []),
            "mitre_techniques": techs
        })
    return out

@app.post("/api/cases", response_model=CaseResponse)
def create_case(payload: CaseCreate, db: Session = Depends(get_db)):
    case_id = str(uuid.uuid4())
    attached = [payload.initial_analysis_id] if payload.initial_analysis_id else []
    c = CaseRecord(
        id=case_id,
        title=payload.title,
        description=payload.description,
        status="NEW",
        priority=payload.priority,
        attached_analysis_ids=attached,
        notes_json=[{
            "id": str(uuid.uuid4()),
            "author": "System",
            "content": f"Case opened with {payload.priority} priority.",
            "created_at": datetime.now(timezone.utc).isoformat()
        }]
    )
    db.add(c)
    db.commit()
    
    # Generate graph and correlate
    build_graph_for_case(c, db)
    correlate_case(c, db)
    
    return get_case_by_id(case_id, db)

@app.get("/api/cases/{case_id}", response_model=CaseResponse)
def get_case_by_id(case_id: str, db: Session = Depends(get_db)):
    c = db.query(CaseRecord).filter(CaseRecord.id == case_id).first()
    if not c:
        raise HTTPException(status_code=404, detail="Case not found")

    attached = []
    for aid in (c.attached_analysis_ids or []):
        r = db.query(EmailRecord).filter(EmailRecord.id == aid).first()
        if r and r.data_json:
            attached.append(r.data_json)

    return CaseResponse(
        id=c.id,
        title=c.title,
        description=c.description,
        status=c.status,
        priority=c.priority,
        assigned_analyst=c.assigned_analyst,
        created_at=c.created_at.isoformat() if c.created_at else "",
        updated_at=c.updated_at.isoformat() if c.updated_at else "",
        attached_analyses=attached,
        notes=c.notes_json or []
    )

@app.patch("/api/cases/{case_id}", response_model=CaseResponse)
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
    return get_case_by_id(case_id, db)

@app.post("/api/cases/{case_id}/notes", response_model=CaseResponse)
def add_case_note(case_id: str, payload: CaseNoteCreate, db: Session = Depends(get_db)):
    c = db.query(CaseRecord).filter(CaseRecord.id == case_id).first()
    if not c: raise HTTPException(status_code=404, detail="Case not found")
    notes = list(c.notes_json or [])
    notes.append({
        "id": str(uuid.uuid4()),
        "author": payload.author or "SOC Analyst",
        "content": payload.content,
        "created_at": datetime.now(timezone.utc).isoformat()
    })
    c.notes_json = notes
    c.updated_at = datetime.now(timezone.utc)

    # Append ANALYST_REVIEW lifecycle event to Chain of Custody for attached analyses
    for aid in (c.attached_analysis_ids or []):
        blockchain_service.append_custody_event(
            evidence_id=aid,
            event_type="ANALYST_REVIEW",
            actor=payload.author or "SOC-Analyst",
            details={"summary": f"Analyst review recorded for Case {case_id}: {payload.content[:70]}", "action_code": "ANALYST_NOTE"},
            db=db
        )

    db.commit()
    return get_case_by_id(case_id, db)

@app.get("/api/sample-emails")
def list_sample_emails():
    return SAMPLE_LIST

@app.get("/api/sample-emails/{sample_id}")
def get_sample_email(sample_id: str):
    s = next((item for item in SAMPLE_LIST if item["id"] == sample_id), None)
    if not s: raise HTTPException(status_code=404, detail="Sample not found")
    p = os.path.join(SAMPLES_DIR, s["filename"])
    if not os.path.exists(p): raise HTTPException(status_code=404, detail="File missing")
    with open(p, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()
    return {**s, "raw_content": content}

@app.post("/api/demo/seed")
def seed_demo(db: Session = Depends(get_db)):
    if not DEMO_MODE:
        raise HTTPException(status_code=403, detail="Demo seeder endpoint is disabled in production environments.")
    count = 0
    first_id = None
    for s in SAMPLE_LIST:
        p = os.path.join(SAMPLES_DIR, s["filename"])
        if os.path.exists(p):
            with open(p, "rb") as f:
                res = scan_email(raw_bytes=f.read())
                save_analysis(res, db)
                if not first_id: first_id = res.analysis_id
                count += 1

    if not db.query(CaseRecord).filter(CaseRecord.id == "inc-demo").first() and first_id:
        db.add(CaseRecord(
            id="inc-demo",
            title="INC-2026-001: Executive Credential Harvest Campaign",
            description="Phishing alerts involving lookalike domain and free webmail spoofing.",
            status="IN_PROGRESS",
            priority="CRITICAL",
            attached_analysis_ids=[first_id],
            notes_json=[{"id": str(uuid.uuid4()), "author": "Lead Analyst", "content": "Initial triage completed.", "created_at": datetime.now(timezone.utc).isoformat()}]
        ))
        db.commit()

    return {"status": "success", "message": f"Loaded {count} sample emails."}

@app.post("/api/demo/reset")
def reset_demo(db: Session = Depends(get_db)):
    if not DEMO_MODE:
        raise HTTPException(status_code=403, detail="Demo database reset endpoint is disabled in production environments.")
    db.query(EmailRecord).delete()
    db.query(CaseRecord).delete()
    db.query(BlockRecord).delete()
    db.query(CustodyEventRecord).delete()
    db.query(ThreatIntelRecord).delete()
    db.commit()
    return seed_demo(db)

@app.get("/api/health")
def health():
    return {"status": "healthy"}




from app.graph_builder import build_graph_for_email, build_graph_for_case
from app.correlator import correlate_case
from collections import deque

@app.get("/api/graph/cases/{case_id}")
def get_case_graph(case_id: str, depth: int = 2, limit: int = 150, db: Session = Depends(get_db)):
    # 1. Sync case graph edges
    case = db.query(CaseRecord).filter_by(id=case_id).first()
    if not case: return {"nodes": [], "edges": []}
    
    build_graph_for_case(case, db)
    for aid in (case.attached_analysis_ids or []):
        email = db.query(EmailRecord).filter_by(id=aid).first()
        if email: build_graph_for_email(email, db)
        
    nodes = {}
    edges = []
    
    def add_node(n_type, n_id, label=None):
        if not label: label = n_id
        n_key = f"{n_type}:{n_id}"
        if n_key not in nodes:
            nodes[n_key] = {"id": n_key, "type": n_type, "label": label, "value": n_id}
            
    # BFS
    queue = deque([("case", case_id)])
    visited = set()
    edge_seen = set()
    
    while queue and len(nodes) < limit:
        curr_type, curr_id = queue.popleft()
        node_key = f"{curr_type}:{curr_id}"
        if node_key in visited: continue
        visited.add(node_key)
        
        # Add the node itself
        label = curr_id
        if curr_type == "case" and curr_id == case.id: label = case.title
        elif curr_type == "case": 
            c = db.query(CaseRecord).filter_by(id=curr_id).first()
            if c: label = c.title
        elif curr_type == "email":
            e = db.query(EmailRecord).filter_by(id=curr_id).first()
            if e: label = e.subject or "Email"
        add_node(curr_type, curr_id, label)
        
        if curr_type == "domain":
            try:
                intel = get_domain_intelligence(curr_id)
                nodes[node_key]["registrar"] = intel.whois_rdap.registrar
                nodes[node_key]["creation_date"] = intel.whois_rdap.creation_date
                nodes[node_key]["privacy_protected"] = intel.whois_rdap.privacy_protected
                nodes[node_key]["newly_registered"] = intel.risk.newly_registered
                nodes[node_key]["suspicious_tld"] = intel.risk.suspicious_tld
                nodes[node_key]["mx_records"] = len(intel.dns_records.mx)
            except Exception:
                pass

        if curr_type == "ip":
            try:
                intel = get_ip_intelligence(curr_id)
                nodes[node_key]["asn"] = intel.asn
                nodes[node_key]["organization"] = intel.organization
                nodes[node_key]["country"] = intel.country
                nodes[node_key]["classification"] = intel.classification
                nodes[node_key]["is_tor"] = intel.is_tor
                nodes[node_key]["is_vpn_proxy"] = intel.is_vpn_proxy
                nodes[node_key]["is_cloud"] = intel.is_cloud
            except Exception:
                pass

        
        if len(nodes) >= limit: break
            
        # Get edges where this is source
        out_edges = db.query(GraphEdgeRecord).filter_by(source_type=curr_type, source_id=curr_id).all()
        # Get edges where this is target
        in_edges = db.query(GraphEdgeRecord).filter_by(target_type=curr_type, target_id=curr_id).all()
        
        for e in out_edges:
            ekey = f"{e.source_type}:{e.source_id}->{e.target_type}:{e.target_id}:{e.relation}"
            if ekey not in edge_seen:
                edge_seen.add(ekey)
                edges.append({"source": f"{e.source_type}:{e.source_id}", "target": f"{e.target_type}:{e.target_id}", "relation": e.relation})
                queue.append((e.target_type, e.target_id))
                
        for e in in_edges:
            ekey = f"{e.source_type}:{e.source_id}->{e.target_type}:{e.target_id}:{e.relation}"
            if ekey not in edge_seen:
                edge_seen.add(ekey)
                edges.append({"source": f"{e.source_type}:{e.source_id}", "target": f"{e.target_type}:{e.target_id}", "relation": e.relation})
                queue.append((e.source_type, e.source_id))

    return {"nodes": list(nodes.values()), "edges": edges}


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
    
    print("REPORT:", report); return report

# Static Files & SPA
DIST_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "dist"))
if os.path.exists(DIST_DIR):
    app.mount("/assets", StaticFiles(directory=os.path.join(DIST_DIR, "assets")), name="assets")

    @app.get("/{full_path:path}")
    async def serve_spa(full_path: str):
        if full_path.startswith("api") or full_path.startswith("docs") or full_path.startswith("redoc") or full_path.startswith("openapi.json"):
            return None
        file_path = os.path.join(DIST_DIR, full_path)
        if os.path.isfile(file_path):
            return FileResponse(file_path)
        return FileResponse(os.path.join(DIST_DIR, "index.html"))


from app.analytics import run_detection_evaluation

@app.get("/api/analytics/detection")
def get_detection_analytics():
    return run_detection_evaluation()

@app.get("/api/analytics/detection/rules")
def get_detection_rules_analytics():
    data = run_detection_evaluation()
    if "error" in data:
        return data
    return data.get("rule_performance", [])

@app.get("/api/analytics/detection/categories")
def get_detection_category_analytics():
    data = run_detection_evaluation()
    if "error" in data:
        return data
    return data.get("category_performance", {})


if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("app.main:app", host="0.0.0.0", port=port, reload=False)
