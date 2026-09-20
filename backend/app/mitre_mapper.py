from typing import List, Dict, Any
from app.models import MitreAttackMapping, ThreatFinding

# Static MITRE ATT&CK Catalog for seeding the DB
MITRE_CATALOG = [
    {
        "id": "T1566",
        "name": "Phishing",
        "tactic": "Initial Access",
        "description": "Adversaries may send phishing messages to gain access to victim systems."
    },
    {
        "id": "T1566.001",
        "name": "Spearphishing Attachment",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious attachment in an attempt to gain access to victim systems."
    },
    {
        "id": "T1566.002",
        "name": "Spearphishing Link",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing emails with a malicious link in an attempt to gain access to victim systems."
    },
    {
        "id": "T1566.003",
        "name": "Spearphishing via Service",
        "tactic": "Initial Access",
        "description": "Adversaries may send spearphishing messages via third-party services in an attempt to gain access to victim systems."
    },
    {
        "id": "T1598",
        "name": "Phishing for Information",
        "tactic": "Reconnaissance",
        "description": "Adversaries may send phishing messages to elicit sensitive information that can be used during targeting."
    },
    {
        "id": "T1598.003",
        "name": "Spearphishing Link",
        "tactic": "Reconnaissance",
        "description": "Adversaries may send spearphishing emails with a malicious link to elicit sensitive information."
    },
    {
        "id": "T1204.002",
        "name": "User Execution: Malicious File",
        "tactic": "Execution",
        "description": "Adversaries may rely upon a user opening a malicious file in order to gain execution."
    }
]

def map_findings_to_mitre(findings: List[ThreatFinding]) -> List[MitreAttackMapping]:
    mappings: Dict[str, MitreAttackMapping] = {}
    
    def add_mapping(technique_id: str, technique_name: str, tactic: str, reason: str, confidence: str, indicators: List[str]):
        if technique_id not in mappings:
            mappings[technique_id] = MitreAttackMapping(
                technique_id=technique_id,
                technique_name=technique_name,
                tactic=tactic,
                reason=reason,
                supporting_indicators=indicators,
                confidence=confidence
            )
        else:
            existing = mappings[technique_id]
            existing.supporting_indicators.extend([i for i in indicators if i not in existing.supporting_indicators])
            if confidence == "HIGH" and existing.confidence != "HIGH":
                existing.confidence = "HIGH"
                existing.reason = reason

    for finding in findings:
        rid = finding.rule_id
        
        # Malicious Attachment
        if rid == "RULE-09":
            add_mapping(
                "T1566.001", "Spearphishing Attachment", "Initial Access",
                "Email contains a dangerous or disguised executable attachment.",
                "HIGH", [finding.evidence]
            )
            add_mapping(
                "T1204.002", "User Execution: Malicious File", "Execution",
                "Relies on the user downloading and executing the malicious payload.",
                "HIGH", [finding.evidence]
            )
            
        # Spearphishing Link / Credential Harvesting
        elif rid in ["RULE-08", "RULE-13"]:
            is_cred_harvest = any(kw in finding.explanation.lower() or kw in finding.evidence.lower() for kw in ["login", "credential", "verify", "password", "account"])
            if is_cred_harvest:
                add_mapping(
                    "T1598.003", "Spearphishing Link", "Reconnaissance",
                    "Suspicious link designed to harvest credentials or sensitive information.",
                    "HIGH" if rid == "RULE-08" else "MEDIUM", [finding.evidence]
                )
            else:
                add_mapping(
                    "T1566.002", "Spearphishing Link", "Initial Access",
                    "Email contains suspicious or highly deceptive links to external infrastructure.",
                    "HIGH" if finding.severity == "CRITICAL" else "MEDIUM", [finding.evidence]
                )
                
    return list(mappings.values())
