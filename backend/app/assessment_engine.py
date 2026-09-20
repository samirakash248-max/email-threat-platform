from typing import Dict, Any, List
from app.models import InvestigativeAssessment

def calculate_investigative_assessment(
    auth_results: Any,
    threat_score: Any,
    ip_intel_dict: Dict[str, Any],
    domain_intel: Dict[str, Any],
    parsed_email: Any
) -> InvestigativeAssessment:
    
    scores = {
        "SPOOFED_DOMAIN": 0,
        "COMPROMISED_ACCOUNT": 0,
        "ANONYMIZED_INFRASTRUCTURE": 0,
        "DIRECT_MALICIOUS_INFRASTRUCTURE": 0
    }
    
    reasons = {k: [] for k in scores.keys()}
    evidence = {k: [] for k in scores.keys()}
    supporting = {k: [] for k in scores.keys()}
    
    # 1. Auth Evaluation (SPOOFED vs COMPROMISED)
    auth_fails = 0
    auth_passes = 0
    
    if auth_results:
        spf = auth_results.spf.status.lower() if hasattr(auth_results.spf, 'status') else "none"
        dkim = auth_results.dkim.status.lower() if hasattr(auth_results.dkim, 'status') else "none"
        dmarc = auth_results.dmarc.status.lower() if hasattr(auth_results.dmarc, 'status') else "none"
        
        for p in [spf, dkim, dmarc]:
            if "fail" in p or "softfail" in p:
                auth_fails += 1
            elif "pass" in p:
                auth_passes += 1
                
        if auth_fails > 0:
            scores["SPOOFED_DOMAIN"] += 35 * auth_fails
            reasons["SPOOFED_DOMAIN"].append("Authentication failures are consistent with domain spoofing.")
            evidence["SPOOFED_DOMAIN"].append(f"SPF: {spf}, DKIM: {dkim}, DMARC: {dmarc}")
            
        if auth_passes >= 2 and auth_fails == 0:
            # Strong auth implies compromised if it's malicious
            scores["COMPROMISED_ACCOUNT"] += 40
            evidence["COMPROMISED_ACCOUNT"].append("Email passed standard SPF/DKIM authentication checks.")
    
    # Reply-To Mismatch
    if parsed_email and parsed_email.sender and parsed_email.reply_to:
        if parsed_email.sender.lower().strip() != parsed_email.reply_to.lower().strip():
            scores["SPOOFED_DOMAIN"] += 25
            reasons["SPOOFED_DOMAIN"].append("Reply-To address conflicts with the apparent sender identity.")
            supporting["SPOOFED_DOMAIN"].append(f"Sender: {parsed_email.sender}, Reply-To: {parsed_email.reply_to}")
            
    # 2. IP Intelligence Evaluation (ANONYMIZED vs DIRECT)
    for ip, intel in ip_intel_dict.items():
        is_tor = intel.get("is_tor", False)
        is_vpn = intel.get("is_vpn_proxy", False)
        is_cloud = intel.get("is_datacenter", False)
        
        if is_tor:
            scores["ANONYMIZED_INFRASTRUCTURE"] += 60
            reasons["ANONYMIZED_INFRASTRUCTURE"].append("Observed sending infrastructure is associated with anonymization services (TOR).")
            supporting["ANONYMIZED_INFRASTRUCTURE"].append(f"IP: {ip} (TOR Exit Node)")
        if is_vpn:
            scores["ANONYMIZED_INFRASTRUCTURE"] += 50
            reasons["ANONYMIZED_INFRASTRUCTURE"].append("Observed sending infrastructure is associated with VPN/Proxy anonymization services.")
            supporting["ANONYMIZED_INFRASTRUCTURE"].append(f"IP: {ip} (VPN/Proxy)")
            
        if is_cloud and not is_tor and not is_vpn:
            scores["DIRECT_MALICIOUS_INFRASTRUCTURE"] += 20
            evidence["DIRECT_MALICIOUS_INFRASTRUCTURE"].append(f"Observed sending infrastructure is hosted in a generic cloud/datacenter environment ({ip}).")
            
        rep = intel.get("reputation") or {}
        if rep.get("listed"):
            scores["DIRECT_MALICIOUS_INFRASTRUCTURE"] += 15
            supporting["DIRECT_MALICIOUS_INFRASTRUCTURE"].append(f"Observed IP ({ip}) is listed by configured reputation sources.")
        
        bot_assoc = rep.get("botnet_association", "")
        if bot_assoc == "KNOWN_BOTNET_ASSOCIATION":
            scores["DIRECT_MALICIOUS_INFRASTRUCTURE"] += 40
            reasons["DIRECT_MALICIOUS_INFRASTRUCTURE"].append(f"Explicit botnet-associated indicator observed ({ip}).")

    # 3. Domain Intelligence Evaluation
    for dom, intel in domain_intel.items():
        is_lookalike = intel.get("is_lookalike_typosquat", False)
        risk = intel.get("risk", {})
        suspicious_tld = risk.get("suspicious_tld", False)
        newly_reg = risk.get("newly_registered", False)
        
        if is_lookalike:
            scores["SPOOFED_DOMAIN"] += 45
            reasons["SPOOFED_DOMAIN"].append(f"Sender domain ({dom}) exhibits lookalike/typosquatting characteristics.")
            supporting["SPOOFED_DOMAIN"].append(f"Domain: {dom}")
            
        if suspicious_tld or newly_reg:
            scores["DIRECT_MALICIOUS_INFRASTRUCTURE"] += 40
            reasons["DIRECT_MALICIOUS_INFRASTRUCTURE"].append(f"Domain ({dom}) exhibits direct risk indicators (newly registered or suspicious TLD).")
            supporting["DIRECT_MALICIOUS_INFRASTRUCTURE"].append(f"Domain: {dom} (Risk: {risk.get('risk_factors', [])})")
            
    # 4. Overall Threat Score influence
    overall = threat_score.overall_score if threat_score else 0
    if overall >= 60:
        if scores["COMPROMISED_ACCOUNT"] >= 40:
            scores["COMPROMISED_ACCOUNT"] += 30
            reasons["COMPROMISED_ACCOUNT"].append("Observed evidence is consistent with possible account compromise; confirmation requires investigation.")
        if scores["DIRECT_MALICIOUS_INFRASTRUCTURE"] > 0:
            scores["DIRECT_MALICIOUS_INFRASTRUCTURE"] += 30
            
    # Select max score
    best_vector = "INSUFFICIENT_EVIDENCE"
    best_score = 0
    
    for vec, score in scores.items():
        if score > best_score:
            best_score = score
            best_vector = vec
            
    if best_score < 40:
        return InvestigativeAssessment(
            vector="INSUFFICIENT_EVIDENCE",
            confidence=0,
            reasons=["Evidence is conflicting or too weak to assign a definitive primary attack vector."],
            supporting_indicators=[],
            evidence_basis=["Requires additional internal logs or external intelligence for confirmation."]
        )
        
    # Cap confidence deterministically based on score (e.g. 95 max)
    confidence = min(95, max(40, best_score))
    
    return InvestigativeAssessment(
        vector=best_vector,
        confidence=confidence,
        reasons=list(set(reasons[best_vector])),
        supporting_indicators=list(set(supporting[best_vector])),
        evidence_basis=list(set(evidence[best_vector]))
    )
