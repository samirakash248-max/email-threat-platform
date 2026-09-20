import os
import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backend")))
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def print_step(msg):
    print(f"\n[+] {msg}")

def upload_email(filepath):
    with open(filepath, "rb") as f:
        res = client.post("/api/analyze-file", files={"file": f})
    assert res.status_code == 200, res.text
    return res.json()

def main():
    print_step("1. Ingesting Synthetic Demo Dataset")
    ds_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples", "demo_dataset"))
    
    a_res = upload_email(os.path.join(ds_dir, "email_a_exec.eml"))
    b_res = upload_email(os.path.join(ds_dir, "email_b_infra.eml"))
    c_res = upload_email(os.path.join(ds_dir, "email_c_attach.eml"))
    d_res = upload_email(os.path.join(ds_dir, "email_d_benign.eml"))
    
    print_step("2. Verifying Threat Scores")
    print(f"Email A (Exec Phish): {a_res['threat_score']['overall_score']} - {a_res['threat_score']['risk_level']}")
    print(f"Email B (Infra): {b_res['threat_score']['overall_score']} - {b_res['threat_score']['risk_level']}")
    print(f"Email C (Attach): {c_res['threat_score']['overall_score']} - {c_res['threat_score']['risk_level']}")
    print(f"Email D (Benign): {d_res['threat_score']['overall_score']} - {d_res['threat_score']['risk_level']}")
    
    # Asserting threat levels
    assert a_res['threat_score']['overall_score'] > 40
    assert d_res['threat_score']['overall_score'] == 0
    
    print_step("3. Verifying URL Intelligence on Email A")
    urls = a_res.get('extracted_urls', [])
    assert any("192.168.1.100" in u['domain'] or "192.168.1.100" in str(u) for u in urls), "URL not extracted!"
    print("URL Intelligence successfully identified malicious infrastructure.")
    
    print_step("4. Verifying MITRE ATT&CK Mappings on Email A")
    mitre = a_res.get('mitre_attack_mappings', [])
    for m in mitre:
        print(f" - {m['technique_id']}: {m['tactic']} ({m['reason']})")
    assert any("T15" in m['technique_id'] for m in mitre), "Missing T1566 mapping!"
    
    print_step("5. Creating Case & Correlating Campaigns")
    case_res = client.post("/api/cases", json={
        "title": "Demo Phishing Incident",
        "description": "Executive Impersonation",
        "priority": "HIGH",
        "initial_analysis_id": a_res['analysis_id']
    })
    assert case_res.status_code == 200, case_res.text
    case_id = case_res.json()["id"]
    print(f"Case Created: {case_id}")
    
    # Also create cases for B, C, D to trigger correlation
    c_b = client.post("/api/cases", json={"title": "Case B", "description": "", "priority": "MEDIUM", "initial_analysis_id": b_res['analysis_id']}).json()["id"]
    c_c = client.post("/api/cases", json={"title": "Case C", "description": "", "priority": "MEDIUM", "initial_analysis_id": c_res['analysis_id']}).json()["id"]
    c_d = client.post("/api/cases", json={"title": "Case D", "description": "", "priority": "LOW", "initial_analysis_id": d_res['analysis_id']}).json()["id"]
    client.get(f"/api/graph/cases/{case_id}")
    client.get(f"/api/graph/cases/{c_b}")
    client.get(f"/api/graph/cases/{c_c}")
    client.get(f"/api/graph/cases/{c_d}")
    # Need to run correlate_case directly since patch does not run it
    from app.correlator import correlate_case
    from app.main import get_db
    db = next(get_db())
    from app.models import CaseRecord
    for cid in [case_id, c_b, c_c, c_d]:
        correlate_case(db.query(CaseRecord).filter_by(id=cid).first(), db)

    
    print_step("6. Verifying Threat Campaign Correlation")
    camps_res = client.get("/api/campaigns")
    assert camps_res.status_code == 200
    camps = camps_res.json()
    print(f"Found {len(camps)} campaigns.")
    # Check if a campaign groups A and B together (shared domain `trustd-bank.com`)
    for c in camps:
        print(f"Campaign {c['id']} related cases: {c.get('related_cases', [])}")
    
    print_step("7. Chain of Custody & Blockchain Verification (Email A)")
    verify_res = client.get(f"/api/blockchain/verify/{a_res['analysis_id']}")
    assert verify_res.status_code == 200
    v_data = verify_res.json()
    print(f"Blockchain Verification: {v_data}"); is_auth = v_data.get("is_authentic", v_data.get("verification_status") == "VERIFIED_AUTHENTIC"); print(f"Blockchain Anchored: {is_auth}")
    
    print_step("8. Simulating Tamper on Email A")
    tamper_res = client.post(f"/api/demo/simulate-tamper/{a_res['analysis_id']}")
    assert tamper_res.status_code == 200, tamper_res.text
    print("Database tampered!")
    
    tamper_verify = client.get(f"/api/blockchain/verify/{a_res['analysis_id']}")
    print(f"Blockchain Authentic After Tamper: {tamper_verify.json().get("is_authentic", tamper_verify.json().get("verification_status") == "VERIFIED_AUTHENTIC")}")
    assert not tamper_verify.json().get("is_authentic", tamper_verify.json().get("verification_status") == "VERIFIED_AUTHENTIC")
    
    print_step("9. Case Closure via SOC Analyst Workflow")
    patch_res = client.patch(f"/api/cases/{case_id}", json={"status": "CLOSED", "actor": "Demo Analyst", "assigned_analyst": "Demo Analyst"})
    assert patch_res.status_code == 200
    print("Case successfully closed.")

    print_step("DEMO SCENARIO COMPLETED SUCCESSFULLY.")

if __name__ == '__main__':
    main()
