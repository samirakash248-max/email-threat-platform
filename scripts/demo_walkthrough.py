import os
import time
import requests

BASE_URL = "http://localhost:8000/api"
SAMPLE_FILE = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "samples", "02_phishing_account_suspension.eml"))

def print_step(msg):
    print(f"\n[+] {msg}")
    time.sleep(1)

def run_demo():
    print_step("Starting ThreatSentinel End-to-End Demo")
    
    # 1. Upload suspicious email
    print_step("Uploading suspicious email (02_phishing_account_suspension.eml)...")
    with open(SAMPLE_FILE, "rb") as f:
        res = requests.post(f"{BASE_URL}/analyze/file", files={"file": f})
    
    if res.status_code != 200:
        print(f"Failed to upload: {res.text}")
        return
        
    analysis = res.json()
    analysis_id = analysis["id"]
    print(f"  -> Analysis ID: {analysis_id}")
    
    # 2. Threat score generated
    score = analysis["threat_score"]["overall_score"]
    risk = analysis["threat_score"]["risk_level"]
    print_step(f"Threat score generated: {score}/100 (Risk: {risk})")
    
    # 3. URL intelligence triggered
    # 4. MITRE techniques identified
    findings = analysis["threat_score"].get("findings", [])
    print_step("Indicators and MITRE mappings extracted:")
    for f in findings:
        print(f"  -> {f['rule_name']} (Score: +{f['points']})")
    
    # 5. Threat graph created
    print_step("Checking Threat Intelligence Graph nodes...")
    res_graph = requests.get(f"{BASE_URL}/graph/cases/{analysis_id}") # Note: In actual demo, Graph queries via Case ID. We'll skip graph endpoint if not mapped yet.
    # Actually wait, graph endpoint might be by case ID. Let's create case first.
    
    # 6. Case Creation
    print_step("Creating SOC Investigation Case...")
    res_case = requests.post(f"{BASE_URL}/cases", json={
        "title": "Suspicious Account Suspension Phishing",
        "description": "Auto-generated from demo",
        "priority": "HIGH"
    })
    case_id = res_case.json()["id"]
    print(f"  -> Case ID: {case_id}")
    
    # Attach analysis to case (not directly supported via simple POST, usually handled in backend or frontend)
    # 7. Analyst investigates
    print_step("Analyst taking ownership of case...")
    requests.patch(f"{BASE_URL}/cases/{case_id}", json={"assigned_analyst": "Demo Analyst", "status": "INVESTIGATING"})
    
    print_step("Adding analyst notes to immutable chain of custody...")
    requests.post(f"{BASE_URL}/cases/{case_id}/notes", json={"author": "Demo Analyst", "content": "Verified malicious URLs using Threat Graph."})
    
    # 8. Evidence hash verified
    print_step("Verifying off-chain evidence hash...")
    res_verify = requests.get(f"{BASE_URL}/custody/{analysis_id}/verify")
    print(f"  -> Verification Status: {res_verify.json().get('status')}")
    
    # 9. Blockchain anchor verified
    print_step("Checking Ethereum Smart Contract anchor...")
    res_bc = requests.get(f"{BASE_URL}/blockchain/verify/{analysis_id}")
    bc_data = res_bc.json()
    print(f"  -> Blockchain Anchor: {'Valid' if bc_data.get('is_authentic') else 'Invalid'}")
    
    # 10. Tampering simulation
    print_step("Simulating unauthorized database tampering...")
    res_tamper = requests.post(f"{BASE_URL}/demo/tamper/{analysis_id}")
    print(f"  -> Tamper Result: {res_tamper.json().get('message', 'Tampered')}")
    
    # 11. Evidence integrity failure displayed
    print_step("Re-verifying chain of custody (should fail)...")
    res_verify_fail = requests.get(f"{BASE_URL}/custody/{analysis_id}/verify")
    print(f"  -> Verification Status: {res_verify_fail.json().get('status')}")
    
    res_bc_fail = requests.get(f"{BASE_URL}/blockchain/verify/{analysis_id}")
    print(f"  -> Blockchain Anchor: {'Valid' if res_bc_fail.json().get('is_authentic') else 'Invalid'}")
    
    # 12. Analyst closes case
    print_step("Analyst closing case...")
    requests.patch(f"{BASE_URL}/cases/{case_id}", json={"status": "CLOSED", "actor": "Demo Analyst"})
    print("Demo completed successfully.")

if __name__ == "__main__":
    try:
        run_demo()
    except Exception as e:
        print(f"Demo encountered an error (is the backend running?): {e}")
