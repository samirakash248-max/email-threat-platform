import re
with open('scripts/run_final_demo.py', 'r') as f:
    text = f.read()

text = re.sub(r'client\.post\("/api/cases".*?Case B.*?b_res.*?\)', r'c_b = client.post("/api/cases", json={"title": "Case B", "description": "", "priority": "MEDIUM", "initial_analysis_id": b_res[\'analysis_id\']}).json()["id"]', text)
text = re.sub(r'client\.post\("/api/cases".*?Case C.*?c_res.*?\)', r'c_c = client.post("/api/cases", json={"title": "Case C", "description": "", "priority": "MEDIUM", "initial_analysis_id": c_res[\'analysis_id\']}).json()["id"]', text)
text = re.sub(r'client\.post\("/api/cases".*?Case D.*?d_res.*?\)', r'c_d = client.post("/api/cases", json={"title": "Case D", "description": "", "priority": "LOW", "initial_analysis_id": d_res[\'analysis_id\']}).json()["id"]\n    client.get(f"/api/graph/cases/{case_id}")\n    client.get(f"/api/graph/cases/{c_b}")\n    client.get(f"/api/graph/cases/{c_c}")\n    client.get(f"/api/graph/cases/{c_d}")\n    # Need to run correlate_case directly since patch does not run it\n    from app.correlator import correlate_case\n    from app.main import get_db\n    db = next(get_db())\n    from app.models import CaseRecord\n    for cid in [case_id, c_b, c_c, c_d]:\n        correlate_case(db.query(CaseRecord).filter_by(id=cid).first(), db)\n', text)

with open('scripts/run_final_demo.py', 'w') as f:
    f.write(text)
