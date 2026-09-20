from fastapi.testclient import TestClient
from app.main import app
from app.models import SessionLocal, CaseRecord, CustodyEventRecord

client = TestClient(app)

def test_case_lifecycle():
    # 1. Create a case
    res = client.post("/api/cases", json={
        "title": "SOC Workflow Test",
        "description": "Testing transitions",
        "priority": "HIGH"
    })
    assert res.status_code == 200
    case_id = res.json()["id"]
    assert res.json()["status"] == "NEW"

    # 2. Add an analyst note
    res_note = client.post(f"/api/cases/{case_id}/notes", json={
        "author": "Alice",
        "content": "Initial triage"
    })
    assert res_note.status_code == 200
    assert len(res_note.json()["notes"]) == 2  # 1 from creation, 1 from Alice

    # 3. Assign to Alice
    res_assign = client.patch(f"/api/cases/{case_id}", json={
        "assigned_analyst": "Alice",
        "actor": "SOC-Manager"
    })
    assert res_assign.status_code == 200
    assert res_assign.json()["assigned_analyst"] == "Alice"

    # 4. Valid transition: NEW -> TRIAGED
    res_tr = client.patch(f"/api/cases/{case_id}", json={
        "status": "TRIAGED",
        "actor": "Alice"
    })
    assert res_tr.status_code == 200
    assert res_tr.json()["status"] == "TRIAGED"

    # 5. Invalid transition: TRIAGED -> RESOLVED
    res_inv = client.patch(f"/api/cases/{case_id}", json={
        "status": "RESOLVED",
        "actor": "Alice"
    })
    assert res_inv.status_code == 400
    assert "Invalid transition" in res_inv.json()["detail"]

    # 6. Valid chain to RESOLVED: TRIAGED -> INVESTIGATING -> RESOLVED
    client.patch(f"/api/cases/{case_id}", json={"status": "INVESTIGATING"})
    res_res = client.patch(f"/api/cases/{case_id}", json={"status": "RESOLVED"})
    assert res_res.status_code == 200

    # 7. Check export
    res_exp = client.get(f"/api/cases/{case_id}/export")
    assert res_exp.status_code == 200
    print(res_exp.text)
    exp_data = res_exp.json()
    assert exp_data["case_id"] == case_id
    assert exp_data["status"] == "RESOLVED"
    assert exp_data["assigned_analyst"] == "Alice"
    assert len(exp_data["analyst_notes"]) == 2
