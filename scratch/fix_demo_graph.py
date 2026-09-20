with open('scripts/run_final_demo.py', 'r') as f:
    text = f.read()

text = text.replace('print_step("6. Verifying Threat Campaign Correlation")', 'for cid in [case_id, b_res["analysis_id"], c_res["analysis_id"], d_res["analysis_id"]]:\n        # Wait, the other case IDs aren\'t saved. I need to get them.\n        pass\n    print_step("6. Verifying Threat Campaign Correlation")')

# Let's save the case IDs from POST /api/cases
post_cases_replace = """
    c_b = client.post("/api/cases", json={"title": "Case B", "description": "", "priority": "MEDIUM", "initial_analysis_id": b_res['analysis_id']}).json()["id"]
    c_c = client.post("/api/cases", json={"title": "Case C", "description": "", "priority": "MEDIUM", "initial_analysis_id": c_res['analysis_id']}).json()["id"]
    c_d = client.post("/api/cases", json={"title": "Case D", "description": "", "priority": "LOW", "initial_analysis_id": d_res['analysis_id']}).json()["id"]
    
    # Trigger graph builds which populates indicators for correlation
    client.get(f"/api/graph/cases/{case_id}")
    client.get(f"/api/graph/cases/{c_b}")
    client.get(f"/api/graph/cases/{c_c}")
    client.get(f"/api/graph/cases/{c_d}")
"""

# Replace the old POST block
old_posts = """
    # Also create cases for B, C, D to trigger correlation
    client.post("/api/cases", json={"title": "Case B", "description": "", "priority": "MEDIUM", "initial_analysis_id": b_res['analysis_id']})
    client.post("/api/cases", json={"title": "Case C", "description": "", "priority": "MEDIUM", "initial_analysis_id": c_res['analysis_id']})
    client.post("/api/cases", json={"title": "Case D", "description": "", "priority": "LOW", "initial_analysis_id": d_res['analysis_id']})
"""

if old_posts.strip() in text:
    text = text.replace(old_posts.strip(), post_cases_replace.strip())
else:
    # Just insert it manually if not exactly matching
    pass

with open('scripts/run_final_demo.py', 'w') as f:
    f.write(text)
