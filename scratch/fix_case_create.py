with open('scripts/run_final_demo.py', 'r') as f:
    text = f.read()

text = text.replace('"attached_analysis_ids": [a_res[\'analysis_id\']]', '"initial_analysis_id": a_res[\'analysis_id\']')
text = text.replace('"attached_analysis_ids": [b_res[\'analysis_id\']]', '"initial_analysis_id": b_res[\'analysis_id\']')
text = text.replace('"attached_analysis_ids": [c_res[\'analysis_id\']]', '"initial_analysis_id": c_res[\'analysis_id\']')
text = text.replace('"attached_analysis_ids": [d_res[\'analysis_id\']]', '"initial_analysis_id": d_res[\'analysis_id\']')

with open('scripts/run_final_demo.py', 'w') as f:
    f.write(text)
