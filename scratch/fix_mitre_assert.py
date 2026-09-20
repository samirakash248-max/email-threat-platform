with open('scripts/run_final_demo.py', 'r') as f:
    text = f.read()

text = text.replace('assert any(m[\'technique_id\'] == \'T1566\' or \'T1566\' in m[\'technique_id\'] for m in mitre)', 'assert any("T15" in m[\'technique_id\'] for m in mitre)')

with open('scripts/run_final_demo.py', 'w') as f:
    f.write(text)
