with open('scripts/run_final_demo.py', 'r') as f:
    text = f.read()

text = text.replace('print(f"Campaign {c[\'id\']} nodes: {c[\'node_count\']} edges: {c[\'edge_count\']}")', 
'print(f"Campaign {c[\'id\']} related cases: {c.get(\'related_cases\', [])}")')

with open('scripts/run_final_demo.py', 'w') as f:
    f.write(text)
