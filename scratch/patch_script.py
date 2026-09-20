import re

with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    text = f.read()
    
m = re.search(r'@app\.patch\("/api/cases/\{case_id\}"\)', text)
if m:
    print("PATCH endpoint:")
    print(text[m.start():m.start()+500])

m = re.search(r'@app\.post\("/api/cases/\{case_id\}/notes"\)', text)
if m:
    print("\nNOTES endpoint:")
    print(text[m.start():m.start()+500])
