import os
with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

start_sync = text.find('def sync_case_mitre')
end_sync = text.find('if __name__ ==')

if start_sync != -1:
    extracted = text[start_sync:end_sync]
    text = text[:start_sync] + text[end_sync:]
    
    insert_pos = text.find('@app.get("/api/cases"')
    text = text[:insert_pos] + extracted + '\n' + text[insert_pos:]
    
    with open('backend/app/main.py', 'w', encoding='utf-8') as f:
        f.write(text)