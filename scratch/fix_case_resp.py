import os

with open('backend/app/models.py', 'r', encoding='utf-8') as f:
    text = f.read()

if "assigned_analyst: Optional[str] = None" not in text:
    text = text.replace('priority: str = "HIGH"', 'priority: str = "HIGH"\\n    assigned_analyst: Optional[str] = None')
    with open('backend/app/models.py', 'w', encoding='utf-8') as f:
        f.write(text)
        
with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    text = f.read()
    
if "assigned_analyst=c.assigned_analyst" not in text:
    text = text.replace('priority=c.priority,', 'priority=c.priority,\\n        assigned_analyst=c.assigned_analyst,')
    with open('backend/app/main.py', 'w', encoding='utf-8') as f:
        f.write(text)
