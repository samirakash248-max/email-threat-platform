import os

with open('backend/app/models.py', 'r', encoding='utf-8') as f:
    text = f.read()

if "active_campaigns: Optional[int]" not in text:
    text = text.replace("active_cases: int", "active_cases: int\\n    active_campaigns: Optional[int] = 0")
    with open('backend/app/models.py', 'w', encoding='utf-8') as f:
        f.write(text)
