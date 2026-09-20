with open('backend/app/main.py', 'r') as f:
    text = f.read()

import re
old_api = """        "last_seen": c.last_seen.isoformat() if c.last_seen else None,
        "cases_count": len(c.related_cases or []),"""

new_api = """        "last_seen": c.last_seen.isoformat() if c.last_seen else None,
        "cases_count": len(c.related_cases or []),
        "related_cases": c.related_cases or [],"""

if '"related_cases":' not in text:
    text = text.replace(old_api, new_api)

with open('backend/app/main.py', 'w') as f:
    f.write(text)
