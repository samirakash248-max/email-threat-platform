with open('backend/app/main.py', 'r') as f:
    text = f.read()

import re
old = '"cases_count": len(c.related_cases or []),'
new = '"cases_count": len(c.related_cases or []),\n        "related_cases": c.related_cases or [],'
text = text.replace(old, new)

with open('backend/app/main.py', 'w') as f:
    f.write(text)
