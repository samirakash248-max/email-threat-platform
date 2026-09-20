with open('backend/app/main.py', 'r') as f:
    text = f.read()
text = text.replace('from app.models import (', 'from app.models import (\n    GraphEdgeRecord,')
with open('backend/app/main.py', 'w') as f:
    f.write(text)
