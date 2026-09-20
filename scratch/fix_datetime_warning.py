with open('backend/app/domain_intelligence.py', 'r') as f:
    text = f.read()

text = text.replace('datetime.utcnow()', 'datetime.now(timezone.utc).replace(tzinfo=None)')

with open('backend/app/domain_intelligence.py', 'w') as f:
    f.write(text)
