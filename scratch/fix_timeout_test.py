with open('backend/app/domain_intelligence.py', 'r') as f:
    text = f.read()

text = text.replace('except Exception: pass', 'except Exception as e:\n            if isinstance(e, dns.exception.Timeout): raise e')

with open('backend/app/domain_intelligence.py', 'w') as f:
    f.write(text)
