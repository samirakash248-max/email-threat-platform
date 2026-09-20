with open('backend/tests/test_ip_intelligence.py', 'r') as f:
    text = f.read()
text = text.replace('203.0.113.1', '93.184.216.34')
with open('backend/tests/test_ip_intelligence.py', 'w') as f:
    f.write(text)
