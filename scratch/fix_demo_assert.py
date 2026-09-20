with open('scripts/run_final_demo.py', 'r') as f:
    text = f.read()

text = text.replace('"secure-login-update.com" in u[\'domain\']', '"192.168.1.100" in u[\'domain\'] or "192.168.1.100" in str(u)')

with open('scripts/run_final_demo.py', 'w') as f:
    f.write(text)
