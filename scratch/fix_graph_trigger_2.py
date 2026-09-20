with open('scripts/run_final_demo.py', 'r') as f:
    text = f.read()
text = text.replace("\\'", "'")
with open('scripts/run_final_demo.py', 'w') as f:
    f.write(text)
