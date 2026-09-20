with open('scripts/run_final_demo.py', 'r') as f:
    text = f.read()

text = text.replace('print(f"Blockchain Anchored: {v_data[\'is_authentic\']}")', 
'print(f"Blockchain Verification: {v_data}"); is_auth = v_data.get("is_authentic", v_data.get("status") == "authentic"); print(f"Blockchain Anchored: {is_auth}")')

text = text.replace('assert not tamper_verify.json()[\'is_authentic\']', 'assert not tamper_verify.json().get("is_authentic", tamper_verify.json().get("status") == "authentic")')
text = text.replace('tamper_verify.json()[\'is_authentic\']', 'tamper_verify.json().get("is_authentic", tamper_verify.json().get("status") == "authentic")')

with open('scripts/run_final_demo.py', 'w') as f:
    f.write(text)
