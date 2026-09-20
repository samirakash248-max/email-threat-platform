with open('scripts/run_final_demo.py', 'r') as f:
    text = f.read()

text = text.replace('assert tamper_res.status_code == 200', 'assert tamper_res.status_code == 200, tamper_res.text')
text = text.replace('v_data.get("status") == "authentic"', 'v_data.get("verification_status") == "VERIFIED_AUTHENTIC"')
text = text.replace('tamper_verify.json().get("status") == "authentic"', 'tamper_verify.json().get("verification_status") == "VERIFIED_AUTHENTIC"')

with open('scripts/run_final_demo.py', 'w') as f:
    f.write(text)
