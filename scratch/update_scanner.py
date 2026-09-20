import re

with open('backend/app/scanner.py', 'r') as f:
    text = f.read()

# 1. Add import
if 'from app.ip_intelligence import get_ip_intelligence' not in text:
    text = text.replace('from app.url_analyzer import analyze_url', 'from app.url_analyzer import analyze_url\nfrom app.ip_intelligence import get_ip_intelligence')

# 2. Extract unique IPs
extract_code = """
    # URL Intelligence
    for i in range(len(urls)):
        urls[i] = analyze_url(urls[i])
        
    # IP Intelligence
    ip_intel_dict = {}
    extracted_ips = set()
    for h in relays:
        if h.ip_address: extracted_ips.add(h.ip_address)
    for u in urls:
        if u.is_ip_host: extracted_ips.add(u.hostname)
        
    for ip in extracted_ips:
        intel = get_ip_intelligence(ip)
        ip_intel_dict[ip] = intel.model_dump()
"""

text = re.sub(r'# URL Intelligence.*?for i in range\(len\(urls\)\):\s*urls\[i\] = analyze_url\(urls\[i\]\)', extract_code.strip(), text, flags=re.DOTALL)

# 3. Replace the kwargs in FullAnalysisResult
text = re.sub(r'ip_intelligence=\{[^\}]+\},', 'ip_intelligence=ip_intel_dict,', text)

with open('backend/app/scanner.py', 'w') as f:
    f.write(text)
