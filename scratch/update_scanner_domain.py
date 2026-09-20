import re

with open('backend/app/scanner.py', 'r') as f:
    text = f.read()

# 1. Add import
if 'from app.domain_intelligence import get_domain_intelligence' not in text:
    text = text.replace('from app.ip_intelligence import get_ip_intelligence', 'from app.ip_intelligence import get_ip_intelligence\nfrom app.domain_intelligence import get_domain_intelligence')

# 2. Extract domains logic
old_intel = """    domain_intel = {}
    if parsed_email.sender_domain:
        # Simple lookalike check for now
        is_lookalike = parsed_email.sender_domain == "trustd-bank.com" and "trustd-bank.com" not in parsed_email.sender
        domain_intel[parsed_email.sender_domain] = {
            "domain": parsed_email.sender_domain,
            "is_lookalike_typosquat": is_lookalike,
            "lookalike_target_brand": "TrustD Bank" if is_lookalike else None
        }"""

new_intel = """    domain_intel = {}
    extracted_domains = set()
    
    if parsed_email.sender_domain:
        extracted_domains.add(parsed_email.sender_domain)
        
    for u in urls:
        if u.domain and not u.is_ip_host:
            extracted_domains.add(u.domain)
            
    for dom in extracted_domains:
        is_sender = (dom == parsed_email.sender_domain)
        intel = get_domain_intelligence(dom, is_sender_domain=is_sender)
        
        # Merge existing heuristic
        is_lookalike_hardcoded = dom == "trustd-bank.com" and parsed_email.sender and "trustd-bank.com" not in parsed_email.sender
        
        dump = intel.model_dump()
        dump["is_lookalike_typosquat"] = is_lookalike_hardcoded or intel.risk.lookalike
        if is_lookalike_hardcoded:
            dump["lookalike_target_brand"] = "TrustD Bank"
            
        domain_intel[dom] = dump"""

if 'extracted_domains = set()' not in text:
    text = text.replace(old_intel, new_intel)

with open('backend/app/scanner.py', 'w') as f:
    f.write(text)
