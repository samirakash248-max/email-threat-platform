import re

with open('backend/app/main.py', 'r') as f:
    text = f.read()

# 1. Add import
if 'from app.domain_intelligence import get_domain_intelligence' not in text:
    text = text.replace('from app.ip_intelligence import get_ip_intelligence', 'from app.ip_intelligence import get_ip_intelligence\nfrom app.domain_intelligence import get_domain_intelligence')

new_endpoint = """
@app.get("/api/intelligence/domain/{domain}")
def get_domain_intel(domain: str):
    try:
        intel = get_domain_intelligence(domain)
        return intel.model_dump()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
"""

if 'def get_domain_intel' not in text:
    text = text.replace('# Catch-all for SPA frontend routing', new_endpoint + '\n\n# Catch-all for SPA frontend routing')

# 2. Enrich Graph domain nodes
graph_update = """
        if curr_type == "domain":
            try:
                intel = get_domain_intelligence(curr_id)
                nodes[node_key]["registrar"] = intel.whois_rdap.registrar
                nodes[node_key]["creation_date"] = intel.whois_rdap.creation_date
                nodes[node_key]["privacy_protected"] = intel.whois_rdap.privacy_protected
                nodes[node_key]["newly_registered"] = intel.risk.newly_registered
                nodes[node_key]["suspicious_tld"] = intel.risk.suspicious_tld
                nodes[node_key]["mx_records"] = len(intel.dns_records.mx)
            except Exception:
                pass
"""
if 'if curr_type == "domain":' not in text:
    text = text.replace('if curr_type == "ip":', graph_update + '\n        if curr_type == "ip":')

with open('backend/app/main.py', 'w') as f:
    f.write(text)
