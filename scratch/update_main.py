import re

with open('backend/app/main.py', 'r') as f:
    text = f.read()

if 'from app.ip_intelligence import get_ip_intelligence' not in text:
    text = text.replace('from app.url_analyzer import analyze_url', 'from app.url_analyzer import analyze_url\nfrom app.ip_intelligence import get_ip_intelligence')

new_endpoint = """
@app.get("/api/intelligence/ip/{ip}")
def get_ip_intel(ip: str):
    try:
        intel = get_ip_intelligence(ip)
        return intel.model_dump()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
"""

if 'def get_ip_intel' not in text:
    # Just append to the end of main.py but before the SPA fallback
    text = text.replace('# Catch-all for SPA frontend routing', new_endpoint + '\n\n# Catch-all for SPA frontend routing')

with open('backend/app/main.py', 'w') as f:
    f.write(text)
