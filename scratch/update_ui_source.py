with open('frontend/src/components/AnalysisWorkspace.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

import re
old = "                              {info.whois_rdap.updated_date && <div><span className=\"text-slate-400\">Updated:</span> {info.whois_rdap.updated_date}</div>}"

new = """                              {info.whois_rdap.updated_date && <div><span className="text-slate-400">Updated:</span> {info.whois_rdap.updated_date}</div>}
                              <div><span className="text-slate-400">Source:</span> {info.whois_rdap.source}</div>"""

text = text.replace(old, new)

with open('frontend/src/components/AnalysisWorkspace.jsx', 'w', encoding='utf-8') as f:
    f.write(text)
