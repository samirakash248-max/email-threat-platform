with open('frontend/src/components/AnalysisWorkspace.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

import re
old_privacy = "<div>\n                                <span className=\"text-slate-400\">Privacy:</span> \n                                {info.whois_rdap.privacy_protected ? <span className=\"text-orange-600 font-medium ml-1\">Protected/Redacted</span> : ' Public'}\n                              </div>"

new_privacy = """<div>
                                <span className="text-slate-400">Privacy:</span> 
                                {info.whois_rdap.privacy_protected ? <span className="text-orange-600 font-medium ml-1">Protected/Redacted</span> : ' Public'}
                              </div>
                              {info.whois_rdap.expiration_date && <div><span className="text-slate-400">Expires:</span> {info.whois_rdap.expiration_date}</div>}
                              {info.whois_rdap.updated_date && <div><span className="text-slate-400">Updated:</span> {info.whois_rdap.updated_date}</div>}"""

text = text.replace(old_privacy, new_privacy)

with open('frontend/src/components/AnalysisWorkspace.jsx', 'w', encoding='utf-8') as f:
    f.write(text)
