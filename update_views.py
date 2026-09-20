import os

with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Add filterMitre state
state_str = "const [filterStatus, setFilterStatus] = useState('ALL');"
if "filterMitre" not in text:
    text = text.replace(state_str, state_str + "\\n  const [filterMitre, setFilterMitre] = useState('ALL');\\n  const [mitreDetails, setMitreDetails] = useState([]);")

# 2. Fetch MITRE details when activeCaseData changes
effect_str = '''api.getCase(selectedCaseId)
      .then(data => setActiveCaseData(data))
      .catch(err => console.error("Error loading case:", err))
      .finally(() => setLoading(false));'''

new_effect = '''api.getCase(selectedCaseId)
      .then(data => setActiveCaseData(data))
      .catch(err => console.error("Error loading case:", err))
      .finally(() => setLoading(false));
      
    api.getCaseMitreTechniques(selectedCaseId)
      .then(data => setMitreDetails(data))
      .catch(err => console.error("Error loading MITRE:", err));'''

if "getCaseMitreTechniques" not in text:
    text = text.replace(effect_str, new_effect)

# 3. Update filteredCases
old_filter = '''const filteredCases = cases.filter(c => {
    if (filterStatus === 'ALL') return true;
    return c.status === filterStatus;
  });'''
  
new_filter = '''const filteredCases = cases.filter(c => {
    let statusMatch = filterStatus === 'ALL' || c.status === filterStatus;
    let mitreMatch = true;
    if (filterMitre !== 'ALL') {
      const techniques = c.mitre_techniques || [];
      if (filterMitre === 'Phishing') mitreMatch = techniques.some(t => t.startsWith('T1566'));
      else if (filterMitre === 'Credential Theft') mitreMatch = techniques.some(t => t.startsWith('T1598') || t === 'T1566.002');
      else if (filterMitre === 'Malicious File') mitreMatch = techniques.includes('T1204.002') || techniques.includes('T1566.001');
      else if (filterMitre === 'Other') mitreMatch = techniques.length > 0;
    }
    return statusMatch && mitreMatch;
  });'''

if "let statusMatch" not in text:
    text = text.replace(old_filter, new_filter)

# 4. Render filter buttons
filter_ui_old = '''<select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}'''
              
filter_ui_new = '''<select
              value={filterMitre}
              onChange={(e) => setFilterMitre(e.target.value)}
              className="bg-[#EFF6FF] border border-[#E2E8F0] rounded-xl px-3 py-1.5 text-xs text-slate-800 font-bold focus:outline-none focus:border-blue-500 cursor-pointer"
            >
              <option value="ALL">MITRE: All</option>
              <option value="Phishing">MITRE: Phishing</option>
              <option value="Credential Theft">MITRE: Credential Theft</option>
              <option value="Malicious File">MITRE: Malicious File</option>
              <option value="Other">MITRE: Other</option>
            </select>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}'''

if "filterMitre" in filter_ui_new and "filterMitre" not in text.split("CaseManager")[1]:
    text = text.replace(filter_ui_old, filter_ui_new)

# 5. Render MITRE ATT&CK section in Case View
mitre_section = '''
                {/* MITRE ATT&CK Section */}
                {mitreDetails && mitreDetails.length > 0 && (
                  <div className="surface-card p-5 space-y-4">
                    <div className="border-b border-[#E2E8F0] pb-2 flex items-center justify-between">
                      <h3 className="font-bold text-sm text-slate-900 flex items-center gap-2">
                        <ShieldAlert className="w-4 h-4 text-rose-600" />
                        MITRE ATT&CK® Mappings
                      </h3>
                      <span className="text-[10px] bg-slate-100 text-slate-600 px-2 py-0.5 rounded font-mono border border-slate-200">{mitreDetails.length} Techniques</span>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {mitreDetails.map((tech, idx) => (
                        <details key={idx} className="group bg-[#F8FAFC] border border-[#E2E8F0] rounded-xl text-xs">
                          <summary className="p-3 cursor-pointer font-bold flex flex-col hover:bg-slate-50">
                            <div className="flex items-center justify-between">
                              <span className="text-blue-700 font-mono">{tech.technique_id}</span>
                              <span className="px-2 py-0.5 rounded text-[9px] uppercase font-bold border bg-rose-50 border-rose-200 text-rose-700">{tech.confidence} CONFIDENCE</span>
                            </div>
                            <span className="text-slate-800 mt-1">{tech.technique_name}</span>
                            <span className="text-[10px] text-slate-500 uppercase mt-0.5 font-normal tracking-wider">{tech.tactic}</span>
                          </summary>
                          <div className="p-3 pt-0 border-t border-[#E2E8F0] text-slate-600 space-y-2 mt-2">
                            <p className="font-sans leading-relaxed"><strong>Reason:</strong> {tech.reason}</p>
                            {tech.supporting_indicators && tech.supporting_indicators.length > 0 && (
                              <div className="pt-2">
                                <strong className="text-[10px] uppercase text-slate-400 block mb-1">Supporting Indicators:</strong>
                                <ul className="list-disc pl-4 space-y-1 font-mono text-[10px]">
                                  {tech.supporting_indicators.map((ind, i) => (
                                    <li key={i} className="text-slate-700 truncate">{ind}</li>
                                  ))}
                                </ul>
                              </div>
                            )}
                          </div>
                        </details>
                      ))}
                    </div>
                  </div>
                )}
'''

if "MITRE ATT&CK® Mappings" not in text:
    target = '''{/* Attached Analyses */}'''
    text = text.replace(target, mitre_section + "\\n                " + target)

with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as f:
    f.write(text)