import re

with open('frontend/src/components/AnalysisWorkspace.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

new_ui = """            <div className="surface-card p-6 space-y-4">
              <h3 className="font-bold text-sm text-slate-900">Domain Intelligence & Forensics</h3>
              <p className="text-xs text-slate-500 italic mb-2">Note: This represents the domain intelligence and configuration. It does not establish domain ownership attribution.</p>
              <div className="space-y-4">
                {Object.entries(domain_intelligence).map(([dom, info], idx) => (
                  <div key={idx} className="surface-card-subtle p-4 border border-slate-200 rounded-lg space-y-3 text-xs font-sans">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-blue-600 font-mono text-sm">{dom}</span>
                      <div className="flex gap-2">
                        {info.is_lookalike_typosquat && (
                          <span className="px-2.5 py-0.5 bg-rose-50 text-rose-600 border border-rose-200 rounded-full text-[10px] font-bold uppercase">Homoglyph / Lookalike</span>
                        )}
                        {info.risk?.suspicious_tld && (
                          <span className="px-2.5 py-0.5 bg-orange-50 text-orange-600 border border-orange-200 rounded-full text-[10px] font-bold uppercase">Suspicious TLD</span>
                        )}
                        {info.risk?.newly_registered && (
                          <span className="px-2.5 py-0.5 bg-purple-50 text-purple-600 border border-purple-200 rounded-full text-[10px] font-bold uppercase">Newly Registered</span>
                        )}
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4">
                      <div>
                        <h4 className="font-semibold text-slate-700 border-b border-slate-200 pb-1 mb-1.5">DNS Records</h4>
                        <div className="space-y-1 text-slate-600 font-mono text-[11px]">
                          {info.dns_records?.a?.length > 0 && <div><span className="text-slate-400">A:</span> {info.dns_records.a.join(', ')}</div>}
                          {info.dns_records?.mx?.length > 0 && <div><span className="text-slate-400">MX:</span> {info.dns_records.mx.join(', ')}</div>}
                          {info.dns_records?.txt?.length > 0 && <div><span className="text-slate-400">TXT:</span> {info.dns_records.txt.length} records</div>}
                          {info.dns_resolution_status === 'unavailable' && <div className="text-amber-600 italic">DNS resolution unavailable</div>}
                        </div>
                      </div>
                      
                      <div>
                        <h4 className="font-semibold text-slate-700 border-b border-slate-200 pb-1 mb-1.5">Registration (WHOIS/RDAP)</h4>
                        <div className="space-y-1 text-slate-600 text-[11px]">
                          {info.whois_rdap?.status === 'success' ? (
                            <>
                              <div><span className="text-slate-400">Registrar:</span> {info.whois_rdap.registrar || 'Unknown'}</div>
                              <div><span className="text-slate-400">Created:</span> {info.whois_rdap.creation_date || 'Unknown'}</div>
                              <div>
                                <span className="text-slate-400">Privacy:</span> 
                                {info.whois_rdap.privacy_protected ? <span className="text-orange-600 font-medium ml-1">Protected/Redacted</span> : ' Public'}
                              </div>
                            </>
                          ) : (
                            <div className="text-slate-400 italic">Registration data {info.whois_rdap?.status || 'unavailable'}</div>
                          )}
                        </div>
                      </div>
                    </div>
                    
                    {(info.risk?.risk_factors?.length > 0 || info.lookalike_target_brand) && (
                      <div className="mt-2 pt-2 border-t border-slate-100">
                        <h4 className="font-semibold text-rose-700 text-[11px] mb-1">Risk Factors</h4>
                        <ul className="list-disc pl-4 text-[11px] text-slate-600 space-y-0.5">
                          {info.lookalike_target_brand && <li>Impersonating brand: <strong>{info.lookalike_target_brand}</strong></li>}
                          {info.risk?.risk_factors?.map((rf, rfi) => (
                            <li key={rfi}>{rf}</li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </div>
                ))}
                {Object.keys(domain_intelligence || {}).length === 0 && (
                  <p className="text-xs text-slate-500 py-6 text-center">No domain intelligence discovered.</p>
                )}
              </div>
            </div>"""

old_ui_start = '<h3 className="font-bold text-sm text-slate-900">Domain & Lookalike Forensics</h3>'
old_ui_end = '</p>\n                )}\n              </div>\n            </div>'

if old_ui_start in text:
    # Use regex to replace the specific block
    import re
    # We want to replace the whole <div className="surface-card p-6 space-y-4"> ... Domain & Lookalike Forensics ... </div>
    pattern = r'<div className="surface-card p-6 space-y-4">\s*<h3 className="font-bold text-sm text-slate-900">Domain & Lookalike Forensics</h3>.*?No domain anomalies discovered.</p>\s*\}\)\s*</div>\s*</div>'
    text = re.sub(pattern, new_ui, text, flags=re.DOTALL)

with open('frontend/src/components/AnalysisWorkspace.jsx', 'w', encoding='utf-8') as f:
    f.write(text)
