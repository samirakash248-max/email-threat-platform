import re

with open('frontend/src/components/AnalysisWorkspace.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

new_intel_tab = """activeTab === 'intel' && (
        <div className="space-y-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="surface-card p-6 space-y-4">
              <h3 className="font-bold text-sm text-slate-900">Domain & Lookalike Forensics</h3>
              <div className="space-y-2.5">
                {Object.entries(domain_intelligence).map(([dom, info], idx) => (
                  <div key={idx} className="surface-card-subtle p-3.5 space-y-1 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <span className="font-bold text-blue-600">{dom}</span>
                      {info.is_lookalike_typosquat && (
                        <span className="px-2.5 py-0.5 bg-rose-50 text-rose-600 border border-rose-200 rounded-full text-[10px] font-bold uppercase">
                          Homoglyph Typosquatting
                        </span>
                      )}
                    </div>
                    {info.lookalike_target_brand && (
                      <div className="text-[11px] text-slate-600 font-sans">
                        Impersonating brand: <strong className="text-slate-800">{info.lookalike_target_brand}</strong>
                      </div>
                    )}
                  </div>
                ))}
                {Object.keys(domain_intelligence).length === 0 && (
                  <p className="text-xs text-slate-500 py-6 text-center">No domain anomalies discovered.</p>
                )}
              </div>
            </div>

            <div className="surface-card p-6 space-y-4">
              <h3 className="font-bold text-sm text-slate-900">Extracted Hyperlinks ({extracted_urls.length})</h3>
              <div className="space-y-2.5 max-h-80 overflow-y-auto">
                {extracted_urls.map((u, idx) => (
                  <div key={idx} className="surface-card-subtle p-3.5 space-y-2 text-xs font-mono border border-slate-200">
                    <div className="flex items-center justify-between">
                      <div className="text-blue-600 font-bold truncate max-w-[70%]">{u.url}</div>
                      {u.risk_level === 'CRITICAL' && <span className="px-2 py-0.5 bg-rose-50 text-rose-700 border border-rose-200 rounded-full text-[10px] font-bold">CRITICAL RISK ({u.risk_score})</span>}
                      {u.risk_level === 'HIGH' && <span className="px-2 py-0.5 bg-orange-50 text-orange-700 border border-orange-200 rounded-full text-[10px] font-bold">HIGH RISK ({u.risk_score})</span>}
                      {u.risk_level === 'MEDIUM' && <span className="px-2 py-0.5 bg-amber-50 text-amber-800 border border-amber-200 rounded-full text-[10px] font-bold">MEDIUM RISK ({u.risk_score})</span>}
                      {u.risk_level === 'LOW' && <span className="px-2 py-0.5 bg-emerald-50 text-emerald-700 border border-emerald-200 rounded-full text-[10px] font-bold">LOW RISK</span>}
                    </div>
                    <div className="text-[11px] text-slate-600 font-sans flex items-center gap-3">
                      <span>Domain: <strong className="text-slate-700 font-mono">{u.domain || u.hostname}</strong></span>
                      {u.is_ip_host && <span className="text-rose-600 font-bold">(Raw IP Address)</span>}
                    </div>
                    {u.has_anchor_mismatch && (
                      <div className="text-[10px] text-rose-600 font-sans">
                         Anchor text mismatch: Displayed "{u.anchor_text}" differs from destination.
                      </div>
                    )}
                    {u.triggered_rules && u.triggered_rules.length > 0 && (
                      <details className="mt-2 text-slate-600 font-sans group">
                        <summary className="cursor-pointer text-blue-600 font-semibold hover:underline text-[11px]">View URL Intelligence Details ({u.triggered_rules.length} Signals)</summary>
                        <div className="mt-2 p-2 bg-slate-50 border border-slate-200 rounded-lg space-y-1.5">
                          {u.triggered_rules.map((rule, ridx) => (
                            <div key={ridx} className="flex justify-between items-center bg-white p-1.5 border border-slate-100 rounded">
                              <span className="font-medium text-slate-800"> {rule.rule_name}</span>
                              <span className="text-rose-600 font-mono text-[10px]">+{rule.score_contribution} pts</span>
                            </div>
                          ))}
                        </div>
                      </details>
                    )}
                  </div>
                ))}
                {extracted_urls.length === 0 && (
                  <p className="text-xs text-slate-500 py-6 text-center">No hyperlinks found in message.</p>
                )}
              </div>
            </div>
          </div>
          
          {/* INFRASTRUCTURE INTELLIGENCE */}
          <div className="surface-card p-6 space-y-4">
            <h3 className="font-bold text-sm text-slate-900 flex items-center gap-2">
              <Globe className="w-4 h-4 text-purple-600" /> Infrastructure Intelligence (Observed IPs)
            </h3>
            <p className="text-xs text-slate-500 italic mb-2">Note: This represents the observed infrastructure (e.g. relays, hosting providers, or Tor nodes). It does not establish the physical location or true identity of the sender.</p>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {Object.entries(ip_intelligence || {}).map(([ip, data], idx) => (
                <div key={idx} className="surface-card-subtle p-4 border border-slate-200 rounded-lg space-y-2">
                  <div className="flex justify-between items-start">
                    <span className="font-mono font-bold text-slate-800">{ip}</span>
                    <span className={`px-2 py-0.5 rounded-full text-[10px] font-bold ${
                      data.classification === 'TOR_EXIT_NODE' ? 'bg-rose-100 text-rose-800' :
                      data.classification === 'VPN/PROXY' ? 'bg-orange-100 text-orange-800' :
                      data.classification === 'DATACENTER' ? 'bg-purple-100 text-purple-800' :
                      data.classification === 'CLOUD/HOSTING' ? 'bg-blue-100 text-blue-800' :
                      'bg-slate-100 text-slate-800'
                    }`}>
                      {data.classification || 'UNKNOWN'}
                    </span>
                  </div>
                  
                  <div className="text-xs font-sans space-y-1">
                    <div className="flex justify-between">
                      <span className="text-slate-500">Observed IP Location:</span>
                      <span className="font-medium text-slate-700">{data.city ? `${data.city}, ${data.country}` : data.country || 'Unknown'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">ASN:</span>
                      <span className="font-medium text-slate-700">{data.asn || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Organization:</span>
                      <span className="font-medium text-slate-700 truncate ml-2 text-right" title={data.organization}>{data.organization || 'N/A'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Confidence:</span>
                      <span className="font-medium text-slate-700">{data.confidence || 'Medium'}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-slate-500">Intel Source:</span>
                      <span className="font-medium text-slate-700 truncate ml-2 text-right" title={data.source}>{data.source || 'Local'}</span>
                    </div>
                  </div>
                </div>
              ))}
              {Object.keys(ip_intelligence || {}).length === 0 && (
                <div className="col-span-full text-center py-6 text-slate-500 text-xs">
                  No IP infrastructure intelligence available.
                </div>
              )}
            </div>
          </div>
        </div>
      )"""

idx_intel = text.find("activeTab === 'intel'")
idx_attach = text.find("activeTab === 'attachments'")

text = text[:idx_intel] + new_intel_tab + text[idx_attach:]

with open('frontend/src/components/AnalysisWorkspace.jsx', 'w', encoding='utf-8') as f:
    f.write(text)
