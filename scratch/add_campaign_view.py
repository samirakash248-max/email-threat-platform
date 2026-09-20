import os

with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

campaign_view = """
export function CampaignManager({ onOpenGraph }) {
  const [campaigns, setCampaigns] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedCampaign, setSelectedCampaign] = useState(null);

  useEffect(() => {
    setLoading(true);
    api.getCampaigns()
      .then(setCampaigns)
      .catch(console.error)
      .finally(() => setLoading(false));
  }, []);

  if (selectedCampaign) {
    return (
      <div className="space-y-6">
        <div className="flex items-center gap-4">
          <button onClick={() => setSelectedCampaign(null)} className="p-2 hover:bg-slate-100 rounded-full transition-colors"><ArrowLeft className="w-5 h-5 text-slate-600"/></button>
          <div>
            <h2 className="text-xl font-bold text-slate-900">{selectedCampaign.name}</h2>
            <p className="text-sm text-slate-500 font-mono">{selectedCampaign.id}</p>
          </div>
          <div className="ml-auto flex gap-3">
            <span className={`px-3 py-1 rounded-full text-xs font-bold ${selectedCampaign.correlation_level === 'HIGH' ? 'bg-rose-100 text-rose-700' : selectedCampaign.correlation_level === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-blue-100 text-blue-700'}`}>
              {selectedCampaign.correlation_level} CORRELATION
            </span>
          </div>
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="md:col-span-2 space-y-6">
            <div className="surface-card p-6">
              <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2"><Network className="w-5 h-5 text-purple-600"/> Correlation Evidence</h3>
              <ul className="space-y-3">
                {selectedCampaign.correlation_reasons.map((r, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm text-slate-700">
                    <CheckCircle2 className="w-4 h-4 text-emerald-500 mt-0.5 shrink-0" />
                    {r}
                  </li>
                ))}
              </ul>
              {selectedCampaign.correlation_reasons.length === 0 && <p className="text-sm text-slate-500 italic">Base candidate. Needs more data.</p>}
            </div>
            
            <div className="surface-card p-6">
              <h3 className="font-bold text-slate-800 mb-4 flex items-center gap-2"><Target className="w-5 h-5 text-rose-600"/> Shared Indicators</h3>
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                {selectedCampaign.related_indicators.map((ind, i) => (
                  <div key={i} className="p-3 bg-slate-50 border border-slate-200 rounded-xl flex items-center gap-3">
                    <span className="uppercase text-[10px] font-bold text-slate-500 w-16">{ind.type}</span>
                    <span className="font-mono text-xs text-slate-800 truncate">{ind.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
          
          <div className="space-y-6">
            <div className="surface-card p-6">
              <h3 className="font-bold text-slate-800 mb-4">Linked Cases ({selectedCampaign.cases_count || (selectedCampaign.related_cases || []).length})</h3>
              <div className="space-y-2">
                {(selectedCampaign.related_cases || []).map(cid => (
                  <div key={cid} className="p-2 border border-slate-200 rounded text-xs font-mono text-slate-700">{cid}</div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h2 className="font-bold text-xl text-slate-900 flex items-center gap-2">
          <Activity className="w-6 h-6 text-rose-600" />
          Threat Campaigns
        </h2>
      </div>
      
      {loading ? (
        <div className="p-12 flex justify-center"><Loader2 className="w-8 h-8 text-blue-500 animate-spin"/></div>
      ) : (
        <div className="grid grid-cols-1 gap-4">
          {campaigns.map(c => (
            <div key={c.id} onClick={() => setSelectedCampaign(c)} className="surface-card p-5 cursor-pointer hover:border-rose-300 transition-colors group">
              <div className="flex items-center justify-between">
                <div>
                  <h3 className="font-bold text-slate-900 group-hover:text-rose-700 transition-colors">{c.name}</h3>
                  <p className="text-xs text-slate-500 mt-1">First Seen: {new Date(c.first_seen).toLocaleDateString()}</p>
                </div>
                <div className="flex gap-4">
                  <div className="text-center"><div className="text-lg font-bold text-slate-800">{c.cases_count}</div><div className="text-[10px] uppercase text-slate-500 font-bold">Cases</div></div>
                  <div className="text-center"><div className="text-lg font-bold text-slate-800">{c.indicators_count}</div><div className="text-[10px] uppercase text-slate-500 font-bold">IOCs</div></div>
                  <div className="text-center"><div className="text-lg font-bold text-slate-800">{c.techniques_count}</div><div className="text-[10px] uppercase text-slate-500 font-bold">TTPs</div></div>
                  <div className="w-px bg-slate-200 mx-2"></div>
                  <div className="flex items-center">
                    <span className={`px-2 py-1 rounded text-[10px] font-bold ${c.correlation_level === 'HIGH' ? 'bg-rose-100 text-rose-700' : c.correlation_level === 'MEDIUM' ? 'bg-amber-100 text-amber-700' : 'bg-slate-100 text-slate-700'}`}>
                      {c.correlation_level}
                    </span>
                  </div>
                </div>
              </div>
            </div>
          ))}
          {campaigns.length === 0 && <p className="text-center text-slate-500 p-8">No campaigns detected yet.</p>}
        </div>
      )}
    </div>
  );
}
"""

if "CampaignManager" not in text:
    text = text.replace("export function CaseManager", campaign_view + "\\nexport function CaseManager")

with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as f:
    f.write(text)

with open('frontend/src/App.jsx', 'r', encoding='utf-8') as f:
    app_text = f.read()

# Update App.jsx navigation and views
nav_btn = """              <button
                onClick={() => setCurrentView('campaigns')}
                className={`flex items-center gap-1.5 px-3.5 py-1.5 rounded-lg text-xs font-bold transition-all ${
                  currentView === 'campaigns' ? 'bg-white text-rose-600 shadow-sm' : 'text-slate-600 hover:text-slate-900 hover:bg-white/50'
                }`}
              >
                <Activity className="w-3.5 h-3.5" /> Campaigns
              </button>
"""

if "setCurrentView('campaigns')" not in app_text:
    target = """<button
                onClick={() => setCurrentView('cases')"""
    app_text = app_text.replace(target, nav_btn + '\\n              ' + target)

view_render = """
        {currentView === 'campaigns' && (
          <CampaignManager />
        )}
"""

if "<CampaignManager" not in app_text:
    target2 = """{currentView === 'cases' && ("""
    app_text = app_text.replace(target2, view_render + '\\n        ' + target2)
    
    # Add CampaignManager to App.jsx imports from Views
    app_text = app_text.replace("CaseManager,", "CaseManager, CampaignManager,")
    
with open('frontend/src/App.jsx', 'w', encoding='utf-8') as f:
    f.write(app_text)
