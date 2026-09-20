import re
with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

soc_case_manager = """export function CaseManager({ currentAnalysis, onSelectAnalysisFromCase }) {
  const [cases, setCases] = useState([]);
  const [selectedCaseId, setSelectedCaseId] = useState(null);
  const [activeCaseData, setActiveCaseData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [showCreateModal, setShowCreateModal] = useState(false);
  const [filterStatus, setFilterStatus] = useState('ALL');
  
  const [activeTab, setActiveTab] = useState('overview'); // overview, graph, campaign, timeline
  const [newTitle, setNewTitle] = useState('');
  const [newDescription, setNewDescription] = useState('');
  const [newPriority, setNewPriority] = useState('HIGH');
  const [newNoteContent, setNewNoteContent] = useState('');
  const [analystName, setAnalystName] = useState('SOC-Analyst');
  const [updateFeedback, setUpdateFeedback] = useState(null);

  const fetchCases = async () => {
    try {
      const data = await api.getCases();
      setCases(data);
      if (data.length > 0 && !selectedCaseId) {
        setSelectedCaseId(data[0].id);
      }
    } catch (err) {
      console.error("Error fetching cases:", err);
    }
  };

  useEffect(() => { fetchCases(); }, []);

  useEffect(() => {
    if (!selectedCaseId) return;
    setLoading(true);
    api.getCase(selectedCaseId)
      .then(data => setActiveCaseData(data))
      .catch(err => console.error("Error loading case:", err))
      .finally(() => setLoading(false));
  }, [selectedCaseId]);

  const handleCreateCase = async (e) => {
    e.preventDefault();
    if (!newTitle.trim()) return;
    try {
      const created = await api.createCase({
        title: newTitle, description: newDescription, priority: newPriority,
        initial_analysis_id: currentAnalysis?.analysis_id || null,
      });
      setNewTitle(''); setNewDescription(''); setShowCreateModal(false);
      await fetchCases(); setSelectedCaseId(created.id);
    } catch (err) { console.error("Error creating case:", err); }
  };

  const handleAddNote = async (e) => {
    e.preventDefault();
    if (!newNoteContent.trim() || !selectedCaseId) return;
    try {
      const updated = await api.addNote(selectedCaseId, { author: analystName, content: newNoteContent });
      setActiveCaseData(updated); setNewNoteContent(''); fetchCases();
    } catch (err) { console.error("Error adding note:", err); }
  };

  const handleUpdateStatus = async (statusVal) => {
    if (!selectedCaseId) return;
    try {
      const updated = await api.patchCase(selectedCaseId, { status: statusVal, actor: analystName });
      setActiveCaseData(updated);
      setUpdateFeedback(`Status changed to ${statusVal}`);
      setTimeout(() => setUpdateFeedback(null), 3000);
      fetchCases();
    } catch (err) {
      alert("Invalid transition: " + err.message);
    }
  };

  const handleAssign = async () => {
    if (!selectedCaseId) return;
    const assignee = prompt("Enter Analyst Name:", analystName);
    if (!assignee) return;
    try {
      const updated = await api.patchCase(selectedCaseId, { assigned_analyst: assignee, actor: analystName });
      setActiveCaseData(updated);
      setUpdateFeedback(`Assigned to ${assignee}`);
      setTimeout(() => setUpdateFeedback(null), 3000);
      fetchCases();
    } catch (err) { console.error("Assignment error:", err); }
  };

  const handleExport = async () => {
    if (!selectedCaseId) return;
    try {
      const data = await api.exportCase(selectedCaseId);
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `Case_Export_${selectedCaseId}.json`;
      a.click();
    } catch (err) { console.error("Export error:", err); }
  };

  const getStatusBadge = (status) => {
    switch (status?.toUpperCase()) {
      case 'NEW': return 'bg-emerald-50 text-emerald-700 border-emerald-200';
      case 'TRIAGED': return 'bg-blue-50 text-blue-700 border-blue-200';
      case 'INVESTIGATING': return 'bg-amber-50 text-amber-700 border-amber-200';
      case 'CONTAINMENT_RECOMMENDED': return 'bg-orange-50 text-orange-700 border-orange-200';
      case 'RESOLVED': return 'bg-indigo-50 text-indigo-700 border-indigo-200';
      case 'CLOSED': return 'bg-slate-100 text-slate-600 border-slate-300';
      default: return 'bg-purple-50 text-purple-700 border-purple-200';
    }
  };

  const filteredCases = cases.filter(c => filterStatus === 'ALL' || c.status === filterStatus);
  const currentStatus = activeCaseData?.status || 'NEW';
  
  const validTransitions = {
    "OPEN": ["NEW", "TRIAGED", "INVESTIGATING", "CLOSED"],
    "NEW": ["TRIAGED", "CLOSED"],
    "TRIAGED": ["INVESTIGATING", "CLOSED"],
    "INVESTIGATING": ["CONTAINMENT_RECOMMENDED", "RESOLVED", "CLOSED"],
    "CONTAINMENT_RECOMMENDED": ["RESOLVED", "CLOSED"],
    "RESOLVED": ["CLOSED", "INVESTIGATING"],
    "CLOSED": ["INVESTIGATING"]
  };
  const availableOptions = validTransitions[currentStatus] || [];

  return (
    <div className="surface-card p-6 space-y-6">
      <div className="flex justify-between border-b border-[#E2E8F0] pb-4">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-blue-50 rounded-xl text-blue-600"><Briefcase className="w-5 h-5" /></div>
          <div><h3 className="font-bold text-slate-900">SOC Case Management</h3></div>
        </div>
        <button onClick={() => setShowCreateModal(true)} className="btn-block-primary text-white px-4 py-2 rounded-xl text-xs font-bold shadow"><Plus className="w-4 h-4 inline-block mr-1"/> New Case</button>
      </div>

      {showCreateModal && (
        <div className="fixed inset-0 bg-black/80 z-50 flex items-center justify-center p-4">
          <div className="surface-card p-6 w-full max-w-md">
            <h4 className="font-bold mb-4 text-sm">New SOC Investigation</h4>
            <form onSubmit={handleCreateCase} className="space-y-3 text-xs">
              <input required value={newTitle} onChange={e=>setNewTitle(e.target.value)} placeholder="Case Title" className="w-full p-2 border rounded"/>
              <textarea value={newDescription} onChange={e=>setNewDescription(e.target.value)} placeholder="Description" className="w-full p-2 border rounded"/>
              <select value={newPriority} onChange={e=>setNewPriority(e.target.value)} className="w-full p-2 border rounded">
                <option value="CRITICAL">CRITICAL</option><option value="HIGH">HIGH</option><option value="MEDIUM">MEDIUM</option>
              </select>
              <div className="flex justify-end gap-2 mt-4">
                <button type="button" onClick={()=>setShowCreateModal(false)} className="px-4 py-2 bg-slate-100 rounded">Cancel</button>
                <button type="submit" className="px-4 py-2 bg-blue-600 text-white rounded font-bold">Create</button>
              </div>
            </form>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        <div className="space-y-3 lg:col-span-1 border-r border-[#E2E8F0] pr-4">
          <select value={filterStatus} onChange={(e) => setFilterStatus(e.target.value)} className="w-full bg-slate-50 border border-slate-200 rounded p-1.5 text-xs">
            <option value="ALL">All Statuses</option>
            <option value="NEW">NEW</option>
            <option value="TRIAGED">TRIAGED</option>
            <option value="INVESTIGATING">INVESTIGATING</option>
            <option value="CONTAINMENT_RECOMMENDED">CONTAINMENT_RECOMMENDED</option>
            <option value="RESOLVED">RESOLVED</option>
            <option value="CLOSED">CLOSED</option>
          </select>
          <div className="h-[500px] overflow-y-auto space-y-2 pr-1">
            {filteredCases.map(c => (
              <div key={c.id} onClick={() => setSelectedCaseId(c.id)} className={`p-3 rounded-lg border cursor-pointer ${selectedCaseId === c.id ? 'bg-blue-50 border-blue-400 shadow-sm' : 'hover:bg-slate-50 border-slate-200'}`}>
                <div className="font-bold text-xs text-slate-900 truncate mb-1">{c.title}</div>
                <div className="flex justify-between items-center text-[10px]">
                  <span className={`px-1.5 py-0.5 rounded border font-bold uppercase ${getStatusBadge(c.status)}`}>{c.status}</span>
                  <span className="text-slate-500 font-mono">{c.id.split('-').slice(0,2).join('-')}</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        <div className="lg:col-span-3 space-y-4">
          {activeCaseData ? (
            <>
              {updateFeedback && <div className="bg-emerald-50 border border-emerald-200 p-2 rounded text-xs text-emerald-700 flex items-center gap-2"><CheckCircle2 className="w-4 h-4"/>{updateFeedback}</div>}
              <div className="flex justify-between items-start">
                <div>
                  <h2 className="text-lg font-bold text-slate-900">{activeCaseData.title}</h2>
                  <p className="text-xs text-slate-500 font-mono mt-1">ID: {activeCaseData.id}</p>
                </div>
                <div className="flex items-center gap-2">
                  <div className="text-xs mr-2"><span className="text-slate-500">Assignee:</span> <span className="font-bold text-slate-800">{activeCaseData.assigned_analyst || 'Unassigned'}</span></div>
                  <button onClick={handleAssign} className="p-1.5 text-slate-500 hover:text-blue-600 hover:bg-blue-50 rounded" title="Assign Analyst"><UserPlus className="w-4 h-4"/></button>
                  <button onClick={handleExport} className="p-1.5 text-slate-500 hover:text-emerald-600 hover:bg-emerald-50 rounded" title="Export Evidence Report"><Download className="w-4 h-4"/></button>
                </div>
              </div>

              <div className="flex items-center gap-2 bg-slate-50 p-2 rounded-lg border border-slate-200">
                <span className="text-xs font-bold text-slate-600 mr-2">Status Actions:</span>
                <span className={`px-2 py-1 text-xs font-bold uppercase rounded border ${getStatusBadge(activeCaseData.status)}`}>{activeCaseData.status}</span>
                <span className="text-slate-400 mx-1">→</span>
                <div className="flex gap-2 flex-wrap">
                  {availableOptions.map(opt => (
                    <button key={opt} onClick={() => handleUpdateStatus(opt)} className="px-3 py-1 bg-white border border-slate-300 rounded text-[10px] font-bold text-slate-700 hover:bg-slate-100 uppercase">{opt}</button>
                  ))}
                  {availableOptions.length === 0 && <span className="text-xs text-slate-500 italic">Terminal State</span>}
                </div>
              </div>

              <div className="flex gap-1 border-b border-slate-200">
                {['overview', 'graph', 'timeline'].map(t => (
                  <button key={t} onClick={() => setActiveTab(t)} className={`px-4 py-2 text-xs font-bold uppercase ${activeTab === t ? 'border-b-2 border-blue-600 text-blue-700' : 'text-slate-500 hover:text-slate-800'}`}>
                    {t}
                  </button>
                ))}
              </div>

              <div className="pt-2 min-h-[400px]">
                {activeTab === 'overview' && (
                  <div className="space-y-4">
                    <div className="surface-card p-4"><h4 className="font-bold text-slate-800 mb-2">Description</h4><p className="text-xs text-slate-700">{activeCaseData.description || 'No description provided.'}</p></div>
                    <div className="surface-card p-4">
                      <h4 className="font-bold text-slate-800 mb-2">Attached Forensics ({activeCaseData.attached_analyses?.length || 0})</h4>
                      <div className="space-y-2">
                        {(activeCaseData.attached_analyses || []).map((a) => (
                          <div key={a.analysis_id} className="p-3 border border-slate-200 rounded flex justify-between text-xs">
                            <span className="font-bold text-slate-800">{a.metadata?.subject || a.analysis_id}</span>
                            <button onClick={() => onSelectAnalysisFromCase(a.analysis_id)} className="text-blue-600 hover:underline">View</button>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
                {activeTab === 'graph' && (
                  <div className="border border-slate-200 rounded-lg overflow-hidden relative">
                    <ThreatGraphView caseId={activeCaseData.id} onBack={() => setActiveTab('overview')} />
                  </div>
                )}
                {activeTab === 'timeline' && (
                  <div className="grid grid-cols-1 gap-4">
                    <div className="space-y-3">
                      <h4 className="font-bold text-slate-800 flex items-center gap-2"><Clock className="w-4 h-4"/> Analyst Notes & Audit Timeline</h4>
                      <form onSubmit={handleAddNote} className="space-y-2 mb-4">
                        <textarea required rows={2} value={newNoteContent} onChange={(e)=>setNewNoteContent(e.target.value)} placeholder="Append immutable investigation note..." className="w-full text-xs p-2 border rounded focus:border-blue-500 outline-none"/>
                        <button type="submit" className="px-3 py-1 bg-slate-800 text-white text-xs rounded hover:bg-slate-700">Add Note</button>
                      </form>
                      <div className="space-y-2 max-h-[300px] overflow-y-auto">
                        {[...(activeCaseData.notes || [])].reverse().map((n, i) => (
                          <div key={i} className="p-3 bg-blue-50/50 border border-blue-100 rounded text-xs space-y-1">
                            <div className="flex justify-between text-slate-500 font-mono text-[10px]"><span>{n.author}</span><span>{new Date(n.created_at).toLocaleString()}</span></div>
                            <p className="text-slate-800">{n.content}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </>
          ) : (
            <div className="flex h-full items-center justify-center text-slate-400 text-sm">Select an incident to view details</div>
          )}
        </div>
      </div>
    </div>
  );
}
"""

start_idx = text.find("export function CaseManager")
# Need to find the end of CaseManager accurately. It ends where CampaignManager begins.
end_idx = text.find("export function CampaignManager")

new_text = text[:start_idx] + soc_case_manager + "\\n\\n" + text[end_idx:]

if "import { Download" not in new_text:
    new_text = new_text.replace("import {", "import { Download, UserPlus, Clock, Share2,", 1)

with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as f:
    f.write(new_text)

print('Injected successfully!')
