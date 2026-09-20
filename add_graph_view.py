import os

with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

# 1. Add import for ForceGraph2D
if "ForceGraph2D" not in text:
    text = text.replace("import React, { useState, useEffect } from 'react';", "import React, { useState, useEffect, useRef, useCallback } from 'react';\\nimport ForceGraph2D from 'react-force-graph-2d';")

# 2. Add Graph View Component
graph_component = """
export function ThreatGraphView({ caseId, onBack }) {
  const [graphData, setGraphData] = useState({ nodes: [], edges: [] });
  const [loading, setLoading] = useState(true);
  const [selectedNode, setSelectedNode] = useState(null);
  
  const fgRef = useRef();

  useEffect(() => {
    if (!caseId) return;
    setLoading(true);
    api.getCaseGraph(caseId)
      .then(data => {
        // Transform for ForceGraph: id must be unique, source/target on edges
        const gData = {
          nodes: data.nodes.map(n => ({ ...n, val: n.type === 'case' ? 25 : n.type === 'email' ? 15 : 10 })),
          links: data.edges.map(e => ({ source: e.source, target: e.target, relation: e.relation }))
        };
        setGraphData(gData);
      })
      .catch(console.error)
      .finally(() => setLoading(false));
  }, [caseId]);

  const handleNodeClick = useCallback(node => {
    setSelectedNode(node);
    // Center/zoom on node
    fgRef.current.centerAt(node.x, node.y, 1000);
    fgRef.current.zoom(8, 2000);
  }, [fgRef]);

  const getNodeColor = (type) => {
    switch (type) {
      case 'case': return '#3B82F6';
      case 'email': return '#10B981';
      case 'ip': return '#EF4444';
      case 'domain': return '#F59E0B';
      case 'url': return '#EC4899';
      case 'hash': return '#8B5CF6';
      case 'technique': return '#6366F1';
      default: return '#94A3B8';
    }
  };

  return (
    <div className="surface-card flex flex-col h-[600px] relative overflow-hidden">
      <div className="absolute top-4 left-4 z-10 flex gap-2">
        <button onClick={onBack} className="bg-white px-3 py-1.5 border border-slate-200 rounded-lg shadow text-xs font-bold text-slate-700 hover:bg-slate-50 cursor-pointer flex items-center gap-1">
           <ArrowLeft className="w-4 h-4" /> Back to Case
        </button>
      </div>
      
      {loading ? (
        <div className="flex-1 flex items-center justify-center"><Loader2 className="w-8 h-8 text-blue-500 animate-spin" /></div>
      ) : (
        <ForceGraph2D
          ref={fgRef}
          graphData={graphData}
          nodeLabel="label"
          nodeColor={n => getNodeColor(n.type)}
          onNodeClick={handleNodeClick}
          linkDirectionalArrowLength={3.5}
          linkDirectionalArrowRelPos={1}
          linkColor={() => '#CBD5E1'}
          width={800}
          height={600}
        />
      )}
      
      {selectedNode && (
        <div className="absolute bottom-4 right-4 z-10 bg-white border border-slate-200 rounded-xl shadow-lg p-4 w-72 text-xs">
          <div className="flex justify-between items-start mb-2">
            <h3 className="font-bold text-slate-900 truncate pr-2">{selectedNode.label}</h3>
            <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-slate-600"><X className="w-4 h-4"/></button>
          </div>
          <div className="space-y-1.5">
            <p><span className="font-semibold text-slate-500">Type:</span> <span className="uppercase text-blue-600 font-bold">{selectedNode.type}</span></p>
            <p className="break-all"><span className="font-semibold text-slate-500">Value:</span> {selectedNode.value}</p>
          </div>
        </div>
      )}
    </div>
  );
}
"""

if "ThreatGraphView" not in text:
    text = text.replace("export function CorrelationView", graph_component + "\\nexport function CorrelationView")

# 3. Add Graph Button to Case View
btn_str = """
            <button 
              onClick={() => setShowGraph(true)}
              className="px-3 py-1.5 bg-purple-50 text-purple-700 font-bold text-xs border border-purple-200 rounded flex items-center gap-1 hover:bg-purple-100 transition-colors"
            >
              <Network className="w-4 h-4"/> Investigate Relationships
            </button>
          </div>
"""

if "setShowGraph" not in text:
    text = text.replace("const [showCreateModal, setShowCreateModal] = useState(false);", "const [showCreateModal, setShowCreateModal] = useState(false);\\n  const [showGraph, setShowGraph] = useState(false);")
    
    # insert button in CaseManager details header
    target = '''</div>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">'''
    text = text.replace(target, btn_str + '\\n' + target.split('</div>')[1])
    
    # wrap case return with showGraph check
    case_return = '''if (!activeCaseData) {'''
    graph_render = '''if (showGraph && activeCaseData) {
    return <ThreatGraphView caseId={activeCaseData.id} onBack={() => setShowGraph(false)} />;
  }
  
  if (!activeCaseData) {'''
    text = text.replace(case_return, graph_render)
    
with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as f:
    f.write(text)