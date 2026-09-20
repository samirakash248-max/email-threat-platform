import re

with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

new_ui = """      {selectedNode && (
        <div className="absolute bottom-4 right-4 z-10 bg-white border border-slate-200 rounded-xl shadow-lg p-4 w-72 text-xs">
          <div className="flex justify-between items-start mb-2">
            <h3 className="font-bold text-slate-900 truncate pr-2">{selectedNode.label}</h3>
            <button onClick={() => setSelectedNode(null)} className="text-slate-400 hover:text-slate-600"><X className="w-4 h-4"/></button>
          </div>
          <div className="space-y-1.5">
            <p><span className="font-semibold text-slate-500">Type:</span> <span className="uppercase text-blue-600 font-bold">{selectedNode.type}</span></p>
            <p className="break-all"><span className="font-semibold text-slate-500">Value:</span> {selectedNode.value}</p>
            {selectedNode.type === 'ip' && selectedNode.classification && (
              <>
                <p><span className="font-semibold text-slate-500">Classification:</span> <span className="font-mono text-purple-700 font-bold bg-purple-50 px-1 py-0.5 rounded">{selectedNode.classification}</span></p>
                {selectedNode.organization && <p><span className="font-semibold text-slate-500">Org:</span> {selectedNode.organization}</p>}
                {selectedNode.asn && <p><span className="font-semibold text-slate-500">ASN:</span> {selectedNode.asn}</p>}
                {selectedNode.country && <p><span className="font-semibold text-slate-500">Country:</span> {selectedNode.country}</p>}
                {selectedNode.is_open_relay && <p><span className="text-rose-600 font-bold bg-rose-50 px-1 py-0.5 rounded uppercase">Open Relay Risk</span></p>}
              </>
            )}
          </div>
        </div>
      )}"""

# Replace the specific block
text = re.sub(r'\{selectedNode && \([\s\S]*?</div>\s*\)\s*\}', new_ui, text)

with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as f:
    f.write(text)
