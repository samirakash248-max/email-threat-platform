import os

with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

metric = """
        <div className="surface-card p-4">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-purple-50 rounded-lg text-purple-600"><Activity className="w-5 h-5"/></div>
            <h3 className="text-xs font-bold text-slate-600 uppercase tracking-wider">Active Campaigns</h3>
          </div>
          <div className="text-3xl font-black text-slate-900">{stats.active_campaigns || 0}</div>
        </div>
"""

if "Active Campaigns" not in text:
    target = """<div className="surface-card p-4">
          <div className="flex items-center gap-3 mb-2">
            <div className="p-2 bg-blue-50 rounded-lg text-blue-600"><Briefcase className="w-5 h-5"/></div>"""
    
    text = text.replace(target, metric + "\\n        " + target)
    
    with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as f:
        f.write(text)
