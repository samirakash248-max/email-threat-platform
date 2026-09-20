import os
import re

with open('frontend/src/App.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

# Add AnalyticsView to imports
if "AnalyticsView" not in text:
    text = text.replace("SampleEmailSelector", "SampleEmailSelector,\n  AnalyticsView")

# Add Analytics to navigation
nav_item = """
            <button 
              onClick={() => setCurrentView('analytics')}
              className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm font-medium transition-colors ${currentView === 'analytics' ? 'bg-blue-50 text-blue-700' : 'text-slate-600 hover:bg-slate-50 hover:text-slate-900'}`}
            >
              <Activity className="w-5 h-5" /> Analytics
            </button>
"""

# Find where to insert it in the nav menu (after cases or somewhere)
if "setCurrentView('analytics')" not in text:
    nav_anchor = "<button \n              onClick={() => setCurrentView('cases')}"
    if nav_anchor in text:
        text = text.replace(nav_anchor, nav_item.strip() + '\n            ' + nav_anchor)
    else:
        # Fallback anchor
        nav_anchor = "onClick={() => setCurrentView('cases')}"
        idx = text.find(nav_anchor)
        # backtrack to `<button`
        btn_idx = text.rfind('<button', 0, idx)
        text = text[:btn_idx] + nav_item.strip() + '\n            ' + text[btn_idx:]

# Add Analytics view case in main render area
render_case = """
        {currentView === 'analytics' && (
          <AnalyticsView />
        )}
"""
if "currentView === 'analytics'" not in text:
    render_anchor = "{currentView === 'cases' &&"
    if render_anchor in text:
        text = text.replace(render_anchor, render_case.strip() + '\n        ' + render_anchor)
    else:
        # Fallback anchor
        render_anchor = "{currentView === 'dashboard' &&"
        text = text.replace(render_anchor, render_case.strip() + '\n        ' + render_anchor)

with open('frontend/src/App.jsx', 'w', encoding='utf-8') as f:
    f.write(text)
