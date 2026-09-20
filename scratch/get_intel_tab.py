import re
with open('frontend/src/components/AnalysisWorkspace.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

# find everything between activeTab === 'intel' and activeTab === 'attachments'
idx_intel = text.find("activeTab === 'intel'")
idx_attach = text.find("activeTab === 'attachments'")
if idx_intel != -1 and idx_attach != -1:
    print(text[idx_intel:idx_attach])
