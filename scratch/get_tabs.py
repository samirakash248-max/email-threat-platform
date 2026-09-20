import re
with open('frontend/src/components/AnalysisWorkspace.jsx', 'r', encoding='utf-8') as f:
    text = f.read()
tabs = re.findall(r'<TabsContent value="([^"]+)"', text)
print("Tabs:", tabs)
