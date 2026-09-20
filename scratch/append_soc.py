import os

with open('scratch/apply_soc_workflow.py', 'r', encoding='utf-8') as f:
    text = f.read()

start = text.find('soc_case_manager = """') + len('soc_case_manager = """')
end = text.rfind('"""')
soc_manager = text[start:end]

with open('frontend/src/components/Views.jsx', 'a', encoding='utf-8') as f:
    f.write('\\n\\n' + soc_manager + '\\n')
    
with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    vtext = f.read()
    
if 'import { Download' not in vtext:
    vtext = vtext.replace('import {', 'import { Download, UserPlus, Share2,', 1)
    with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as f:
        f.write(vtext)
