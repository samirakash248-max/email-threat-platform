import os

with open('scratch/apply_soc_workflow.py', 'r', encoding='utf-8') as f:
    text = f.read()

start = text.find('soc_case_manager = """') + len('soc_case_manager = """')
end = text.rfind('"""')
soc_manager = text[start:end]

with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    vtext = f.read()

s1 = vtext.find('export function CaseManager')
s2 = vtext.find('export function CampaignManager')

new_text = vtext[:s1] + soc_manager + '\\n\\n' + vtext[s2:]

if 'import { Download' not in new_text:
    new_text = new_text.replace('import {', 'import { Download, UserPlus, Share2,', 1)

with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as f:
    f.write(new_text)
