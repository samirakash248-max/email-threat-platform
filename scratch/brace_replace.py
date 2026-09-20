import os

with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

start_idx = text.find('export function CaseManager')

brace_count = 0
in_case_manager = False
end_idx = -1

for i in range(start_idx, len(text)):
    if text[i] == '{':
        brace_count += 1
        in_case_manager = True
    elif text[i] == '}':
        brace_count -= 1
        if in_case_manager and brace_count == 0:
            end_idx = i + 1
            break

with open('scratch/apply_soc_workflow.py', 'r', encoding='utf-8') as f:
    script_text = f.read()

soc_idx1 = script_text.find('soc_case_manager = """') + len('soc_case_manager = """')
soc_idx2 = script_text.rfind('"""')
soc_manager = script_text[soc_idx1:soc_idx2].strip() + '\n\n'

new_text = text[:start_idx] + soc_manager + text[end_idx:]

if 'import { Download' not in new_text:
    new_text = new_text.replace('import {', 'import { Download, UserPlus, Share2,', 1)
    
with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as fw:
    fw.write(new_text)
