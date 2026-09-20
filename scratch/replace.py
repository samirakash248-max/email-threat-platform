import os

with open('frontend/src/components/Views.jsx', 'r', encoding='utf-8') as f:
    text = f.read()

start = text.find('export function CaseManager')
end = text.find('export function CampaignManager')

with open('scratch/apply_soc_workflow.py', 'r', encoding='utf-8') as f:
    script_text = f.read()

target = 'soc_case_manager = """\\n'
idx1 = script_text.find(target) + len(target)
idx2 = script_text.find('"""', idx1)

soc_case_manager = script_text[idx1:idx2]

if start != -1 and end != -1:
    new_text = text[:start] + soc_case_manager + "\\n" + text[end:]
    with open('frontend/src/components/Views.jsx', 'w', encoding='utf-8') as f:
        f.write(new_text)
    print("Replaced successfully.")
else:
    print("Failed boundaries.")
