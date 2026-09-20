import os

with open('backend/app/models.py', 'r', encoding='utf-8') as f:
    text = f.read()

# Change default status and add assigned_analyst
old_case = '''    status = Column(String, default="OPEN", index=True)
    priority = Column(String, default="HIGH", index=True)'''
    
new_case = '''    status = Column(String, default="NEW", index=True)
    priority = Column(String, default="HIGH", index=True)
    assigned_analyst = Column(String, nullable=True)'''

if "assigned_analyst = Column" not in text:
    text = text.replace(old_case, new_case)
    with open('backend/app/models.py', 'w', encoding='utf-8') as f:
        f.write(text)
