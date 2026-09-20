with open('backend/app/main.py', 'r') as f:
    text = f.read()

text = text.replace('add_node(curr_type, curr_id, label)\n        elif curr_type == "ip":', 'add_node(curr_type, curr_id, label)\n        if curr_type == "ip":')

with open('backend/app/main.py', 'w') as f:
    f.write(text)
