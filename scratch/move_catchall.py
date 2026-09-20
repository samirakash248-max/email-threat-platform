import os

with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

start = text.find('# Static Files & SPA')
end_str = 'return FileResponse(os.path.join(DIST_DIR, "index.html"))'
end = text.find(end_str) + len(end_str)

static_block = text[start:end]

text = text[:start] + text[end:]

main_idx = text.find('if __name__ == "__main__":')
text = text[:main_idx] + static_block + '\n\n' + text[main_idx:]

with open('backend/app/main.py', 'w', encoding='utf-8') as f:
    f.write(text)
