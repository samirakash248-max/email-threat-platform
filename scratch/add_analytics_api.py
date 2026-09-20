import os

with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

analytics_endpoints = """
from app.analytics import run_detection_evaluation

@app.get("/api/analytics/detection")
def get_detection_analytics():
    return run_detection_evaluation()

@app.get("/api/analytics/detection/rules")
def get_detection_rules_analytics():
    data = run_detection_evaluation()
    if "error" in data:
        return data
    return data.get("rule_performance", [])

@app.get("/api/analytics/detection/categories")
def get_detection_category_analytics():
    data = run_detection_evaluation()
    if "error" in data:
        return data
    return data.get("category_performance", {})
"""

# Insert before if __name__ == '__main__':
main_idx = text.find('if __name__ == "__main__":')
text = text[:main_idx] + analytics_endpoints + '\n\n' + text[main_idx:]

with open('backend/app/main.py', 'w', encoding='utf-8') as f:
    f.write(text)
