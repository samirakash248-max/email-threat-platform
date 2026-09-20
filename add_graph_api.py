import os

with open('backend/app/main.py', 'r', encoding='utf-8') as f:
    text = f.read()

graph_api = """
from app.graph_builder import build_graph_for_email, build_graph_for_case
from collections import deque

@app.get("/api/graph/cases/{case_id}")
def get_case_graph(case_id: str, depth: int = 2, limit: int = 150, db: Session = Depends(get_db)):
    # 1. Sync case graph edges
    case = db.query(CaseRecord).filter_by(id=case_id).first()
    if not case: return {"nodes": [], "edges": []}
    
    build_graph_for_case(case, db)
    for aid in (case.attached_analysis_ids or []):
        email = db.query(EmailRecord).filter_by(id=aid).first()
        if email: build_graph_for_email(email, db)
        
    nodes = {}
    edges = []
    
    def add_node(n_type, n_id, label=None):
        if not label: label = n_id
        n_key = f"{n_type}:{n_id}"
        if n_key not in nodes:
            nodes[n_key] = {"id": n_key, "type": n_type, "label": label, "value": n_id}
            
    # BFS
    queue = deque([("case", case_id)])
    visited = set()
    edge_seen = set()
    
    while queue and len(nodes) < limit:
        curr_type, curr_id = queue.popleft()
        node_key = f"{curr_type}:{curr_id}"
        if node_key in visited: continue
        visited.add(node_key)
        
        # Add the node itself
        label = curr_id
        if curr_type == "case" and curr_id == case.id: label = case.title
        elif curr_type == "case": 
            c = db.query(CaseRecord).filter_by(id=curr_id).first()
            if c: label = c.title
        elif curr_type == "email":
            e = db.query(EmailRecord).filter_by(id=curr_id).first()
            if e: label = e.subject or "Email"
        add_node(curr_type, curr_id, label)
        
        if len(nodes) >= limit: break
            
        # Get edges where this is source
        out_edges = db.query(GraphEdgeRecord).filter_by(source_type=curr_type, source_id=curr_id).all()
        # Get edges where this is target
        in_edges = db.query(GraphEdgeRecord).filter_by(target_type=curr_type, target_id=curr_id).all()
        
        for e in out_edges:
            ekey = f"{e.source_type}:{e.source_id}->{e.target_type}:{e.target_id}:{e.relation}"
            if ekey not in edge_seen:
                edge_seen.add(ekey)
                edges.append({"source": f"{e.source_type}:{e.source_id}", "target": f"{e.target_type}:{e.target_id}", "relation": e.relation})
                queue.append((e.target_type, e.target_id))
                
        for e in in_edges:
            ekey = f"{e.source_type}:{e.source_id}->{e.target_type}:{e.target_id}:{e.relation}"
            if ekey not in edge_seen:
                edge_seen.add(ekey)
                edges.append({"source": f"{e.source_type}:{e.source_id}", "target": f"{e.target_type}:{e.target_id}", "relation": e.relation})
                queue.append((e.source_type, e.source_id))

    return {"nodes": list(nodes.values()), "edges": edges}
"""

if "get_case_graph" not in text:
    target = 'if __name__ == "__main__":'
    text = text.replace(target, graph_api + "\\n" + target)
    with open('backend/app/main.py', 'w', encoding='utf-8') as f:
        f.write(text)
