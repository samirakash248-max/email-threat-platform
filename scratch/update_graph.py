import re

with open('backend/app/main.py', 'r') as f:
    text = f.read()

graph_update = """
        elif curr_type == "ip":
            try:
                intel = get_ip_intelligence(curr_id)
                nodes[node_key]["asn"] = intel.asn
                nodes[node_key]["organization"] = intel.organization
                nodes[node_key]["country"] = intel.country
                nodes[node_key]["classification"] = intel.classification
                nodes[node_key]["is_tor"] = intel.is_tor
                nodes[node_key]["is_vpn_proxy"] = intel.is_vpn_proxy
                nodes[node_key]["is_cloud"] = intel.is_cloud
            except Exception:
                pass
"""

text = re.sub(r'(elif curr_type == "email":.*?add_node\(curr_type, curr_id, label\))', r'\1' + graph_update, text, flags=re.DOTALL)

with open('backend/app/main.py', 'w') as f:
    f.write(text)
