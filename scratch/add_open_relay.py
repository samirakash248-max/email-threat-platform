import re

with open('backend/app/scanner.py', 'r') as f:
    text = f.read()

# Replace the IP intel extraction logic to add passive open relay check
old_intel = """    for ip in extracted_ips:
        intel = get_ip_intelligence(ip)
        ip_intel_dict[ip] = intel.model_dump()"""

new_intel = """    for ip in extracted_ips:
        intel = get_ip_intelligence(ip)
        
        # Passive Open Relay Check:
        # If this IP is an external relay that received mail from another external IP
        # without authentication, it exhibits open relay risk.
        # We passively infer this by looking at RelayHops.
        for r in relays:
            if r.ip_address == ip and not r.is_private_ip:
                # If there are multiple hops and it lacks auth indicators in the raw header
                # We can do a rudimentary heuristic:
                raw = metadata.get("all_headers", "").lower()
                if "with esmtp id" in raw and "auth=" not in raw and "esmtpsa" not in raw:
                    intel.is_open_relay = True
                    break

        ip_intel_dict[ip] = intel.model_dump()"""

text = text.replace(old_intel, new_intel)

with open('backend/app/scanner.py', 'w') as f:
    f.write(text)
