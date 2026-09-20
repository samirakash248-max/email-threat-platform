with open('README.md', 'r') as f:
    text = f.read()

limitations_addition = """
- **Infrastructure Intelligence**: IP intelligence establishes *observed infrastructure* (e.g., Tor exit nodes, VPNs, cloud providers). It does not, and cannot, establish the physical location or true identity of the attacker.
- **Geolocation**: Any geographic location derived from IPs reflects the datacenter or ISP location, not the sender.
- **Offline Fallback**: The IP intelligence component works offline via local deterministic lists (for major clouds and Tor). A live external provider is optional and configurable via `USE_LIVE_IP_API=true`.
"""

if '## ?? Known Limitations' in text:
    text = text.replace('## ?? Known Limitations', '## ?? Known Limitations\n' + limitations_addition)

with open('README.md', 'w') as f:
    f.write(text)
