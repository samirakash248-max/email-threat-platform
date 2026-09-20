with open('README.md', 'r') as f:
    text = f.read()

limitations_addition = """
- **Domain Intelligence**: Domain WHOIS/RDAP and DNS heuristics highlight infrastructure configuration (e.g. shared MX, privacy protection) and cannot attribute actual ownership to a specific human actor. PII from WHOIS is intentionally minimized.
- **Offline Fallback for DNS/RDAP**: Domain intelligence relies on local mocked data sets when `USE_LIVE_DNS_API=true` and `USE_LIVE_WHOIS_API=true` are not enabled, allowing the application to function entirely offline without external resolution delays or third-party dependencies.
"""

if '## ?? Known Limitations' in text:
    text = text.replace('## ?? Known Limitations', '## ?? Known Limitations\n' + limitations_addition)

with open('README.md', 'w') as f:
    f.write(text)
