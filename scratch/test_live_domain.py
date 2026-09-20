import os
import json
os.environ["USE_LIVE_DNS_API"] = "true"
os.environ["USE_LIVE_WHOIS_API"] = "true"

from app.domain_intelligence import get_domain_intelligence

intel = get_domain_intelligence("example.com")
print(json.dumps(intel.model_dump(), indent=2))
