import re
from urllib.parse import urlparse, unquote
from app.models import URLRiskSignal, ExtractedURL

TARGET_BRANDS = ["microsoft", "google", "apple", "amazon", "paypal", "netflix", "facebook", "linkedin", "office365", "chase", "bankofamerica"]
SUSPICIOUS_TLDS = {".xyz", ".top", ".pw", ".cc", ".zip", ".click", ".link", ".buzz", ".cn", ".su"}
SUSPICIOUS_KEYWORDS = {"login", "verify", "secure", "account", "password", "signin", "authentication", "update", "payment", "invoice"}

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)
    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def analyze_url(extracted_url: ExtractedURL) -> ExtractedURL:
    url = extracted_url.url
    
    try:
        parsed = urlparse(url)
    except Exception:
        return extracted_url
        
    scheme = parsed.scheme.lower() if parsed.scheme else "http"
    hostname = parsed.hostname.lower() if parsed.hostname else ""
    port = parsed.port
    path = parsed.path.lower()
    query = parsed.query
    
    extracted_url.scheme = scheme
    extracted_url.hostname = hostname
    extracted_url.port = port
    extracted_url.path = path
    extracted_url.query = query
    
    signals = []
    suspicious_features = []
    score = 0
    
    def add_signal(name, desc, pts):
        nonlocal score
        signals.append(URLRiskSignal(rule_name=name, description=desc, score_contribution=pts))
        suspicious_features.append(name)
        score += pts
        
    ip_pattern = re.compile(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$')
    if ip_pattern.match(hostname):
        add_signal("IP-based URL", "Host is a raw IP address instead of a domain.", 30)
    else:
        hex_ip = re.compile(r'^0x[0-9a-f]+$', re.IGNORECASE)
        if hex_ip.match(hostname) or hostname.isdigit():
            add_signal("Obfuscated IP", "Host uses decimal or hex IP representation.", 40)
            
    if scheme == "http":
        add_signal("Insecure Scheme", "URL uses unencrypted HTTP.", 10)
        
    if hostname.count('.') >= 3 and not ip_pattern.match(hostname):
        add_signal("Excessive Subdomains", f"Hostname '{hostname}' has {hostname.count('.')} subdomains.", 15)
        
    if len(url) > 150:
        add_signal("Suspicious URL Length", f"URL length is {len(url)} characters, often used for obfuscation.", 15)
        
    if parsed.username or parsed.password or '@' in parsed.netloc:
        add_signal("Userinfo (@) Trick", "URL contains '@' in authority section to spoof the domain.", 40)
        
    if url.count('%') > 5:
        add_signal("Excessive URL Encoding", "URL uses excessive percent-encoding.", 10)
        
    if 'xn--' in hostname:
        add_signal("Punycode / IDN", "Domain uses Punycode (IDN), commonly used for homograph attacks.", 35)
        
    tld = ""
    if "." in hostname and not ip_pattern.match(hostname):
        tld = hostname[hostname.rfind("."):]
    if tld in SUSPICIOUS_TLDS:
        add_signal("Suspicious TLD", f"The TLD '{tld}' is frequently associated with malicious activity.", 15)
        
    if not ip_pattern.match(hostname) and 'xn--' not in hostname:
        clean_host = hostname.replace(tld, "")
        for brand in TARGET_BRANDS:
            if brand in clean_host and clean_host != brand:
                add_signal("Brand Impersonation", f"Domain contains targeted brand name '{brand}'.", 25)
                break
            if abs(len(clean_host) - len(brand)) <= 2:
                dist = levenshtein_distance(clean_host, brand)
                if dist == 1 and clean_host != brand:
                    add_signal("Brand Typosquatting", f"Domain is 1 character away from '{brand}'.", 30)
                    break
                    
    if path:
        path_lower = path.lower()
        found_kw = [kw for kw in SUSPICIOUS_KEYWORDS if kw in path_lower]
        if found_kw:
            add_signal("Suspicious Path Keywords", f"Found high-risk keywords: {', '.join(found_kw)}.", 15)
            
    redirect_params = ["url=", "redirect=", "next=", "out=", "goto=", "returnurl="]
    if query:
        query_lower = query.lower()
        found_redir = [rp for rp in redirect_params if rp in query_lower]
        if found_redir:
            add_signal("Open Redirect Indicator", "URL contains parameters commonly used for open redirects.", 15)
            
    try:
        normalized = unquote(url)
    except:
        normalized = url
        
    extracted_url.normalized_url = normalized
    extracted_url.risk_score = min(score, 100)
    
    if extracted_url.risk_score >= 70:
        extracted_url.risk_level = "CRITICAL"
    elif extracted_url.risk_score >= 40:
        extracted_url.risk_level = "HIGH"
    elif extracted_url.risk_score >= 15:
        extracted_url.risk_level = "MEDIUM"
    else:
        extracted_url.risk_level = "LOW"
        
    extracted_url.suspicious_features = suspicious_features
    extracted_url.triggered_rules = signals
    
    return extracted_url
