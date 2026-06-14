import os
import re
import socket
import ssl
import base64
from urllib.parse import urlparse
from datetime import datetime
import requests
import whois
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")
GOOGLE_SAFE_BROWSING_API_KEY = os.getenv("GOOGLE_SAFE_BROWSING_API_KEY")

KNOWN_SAFE_DOMAINS = {
    'google.com', 'facebook.com', 'twitter.com', 'instagram.com', 'linkedin.com',
    'wikipedia.org', 'amazon.com', 'apple.com', 'microsoft.com', 'netflix.com',
    'paypal.com', 'leetcode.com', 'chatgpt.com', 'openai.com', 'github.com',
    'stackoverflow.com', 'reddit.com', 'youtube.com', 'twitch.tv', 'spotify.com',
    'zoom.us', 'slack.com', 'dropbox.com', 'notion.so', 'figma.com'
}

def extract_domain(url):
    """Extract clean domain name from URL."""
    try:
        # Add scheme if missing so urlparse works properly
        if not re.match(r'^https?://', url, re.IGNORECASE):
            url_parsed = urlparse('http://' + url)
        else:
            url_parsed = urlparse(url)
        
        domain = url_parsed.netloc.lower()
        if domain.startswith('www.'):
            domain = domain[4:]
        # Remove port if present
        domain = domain.split(':')[0]
        return domain
    except Exception:
        return ""

def is_whitelisted(domain):
    """Check if domain or parent domain is whitelisted."""
    if not domain:
        return False
    if domain in KNOWN_SAFE_DOMAINS:
        return True
    # Check if it's a subdomain of a whitelisted domain
    for safe in KNOWN_SAFE_DOMAINS:
        if domain.endswith('.' + safe):
            return True
    return False

def check_virustotal(url):
    """Check URL against VirusTotal v3 API."""
    if not VIRUSTOTAL_API_KEY:
        return {"checked": False, "reason": "API Key not configured", "malicious_count": 0}
    
    try:
        # VirusTotal v3 URL ID is base64 representation of URL without padding
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        
        response = requests.get(vt_url, headers=headers, timeout=5)
        
        # If URL not found in VT database, try scanning it
        if response.status_code == 404:
            # Try checking the domain instead
            domain = extract_domain(url)
            if domain:
                domain_url = f"https://www.virustotal.com/api/v3/domains/{domain}"
                response = requests.get(domain_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            return {
                "checked": True,
                "malicious_count": malicious,
                "suspicious_count": suspicious,
                "total_engines": sum(stats.values())
            }
        else:
            return {"checked": False, "reason": f"API Error (HTTP {response.status_code})", "malicious_count": 0}
            
    except Exception as e:
        return {"checked": False, "reason": f"Request failed: {str(e)}", "malicious_count": 0}

def check_safe_browsing(url):
    """Check URL against Google Safe Browsing v4 API."""
    if not GOOGLE_SAFE_BROWSING_API_KEY:
        return {"checked": False, "reason": "API Key not configured", "flagged": False}
    
    try:
        sb_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}"
        payload = {
            "client": {
                "clientId": "phishguard",
                "clientVersion": "2.0.0"
            },
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }
        
        response = requests.post(sb_url, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            # If there's a match, matches will be present in the response
            matches = data.get("matches", [])
            if matches:
                threat_type = matches[0].get("threatType", "Malicious")
                return {"checked": True, "flagged": True, "threat_type": threat_type}
            return {"checked": True, "flagged": False}
        else:
            return {"checked": False, "reason": f"API Error (HTTP {response.status_code})", "flagged": False}
            
    except Exception as e:
        return {"checked": False, "reason": f"Request failed: {str(e)}", "flagged": False}

def check_whois(domain):
    """Get domain age using WHOIS library."""
    if not domain:
        return {"checked": False, "reason": "No valid domain"}
    
    # Do not run WHOIS lookup on IP addresses
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, domain):
        return {"checked": False, "reason": "IP address domain"}
        
    try:
        # Set a low timeout to avoid blocking requests
        # python-whois uses standard socket which doesn't always support timeout natively,
        # but we can wrap it or try to fetch quickly.
        w = whois.whois(domain)
        creation_date = w.creation_date
        
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
            
        if creation_date:
            if hasattr(creation_date, 'tzinfo') and creation_date.tzinfo is not None:
                creation_date = creation_date.replace(tzinfo=None)
            age_days = (datetime.now() - creation_date).days
            return {"checked": True, "age_days": age_days, "creation_date": creation_date.strftime('%Y-%m-%d')}
        else:
            return {"checked": True, "age_days": None, "reason": "Creation date not in WHOIS data"}
            
    except Exception as e:
        return {"checked": False, "reason": f"WHOIS failed: {str(e)}"}

def check_ssl(domain):
    """Check if the domain has a valid SSL certificate."""
    if not domain:
        return {"checked": False, "reason": "No valid domain", "has_ssl": False}
        
    # Check port 443
    try:
        context = ssl.create_default_context()
        # Set timeout to 3 seconds to prevent long blocks
        with socket.create_connection((domain, 443), timeout=3) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    # Successfully established TLS/SSL connection with verified certificate
                    return {"checked": True, "has_ssl": True, "valid": True}
        return {"checked": True, "has_ssl": False, "valid": False}
    except ssl.SSLCertVerificationError as e:
        # Connection succeeded but cert validation failed
        return {"checked": True, "has_ssl": True, "valid": False, "reason": f"Cert verification failed: {e.reason}"}
    except Exception as e:
        # Connection failed or port 443 closed
        return {"checked": True, "has_ssl": False, "valid": False, "reason": str(e)}

def check_url_heuristics(url):
    """Perform static/heuristic check on URL patterns."""
    heuristics = {
        "uses_ip": False,
        "is_long": False,
        "many_subdomains": False,
        "has_suspicious_keywords": False,
        "no_https": False,
        "suspicious_keywords_found": []
    }
    
    url_lower = url.lower()
    
    # 1. Scheme Check
    if url_lower.startswith('http://'):
        heuristics["no_https"] = True
    elif not url_lower.startswith('https://') and not url_lower.startswith('http://'):
        # If no scheme, default to checking without secure prefix
        heuristics["no_https"] = True
        
    # 2. Extract domain and check IP usage
    domain = extract_domain(url)
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, domain):
        heuristics["uses_ip"] = True
        
    # 3. Length check (>75 chars)
    if len(url) > 75:
        heuristics["is_long"] = True
        
    # 4. Subdomains check (>3 dots)
    if domain.count('.') > 3:
        heuristics["many_subdomains"] = True
        
    # 5. Suspicious keywords check
    keywords = ['verify', 'secure', 'bank', 'update', 'login', 'signin', 'submit', 
                'ebay', 'paypal', 'free', 'gift', 'claim', 'urgent', 'warning', 
                'account', 'support', 'billing', 'verification']
    
    # We check in the path or subdomain, excluding the main domain parts
    parsed = urlparse(url if '://' in url else 'http://' + url)
    path_and_query = parsed.path + parsed.query
    
    found_keywords = []
    for kw in keywords:
        if kw in path_and_query:
            found_keywords.append(kw)
        # Check if keyword is part of a subdomain (but not the primary domain name)
        subdomains = domain.split('.')[:-2] if len(domain.split('.')) > 2 else []
        for sub in subdomains:
            if kw in sub:
                found_keywords.append(kw)
                
    if found_keywords:
        heuristics["has_suspicious_keywords"] = True
        heuristics["suspicious_keywords_found"] = list(set(found_keywords))
        
    return heuristics

def calculate_risk_score(url, vt_res, sb_res, whois_res, ssl_res, heur_res):
    """Calculate a final risk score from 0-100 based on weighted signals."""
    domain = extract_domain(url)
    
    # Whitelist is absolute safety
    if is_whitelisted(domain):
        return {
            "score": 0,
            "verdict": "Safe",
            "reasons": ["This is a known and trusted domain (Whitelisted)."]
        }
        
    score = 0
    reasons = []
    
    # 1. Google Safe Browsing (Weight: 50)
    if sb_res.get("checked") and sb_res.get("flagged"):
        score += 50
        threat = sb_res.get("threat_type", "Malicious threat")
        reasons.append(f"Google Safe Browsing flagged URL as: {threat}")
        
    # 2. VirusTotal (Weight: 50)
    if vt_res.get("checked"):
        malicious = vt_res.get("malicious_count", 0)
        if malicious > 0:
            score += 50
            reasons.append(f"VirusTotal detected threat on {malicious} engine(s).")
            
    # 3. WHOIS Domain Age (Weight: 20)
    if whois_res.get("checked"):
        age = whois_res.get("age_days")
        if age is not None:
            if age < 30:
                score += 20
                reasons.append(f"Domain is very new (created {age} days ago).")
            elif age < 180:
                score += 5
                reasons.append(f"Domain is relatively new (created {age} days ago).")
        else:
            # No age/creation date found in WHOIS for a non-IP domain
            score += 5
            reasons.append("WHOIS registration details are missing or hidden.")
            
    # 4. SSL Certificate (Weight: 15 for missing, 15 for invalid)
    if ssl_res.get("checked"):
        if not ssl_res.get("has_ssl"):
            score += 15
            reasons.append("SSL/HTTPS port is closed or unavailable.")
        elif not ssl_res.get("valid"):
            score += 15
            reasons.append("SSL certificate is invalid, untrusted, or expired.")
            
    # 5. Heuristics: HTTP usage (Weight: 15)
    if heur_res.get("no_https"):
        # Only add reason if we haven't already complained about missing SSL above
        score += 15
        if "SSL/HTTPS port is closed or unavailable." not in reasons:
            reasons.append("URL uses insecure HTTP instead of HTTPS.")
            
    # 6. Heuristics: IP Address (Weight: 10)
    if heur_res.get("uses_ip"):
        score += 10
        reasons.append("URL uses an IP address directly instead of a domain name.")
        
    # 7. Heuristics: Keywords (Weight: 10)
    if heur_res.get("has_suspicious_keywords"):
        score += 10
        kws = ", ".join(heur_res.get("suspicious_keywords_found", []))
        reasons.append(f"Contains suspicious keywords in URL/subdomains ({kws}).")
        
    # 8. Heuristics: Length (Weight: 5)
    if heur_res.get("is_long"):
        score += 5
        reasons.append("URL length is unusually long (> 75 characters).")
        
    # 9. Heuristics: Subdomains (Weight: 5)
    if heur_res.get("many_subdomains"):
        score += 5
        reasons.append("Domain contains an excessive number of subdomains.")
        
    # Clamp score to [0, 100]
    score = min(max(score, 0), 100)
    
    # Verdict logic
    if score <= 20:
        verdict = "Safe"
    elif score <= 50:
        verdict = "Suspicious"
    else:
        verdict = "Malicious"
        
    if not reasons:
        reasons.append("No active threat signals detected. The URL appears clean.")
        
    return {
        "score": score,
        "verdict": verdict,
        "reasons": reasons
    }

def analyze_url(url):
    """Main function to perform full real-time analysis of a URL."""
    domain = extract_domain(url)
    
    # If whitelisted, return immediately without calls to save APIs/time
    if is_whitelisted(domain):
        return {
            "url": url,
            "domain": domain,
            "risk_score": 0,
            "verdict": "Safe",
            "reasons": ["This is a known and trusted domain (Whitelisted)."],
            "details": {
                "virustotal": {"checked": True, "malicious_count": 0},
                "safe_browsing": {"checked": True, "flagged": False},
                "whois": {"checked": True, "age_days": 9999},
                "ssl": {"checked": True, "has_ssl": True, "valid": True},
                "heuristics": check_url_heuristics(url)
            }
        }
        
    # Run heuristic check
    heur_res = check_url_heuristics(url)
    
    # Run live checks
    vt_res = check_virustotal(url)
    sb_res = check_safe_browsing(url)
    whois_res = check_whois(domain)
    ssl_res = check_ssl(domain)
    
    # Calculate final verdict
    analysis = calculate_risk_score(url, vt_res, sb_res, whois_res, ssl_res, heur_res)
    
    return {
        "url": url,
        "domain": domain,
        "risk_score": analysis["score"],
        "verdict": analysis["verdict"],
        "reasons": analysis["reasons"],
        "details": {
            "virustotal": vt_res,
            "safe_browsing": sb_res,
            "whois": whois_res,
            "ssl": ssl_res,
            "heuristics": heur_res
        }
    }

def analyze_text(text, content_type='email'):
    """Analyze email or SMS text for phishing signs."""
    text_lower = text.lower()
    reasons = []
    
    # 1. Extract URLs
    url_pattern = r'(https?://[^\s<>"]+|www\.[^\s<>"]+)'
    urls = re.findall(url_pattern, text)
    
    max_url_score = 0
    url_reasons = []
    url_scanned_details = []
    
    for url in urls[:5]: # Limit to first 5 URLs to avoid rate limits / long delays
        # Clean the URL if it starts with www. without scheme
        scan_url = url
        if not re.match(r'^https?://', url, re.IGNORECASE):
            scan_url = 'http://' + url
            
        url_analysis = analyze_url(scan_url)
        url_scanned_details.append(url_analysis)
        if url_analysis["risk_score"] > max_url_score:
            max_url_score = url_analysis["risk_score"]
            url_reasons = url_analysis["reasons"]
            
    # 2. Heuristics: Keywords (phishing keywords)
    phishing_keywords = {
        'verify': 'Request to verify credentials/account',
        'suspended': 'Threat of account suspension',
        'urgent': 'Creating artificial sense of urgency',
        'winner': 'Offering false winnings/rewards',
        'claim': 'Prompting to claim a gift or money',
        'free': 'Offering free items/services',
        'password': 'Inquiring about credentials/passwords',
        'login': 'Prompting to log in to an account',
        'expire': 'Threat of expiration of service/access',
        'confirm': 'Requesting confirmation of personal details',
        'security': 'Claiming a security alert or issue',
        'update': 'Prompting to update account details',
        'immediately': 'Urging immediate response'
    }
    
    found_keywords = []
    keyword_score = 0
    for kw, description in phishing_keywords.items():
        count = text_lower.count(kw)
        if count > 0:
            found_keywords.append(kw)
            keyword_score += 10
            
    keyword_score = min(keyword_score, 30)
    
    # SMS specific keyword/length heuristics
    if content_type == 'sms':
        if len(text) > 160:
            keyword_score += 5
            reasons.append("SMS message is unusually long.")
            
    if found_keywords:
        reasons.append(f"Contains suspicious keywords: {', '.join(found_keywords)}")
        
    # Combine scores:
    if urls:
        reasons.append(f"Extracted and scanned {len(urls)} link(s) from the text.")
        if max_url_score > 0:
            reasons.append(f"Most suspicious link scored {max_url_score}/100 in risk.")
            for r in url_reasons:
                if r not in reasons:
                    reasons.append(f"Link threat: {r}")
        final_score = max(max_url_score, keyword_score)
    else:
        final_score = keyword_score
        
    final_score = min(max(final_score, 0), 100)
    
    # Verdict logic
    if final_score <= 20:
        verdict = "Safe"
    elif final_score <= 50:
        verdict = "Suspicious"
    else:
        verdict = "Malicious"
        
    if not reasons:
        reasons.append("No obvious phishing indicators or suspicious links detected.")
        
    return {
        "text": text,
        "content_type": content_type,
        "risk_score": final_score,
        "verdict": verdict,
        "reasons": reasons,
        "urls_scanned": url_scanned_details
    }

