import math
import re
from urllib.parse import urlparse
from typing import Dict, Any, List
import httpx
from backend.app.utils.ssrf_protector import is_safe_url
from backend.app.utils.typosquatting import analyze_domain_typosquatting, split_domain, KNOWN_SHORTENERS, HIGH_RISK_TLDS

SUSPICIOUS_PATHS = [
    r"/login", r"/signin", r"/verify", r"/secure", r"/banking",
    r"/update-billing", r"/wallet", r"/account-suspended", r"/confirm",
    r"/credential", r"/auth/login", r"/portal/security"
]

def calculate_shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    freq = {}
    for c in text:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def analyze_website_url(url_str: str) -> Dict[str, Any]:
    """
    Safely inspects a website URL without executing scripts or downloading payloads.
    Includes SSRF guard, lexical analysis, typosquatting checks, and safe probe.
    """
    indicators = []
    rule_score = 0.0
    
    url_clean = url_str.strip()
    if not url_clean.startswith(("http://", "https://")):
        url_clean = "https://" + url_clean

    # 1. SSRF and Domain Validity Check. We still run lexical analysis below
    # even for blocked targets, so users see every reason the URL is dangerous.
    ssrf_safe, ssrf_reason, _ssrf_host = is_safe_url(url_clean)
    if not ssrf_safe:
        rule_score += 95.0
        indicators.append({
            "indicator_type": "SSRF_FORBIDDEN_TARGET",
            "title": "Restricted Target / SSRF Protection Triggered",
            "description": ssrf_reason,
            "severity": "CRITICAL",
            "evidence": url_clean
        })

    try:
        parsed = urlparse(url_clean)
        hostname = (parsed.hostname or "").lower()
        path = parsed.path.lower()
        query = parsed.query.lower()
    except Exception as e:
        return {
            "url": url_clean,
            "hostname": "malformed",
            "is_accessible": False,
            "rule_score": 75.0,
            "indicators": [{
                "indicator_type": "MALFORMED_URL",
                "title": "Malformed URL Structure",
                "description": f"URL syntax could not be parsed: {str(e)}",
                "severity": "HIGH",
                "evidence": url_clean
            }],
            "domain_info": {}
        }

    # 2. IP Address in Hostname
    is_ip = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', hostname))
    if is_ip:
        rule_score += 45
        indicators.append({
            "indicator_type": "IP_BASED_URL",
            "title": "Raw IP Address Hostname",
            "description": f"The website is accessed directly via numeric IP address ({hostname}) rather than a registered domain name, standard practice in zero-day phishing kits.",
            "severity": "CRITICAL",
            "evidence": hostname
        })

    # 3. Excessive Subdomains (Domain Fronting / Obfuscation)
    parts = hostname.split(".")
    if len(parts) > 3 and not is_ip:
        rule_score += 25
        indicators.append({
            "indicator_type": "EXCESSIVE_SUBDOMAINS",
            "title": "Deep Subdomain Hierarchy",
            "description": f"Domain contains {len(parts)} levels of hierarchy, often utilized to bury the true root domain from mobile browser address bars.",
            "severity": "MEDIUM",
            "evidence": hostname
        })

    # 4. '@' Symbol in URL
    if "@" in url_clean:
        rule_score += 40
        indicators.append({
            "indicator_type": "URL_USERINFO_OBFUSCATION",
            "title": "UserInfo '@' Obfuscation Trick",
            "description": "URL includes an '@' symbol, tricking users into thinking the prefix is the domain while browsers actually navigate to the segment after '@'.",
            "severity": "CRITICAL",
            "evidence": url_clean
        })

    # 5. Shannon Entropy (DGA Detection)
    main_domain, _, _ = split_domain(hostname)
    entropy = calculate_shannon_entropy(main_domain)
    if entropy > 3.8 and len(main_domain) > 10:
        rule_score += 30
        indicators.append({
            "indicator_type": "HIGH_DOMAIN_ENTROPY",
            "title": "High Entropy Domain (Probable DGA)",
            "description": f"Domain '{main_domain}' exhibits unusually high randomness (entropy: {entropy:.2f}), characteristic of Domain Generation Algorithms used by botnets.",
            "severity": "HIGH",
            "evidence": f"Entropy: {entropy:.2f}"
        })

    # 6. Typosquatting & Brand Spoofing Check
    typo_indicators = analyze_domain_typosquatting(hostname)
    for ti in typo_indicators:
        rule_score += 35
        indicators.append({
            "indicator_type": ti["type"],
            "title": ti["title"],
            "description": ti["description"],
            "severity": ti["severity"],
            "evidence": ti["evidence"]
        })

    # 7. Suspicious Path & Credential Keywords
    for pat in SUSPICIOUS_PATHS:
        if re.search(pat, path):
            rule_score += 20
            indicators.append({
                "indicator_type": "SUSPICIOUS_LOGIN_PATH",
                "title": "Sensitive Portal / Authentication Path",
                "description": f"URL path matches high-risk authentication keyword '{pat}' on an unverified domain.",
                "severity": "MEDIUM",
                "evidence": path
            })
            break

    # 8. Safe HTTP Probe (Strict timeout, never executes scripts, verifies redirect safety)
    probe_info = {
        "status_code": None,
        "https": url_clean.startswith("https://"),
        "redirect_chain": [],
        "content_length": 0
    }
    
    if not ssrf_safe:
        probe_info["probe_error"] = "Outbound probe blocked by SSRF guard"
    else:
        try:
            # Strict 1.0 second timeout to prevent slow/hanging network calls
            with httpx.Client(timeout=1.0, follow_redirects=False, verify=True) as client:
                resp = client.head(url_clean)
                probe_info["status_code"] = resp.status_code

                # Check redirect header if 3xx
                if resp.status_code in (301, 302, 303, 307, 308):
                    redirect_url = resp.headers.get("Location", "")
                    probe_info["redirect_chain"].append(redirect_url)

                    # Verify destination is safe
                    dest_safe, dest_reason, _ = is_safe_url(redirect_url)
                    if not dest_safe:
                        rule_score += 50
                        indicators.append({
                            "indicator_type": "SUSPICIOUS_REDIRECT_INTERNAL",
                            "title": "Dangerous Redirect to Internal Target",
                            "description": f"URL redirects to restricted destination: {dest_reason}",
                            "severity": "CRITICAL",
                            "evidence": redirect_url
                        })
        except Exception as e:
            probe_info["probe_error"] = str(e)

    # Insecure Protocol Check
    if not url_clean.startswith("https://"):
        rule_score += 15
        indicators.append({
            "indicator_type": "INSECURE_HTTP_PROTOCOL",
            "title": "Unencrypted HTTP Protocol",
            "description": "Website does not enforce TLS encryption (HTTP), transmitting any submitted form data in cleartext.",
            "severity": "LOW",
            "evidence": "http://"
        })

    rule_score = min(max(rule_score, 0.0), 100.0)

    return {
        "url": url_clean,
        "hostname": hostname,
        "scheme": parsed.scheme,
        "path": path,
        "rule_score": rule_score,
        "indicators": indicators,
        "domain_info": {
            "hostname": hostname,
            "entropy": round(entropy, 2),
            "parts_count": len(parts),
            "is_ip": is_ip,
            "ssrf_blocked": not ssrf_safe,
            "probe": probe_info
        }
    }
