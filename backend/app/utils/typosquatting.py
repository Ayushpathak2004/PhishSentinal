import re
from typing import List, Dict, Optional, Tuple

HIGH_VALUE_BRANDS = [
    "paypal", "microsoft", "apple", "google", "amazon", "netflix",
    "chase", "bankofamerica", "wellsfargo", "citibank", "coinbase",
    "binance", "facebook", "instagram", "linkedin", "twitter",
    "dropbox", "dhl", "fedex", "usps", "whatsapp", "telegram",
    "steam", "adobe", "outlook", "icloud", "yahoo"
]

HIGH_RISK_TLDS = {
    "xyz", "top", "buzz", "loan", "work", "click", "fit", "gq", "tk", 
    "ml", "cf", "ga", "country", "stream", "men", "bid", "download"
}

KNOWN_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd", "buff.ly", "ow.ly", 
    "rebrand.ly", "rb.gy", "cutt.ly", "goo.gl", "qr.ae", "shorturl.at"
}

# Common homoglyph replacements
HOMOGLYPH_MAP = {
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'і': 'i', 'ј': 'j', 'ѕ': 's', 'ԁ': 'd', 'ԛ': 'q', '0': 'o', '1': 'l'
}

# Common multi-part public suffixes. Without these, "example.co.uk" is parsed
# as domain "co" + TLD "uk", which hides the real domain.
MULTI_PART_TLDS = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk",
    "com.au", "net.au", "org.au", "gov.au",
    "co.in", "net.in", "org.in", "gov.in",
    "co.jp", "ne.jp", "or.jp", "go.jp",
    "com.br", "net.br", "org.br", "gov.br",
    "co.za", "org.za", "gov.za",
    "com.mx", "org.mx", "gob.mx",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.cn", "net.cn", "org.cn", "gov.cn",
    "com.sg", "net.sg", "org.sg", "gov.sg",
    "com.hk", "net.hk", "org.hk", "gov.hk",
    "com.tw", "net.tw", "org.tw", "gov.tw",
    "co.kr", "or.kr", "go.kr",
    "com.tr", "net.tr", "org.tr", "gov.tr",
    "co.il", "org.il", "net.il", "gov.il",
    "com.ar", "net.ar", "org.ar", "gob.ar",
    "com.ua", "net.ua", "org.ua", "gov.ua",
}


def normalize_homoglyphs(text: str) -> str:
    """Map visually similar Unicode/character confusables to ASCII."""
    if not text:
        return text
    return "".join(HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def split_domain(hostname: str) -> Tuple[str, str, List[str]]:
    """
    Split a hostname into (main_domain, tld, subdomains) with basic public
    suffix handling. Falls back to the last two labels for unknown suffixes.
    """
    parts = [p for p in hostname.lower().strip(".").split(".") if p]
    if len(parts) < 2:
        return (parts[0] if parts else ""), "", []

    if len(parts) >= 3:
        two_part_suffix = f"{parts[-2]}.{parts[-1]}"
        if two_part_suffix in MULTI_PART_TLDS:
            return parts[-3], two_part_suffix, parts[:-3]

    return parts[-2], parts[-1], parts[:-2]


def _brand_matches_label(label: str, brand: str) -> bool:
    """
    True when the brand appears as a whole label or is separated from the rest
    of the domain by a non-alphanumeric character. This avoids flagging words
    that merely contain a brand (e.g. "pineapple" containing "apple").
    """
    if not label or not brand:
        return False
    if label == brand:
        return True
    pattern = rf"(?:^|[^a-z0-9]){re.escape(brand)}(?:[^a-z0-9]|$)"
    return re.search(pattern, label) is not None

def levenshtein_distance(s1: str, s2: str) -> int:
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

def analyze_domain_typosquatting(hostname: str) -> List[Dict[str, str]]:
    """
    Examines a domain name for typosquatting, brand impersonation, and homoglyphs.
    """
    indicators = []
    hostname_clean = hostname.lower().strip()
    
    # 1. Punycode check
    if hostname_clean.startswith("xn--") or ".xn--" in hostname_clean:
        indicators.append({
            "type": "PUNYCODE_HOMOGLYPH",
            "title": "Internationalized Domain / Punycode Detected",
            "description": f"Domain '{hostname_clean}' utilizes Punycode encoding, a common vehicle for visual spoofing.",
            "severity": "HIGH",
            "evidence": hostname_clean
        })

    # Extract parts with public-suffix awareness
    main_domain, tld, subdomains = split_domain(hostname_clean)
    normalized_main = normalize_homoglyphs(main_domain)

    # 2. High-risk TLD check
    tld_leaf = tld.rsplit(".", 1)[-1]
    if tld_leaf in HIGH_RISK_TLDS:
        indicators.append({
            "type": "SUSPICIOUS_TLD",
            "title": "High-Risk Top-Level Domain",
            "description": f"Domain ends with '.{tld}', which is frequently associated with disposable phishing campaigns.",
            "severity": "MEDIUM",
            "evidence": f".{tld}"
        })

    # 3. Known Shortener check
    full_domain = f"{main_domain}.{tld}" if tld else main_domain
    if full_domain in KNOWN_SHORTENERS:
        indicators.append({
            "type": "URL_SHORTENER",
            "title": "URL Shortener Service Detected",
            "description": f"The link uses shortening service '{full_domain}' which conceals the ultimate landing destination.",
            "severity": "MEDIUM",
            "evidence": full_domain
        })

    # 4. Brand Impersonation, Homoglyph Spoofing & Typosquatting in main domain
    for brand in HIGH_VALUE_BRANDS:
        # Visual confusable that normalizes exactly to the brand (e.g. paypa1)
        if normalized_main == brand and main_domain != brand:
            indicators.append({
                "type": "HOMOGLYPH_BRAND_SPOOFING",
                "title": f"Homoglyph Brand Spoofing: {brand.capitalize()}",
                "description": f"Domain '{main_domain}' uses visually similar characters that resolve to the trademark '{brand}'.",
                "severity": "CRITICAL",
                "evidence": f"Domain '{main_domain}' normalizes to '{normalized_main}'"
            })
            break

        # Brand appears as a label (paypal-security-login) but not the exact
        # brand domain itself (paypal.com). Boundary-aware matching avoids
        # false positives such as "pineapple" containing "apple".
        if main_domain != brand and (
            _brand_matches_label(main_domain, brand)
            or _brand_matches_label(normalized_main, brand)
        ):
            indicators.append({
                "type": "BRAND_IMPERSONATION",
                "title": f"Targeted Brand Name In Domain: {brand.capitalize()}",
                "description": f"The domain '{main_domain}' contains the trademark '{brand}' combined with other characters.",
                "severity": "CRITICAL",
                "evidence": f"Brand '{brand}' found within '{main_domain}'"
            })
            break

        # Typosquatting: Levenshtein distance of 1 or 2
        dist = levenshtein_distance(main_domain, brand)
        if 1 <= dist <= 2 and len(main_domain) >= 4 and abs(len(main_domain) - len(brand)) <= 2:
            indicators.append({
                "type": "TYPOSQUATTING",
                "title": f"Typosquatting of {brand.capitalize()}",
                "description": f"Domain '{main_domain}' is suspiciously similar to legitimate brand '{brand}' (edit distance: {dist}).",
                "severity": "CRITICAL",
                "evidence": f"Domain '{main_domain}' vs Target '{brand}'"
            })
            break

    # 5. Brand in Subdomain (e.g. paypal.com.login-verify.xyz)
    for sub in subdomains:
        normalized_sub = normalize_homoglyphs(sub)
        for brand in HIGH_VALUE_BRANDS:
            if _brand_matches_label(sub, brand) or _brand_matches_label(normalized_sub, brand):
                indicators.append({
                    "type": "SUBDOMAIN_BRAND_SPOOFING",
                    "title": f"Subdomain Brand Spoofing ({brand.capitalize()})",
                    "description": f"Subdomain '{sub}' impersonates brand '{brand}' to deceive victims on third-party host '{full_domain}'.",
                    "severity": "CRITICAL",
                    "evidence": f"Subdomain: {sub}, Actual Root: {full_domain}"
                })
                break

    return indicators


def has_suspicious_brand_mention(hostname: str) -> bool:
    """Return whether a hostname contains a brand-impersonation signal."""
    brand_indicator_types = {
        "HOMOGLYPH_BRAND_SPOOFING",
        "BRAND_IMPERSONATION",
        "TYPOSQUATTING",
        "SUBDOMAIN_BRAND_SPOOFING",
    }
    return any(
        indicator["type"] in brand_indicator_types
        for indicator in analyze_domain_typosquatting(hostname)
    )
