import math
import re
from urllib.parse import urlparse, urlunparse
from typing import Dict, Any, List

from backend.app.utils.typosquatting import split_domain


def normalize_url_for_model(url: str) -> str:
    """Canonicalize www and root-path variants before deriving URL features."""
    target_url = (url or "").strip()
    if not target_url:
        return ""
    if not target_url.lower().startswith(("http://", "https://")):
        target_url = f"https://{target_url}"

    parsed = urlparse(target_url)
    hostname = parsed.hostname
    if not hostname:
        return target_url

    normalized_host = hostname.lower()
    if normalized_host.startswith("www."):
        normalized_host = normalized_host[4:]

    try:
        port = parsed.port
    except ValueError:
        return target_url

    authority = f"[{normalized_host}]" if ":" in normalized_host else normalized_host
    if port is not None:
        authority = f"{authority}:{port}"
    if "@" in parsed.netloc:
        authority = f"{parsed.netloc.rsplit('@', 1)[0]}@{authority}"

    path = "" if parsed.path == "/" else parsed.path
    return urlunparse(parsed._replace(
        scheme=parsed.scheme.lower(),
        netloc=authority,
        path=path,
    ))


def calculate_entropy(text: str) -> float:
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

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "num_dots",
    "num_hyphens",
    "has_ip",
    "has_at_symbol",
    "domain_entropy",
    "is_shortener",
    "has_sensitive_keyword",
    "has_brand_mention",
    "urgency_count",
    "credential_harvest_count",
    "sender_reply_mismatch",
    "has_executable_attachment",
    "dmarc_spf_failure"
]

def extract_features_from_scan(scan_type: str, raw_data: Dict[str, Any]) -> List[float]:
    """
    Extracts a standardized 15-dimensional numeric feature vector for ML evaluation.
    """
    url_length = 0
    domain_length = 0
    num_dots = 0
    num_hyphens = 0
    has_ip = 0
    has_at_symbol = 0
    domain_entropy = 0.0
    is_shortener = 0
    has_sensitive_keyword = 0
    has_brand_mention = 0
    urgency_count = 0
    credential_harvest_count = 0
    sender_reply_mismatch = 0
    has_executable_attachment = 0
    dmarc_spf_failure = 0

    if scan_type in ("WEBSITE", "QR"):
        target_url = raw_data.get("url", "") or raw_data.get("decoded_content", "")
        try:
            normalized_url = normalize_url_for_model(target_url)
            url_length = len(normalized_url)
            parsed = urlparse(normalized_url)
            host = (parsed.hostname or "").lower()
            path = (parsed.path or "").lower()
            main_domain, _, _ = split_domain(host)
            domain_length = len(main_domain)
            num_dots = host.count(".")
            num_hyphens = int("-" in host)
            has_ip = 1 if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', host) else 0
            has_at_symbol = 1 if "@" in normalized_url else 0
            domain_entropy = calculate_entropy(main_domain)
            
            from backend.app.utils.typosquatting import (
                KNOWN_SHORTENERS,
                has_suspicious_brand_mention,
            )
            is_shortener = 1 if any(s in host for s in KNOWN_SHORTENERS) else 0
            has_brand_mention = int(has_suspicious_brand_mention(host))
            
            sensitive_keywords = ["login", "signin", "verify", "secure", "wallet", "banking", "account", "update"]
            has_sensitive_keyword = 1 if any(k in path or k in host for k in sensitive_keywords) else 0
            urgency_terms = ["urgent", "immediate", "suspended", "terminate", "action", "verify", "expire"]
            urgency_count = sum(1 for term in urgency_terms if term in normalized_url.lower())
            harvest_terms = ["password", "login", "verify", "credential", "account", "banking"]
            credential_harvest_count = sum(
                1 for term in harvest_terms if term in normalized_url.lower()
            )
        except Exception:
            pass

    elif scan_type == "EMAIL":
        subject = raw_data.get("subject", "").lower()
        # The email detector returns "body_preview" (capped at 500 chars).
        # Accept "body" too so both detector shapes feed the ML features.
        body = (raw_data.get("body") or raw_data.get("body_preview") or "").lower()
        full_text = f"{subject} {body}"
        
        sender_domain = raw_data.get("sender_domain", "").lower()
        reply_to = raw_data.get("reply_to", "").lower()
        if reply_to and sender_domain and sender_domain not in reply_to:
            sender_reply_mismatch = 1

        urgency_terms = ["urgent", "immediate", "suspended", "terminate", "action required", "hours", "unauthorized"]
        urgency_count = sum(1 for term in urgency_terms if term in full_text)

        harvest_terms = ["password", "pin", "verify card", "billing", "credential", "ssn", "login"]
        credential_harvest_count = sum(1 for term in harvest_terms if term in full_text)

        attachments = raw_data.get("attachments", [])
        from backend.app.detectors.email_detector import SUSPICIOUS_EXTENSIONS
        for att in attachments:
            fname = att.get("filename", "").lower()
            if any(fname.endswith(ext) for ext in SUSPICIOUS_EXTENSIONS):
                has_executable_attachment = 1
                break

        headers = raw_data.get("headers", {})
        auth_hdr = (headers.get("spf", "") + " " + headers.get("auth_results", "")).lower()
        if "fail" in auth_hdr:
            dmarc_spf_failure = 1

        extracted_urls = raw_data.get("extracted_urls", [])
        if extracted_urls:
            url_length = len(extracted_urls[0])
            num_dots = extracted_urls[0].count(".")

    return [
        float(url_length),
        float(domain_length),
        float(num_dots),
        float(num_hyphens),
        float(has_ip),
        float(has_at_symbol),
        float(round(domain_entropy, 2)),
        float(is_shortener),
        float(has_sensitive_keyword),
        float(has_brand_mention),
        float(urgency_count),
        float(credential_harvest_count),
        float(sender_reply_mismatch),
        float(has_executable_attachment),
        float(dmarc_spf_failure)
    ]
