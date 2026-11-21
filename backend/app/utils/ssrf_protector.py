import ipaddress
import socket
from urllib.parse import urlparse
from typing import Tuple, List, Optional
import dns.resolver

BLOCKED_HOSTNAMES = {
    "localhost",
    "metadata.google.internal",
    "metadata.aws.internal",
    "instance-data",
    "169.254.169.254",
    "100.100.100.200",
}

def is_safe_url(url_str: str) -> Tuple[bool, str, Optional[str]]:
    """
    Validates URL to protect against SSRF and unauthorized local network access.
    Returns: (is_safe, reason, normalized_hostname)
    """
    if not url_str or not isinstance(url_str, str):
        return False, "Empty or invalid URL provided", None
        
    url_clean = url_str.strip()
    if not url_clean.startswith(("http://", "https://")):
        url_clean = "https://" + url_clean
        
    try:
        parsed = urlparse(url_clean)
    except Exception as e:
        return False, f"Malformed URL syntax: {str(e)}", None
        
    hostname = parsed.hostname
    if not hostname:
        return False, "URL does not contain a valid hostname", None
        
    hostname_lower = hostname.lower().rstrip(".")

    # Check blocked hostnames
    if hostname_lower in BLOCKED_HOSTNAMES:
        return False, f"Access to restricted infrastructure/metadata hostname '{hostname}' is blocked", hostname_lower

    # Block common internal-only DNS suffixes (mDNS, internal zones, home LAN)
    if hostname_lower.endswith((".local", ".internal", ".localhost", ".home", ".lan", ".intranet")):
        return False, f"Access to internal-only hostname '{hostname}' is blocked", hostname_lower
        
    # Check if host is direct IP address
    try:
        ip = ipaddress.ip_address(hostname_lower)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            return False, f"Direct access to private, loopback, or internal IP '{ip}' is strictly blocked", hostname_lower
        return True, "Public IP address", hostname_lower
    except ValueError:
        # Not a direct IP, check DNS
        pass
        
    # Resolve both A and AAAA records with a strict timeout. Fail closed: if
    # the domain cannot be resolved we cannot prove it is not internal, so we
    # do not allow the probe.
    resolved_ips = set()
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 0.5
        resolver.timeout = 0.5
        for qtype in ("A", "AAAA"):
            try:
                answers = resolver.resolve(hostname_lower, qtype)
                for rdata in answers:
                    resolved_ips.add(rdata.address)
            except Exception:
                continue
    except Exception:
        pass

    if not resolved_ips:
        return False, (
            f"Domain '{hostname}' could not be resolved to a public IP address; "
            "SSRF check refuses to probe an unverifiable target"
        ), hostname_lower

    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified:
                return False, f"Domain '{hostname}' resolves to internal/private IP '{ip_str}' (SSRF prevention)", hostname_lower
        except ValueError:
            continue

    return True, "Safe public URL", hostname_lower
