import email
from email import policy
import re
from typing import Dict, Any, List, Optional
from backend.app.utils.typosquatting import analyze_domain_typosquatting

SUSPICIOUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
    ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".cpl", ".iso", ".img",
    ".dll", ".msi", ".jar", ".docm", ".xlsm", ".pptm", ".dotm", ".xltm"
}

URGENT_PHRASES = [
    r"immediate\s+action\s+required",
    r"account\s+(has\s+been\s+)?suspended",
    r"unauthorized\s+access\s+detected",
    r"verify\s+your\s+identity\s+within\s+\d+\s+hours?",
    r"failure\s+to\s+respond\s+will\s+result\s+in",
    r"security\s+alert.*compromised",
    r"wire\s+transfer\s+request",
    r"urgent\s+wire\s+transfer",
    r"confidential\s+inquiry",
    r"reset\s+your\s+password\s+now",
    r"your\s+account\s+will\s+be\s+terminated",
    r"final\s+notice",
    r"tax\s+refund\s+waiting",
    r"lottery\s+winner",
    r"inheritance\s+claim"
]

CREDENTIAL_HARVEST_PHRASES = [
    r"enter\s+your\s+password",
    r"confirm\s+your\s+pin",
    r"update\s+billing\s+details",
    r"verify\s+credit\s+card",
    r"social\s+security\s+number",
    r"login\s+to\s+verify",
    r"click\s+here\s+to\s+validate"
]

def extract_email_address(raw_str: str) -> str:
    if not raw_str:
        return ""
    match = re.search(r'<([^>]+)>', raw_str)
    if match:
        return match.group(1).strip().lower()
    match = re.search(r'[\w\.-]+@[\w\.-]+\.\w+', raw_str)
    return match.group(0).strip().lower() if match else raw_str.strip().lower()

def extract_domain(email_addr: str) -> str:
    if "@" in email_addr:
        return email_addr.split("@")[-1].strip().lower()
    return ""

def analyze_email_content(
    raw_content: Optional[str] = None,
    sender: Optional[str] = None,
    subject: Optional[str] = None,
    body: Optional[str] = None,
    attachments_metadata: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    """
    Parses and inspects email headers, sender mismatch, phishing vocabulary,
    suspicious attachments, and embedded URLs.
    """
    indicators = []
    rule_score = 0.0
    extracted_urls = []
    inspected_headers = {}
    
    parsed_sender = sender or ""
    parsed_reply_to = ""
    parsed_subject = subject or ""
    parsed_body = body or ""
    attachments = attachments_metadata or []

    # If raw MIME content is provided, parse via standard library
    if raw_content:
        try:
            msg = email.message_from_string(raw_content, policy=policy.default)
            parsed_sender = str(msg.get("From", parsed_sender))
            parsed_reply_to = str(msg.get("Reply-To", ""))
            parsed_subject = str(msg.get("Subject", parsed_subject))
            
            # Inspect key security headers
            inspected_headers["from"] = parsed_sender
            inspected_headers["reply_to"] = parsed_reply_to
            inspected_headers["subject"] = parsed_subject
            inspected_headers["spf"] = msg.get("Received-SPF", "")
            inspected_headers["auth_results"] = msg.get("Authentication-Results", "")
            inspected_headers["dkim"] = msg.get("DKIM-Signature", "")
            inspected_headers["return_path"] = msg.get("Return-Path", "")
            
            # Extract body
            body_parts = []
            for part in msg.walk():
                content_type = part.get_content_type()
                content_disposition = str(part.get("Content-Disposition", ""))
                
                # Check attachments
                filename = part.get_filename()
                if filename:
                    attachments.append({
                        "filename": filename,
                        "size": len(part.get_payload(decode=True) or b""),
                        "content_type": content_type
                    })
                elif content_type in ["text/plain", "text/html"] and "attachment" not in content_disposition:
                    try:
                        payload = part.get_payload(decode=True)
                        if payload:
                            body_parts.append(payload.decode("utf-8", errors="ignore"))
                    except Exception:
                        pass
            if body_parts:
                parsed_body = "\n".join(body_parts)
        except Exception as e:
            # Fallback if MIME parse fails
            parsed_body = raw_content

    sender_addr = extract_email_address(parsed_sender)
    sender_domain = extract_domain(sender_addr)
    reply_to_addr = extract_email_address(parsed_reply_to)
    reply_to_domain = extract_domain(reply_to_addr)

    # 1. Sender Domain vs Reply-To Mismatch
    if reply_to_addr and sender_domain and reply_to_domain and sender_domain != reply_to_domain:
        rule_score += 35
        indicators.append({
            "indicator_type": "SENDER_REPLY_TO_MISMATCH",
            "title": "Sender and Reply-To Domain Mismatch",
            "description": f"The email claims to originate from '@{sender_domain}' but replies are routed to '@{reply_to_domain}', a classic BEC / phishing evasion tactic.",
            "severity": "HIGH",
            "evidence": f"From: {sender_addr} | Reply-To: {reply_to_addr}"
        })

    # 2. Typosquatting in sender domain
    if sender_domain:
        typo_indicators = analyze_domain_typosquatting(sender_domain)
        for ti in typo_indicators:
            rule_score += 40
            indicators.append({
                "indicator_type": ti["type"],
                "title": ti["title"],
                "description": ti["description"],
                "severity": ti["severity"],
                "evidence": ti["evidence"]
            })

    # 3. Authentication Header Failures (SPF / DMARC)
    auth_str = (inspected_headers.get("auth_results", "") + " " + inspected_headers.get("spf", "")).lower()
    if "spf=fail" in auth_str or "spf=softfail" in auth_str:
        rule_score += 25
        indicators.append({
            "indicator_type": "SPF_VERIFICATION_FAILURE",
            "title": "SPF Authentication Failure",
            "description": "Sending mail server is not authorized by the domain's SPF record, indicating likely spoofing.",
            "severity": "HIGH",
            "evidence": inspected_headers.get("spf") or inspected_headers.get("auth_results")
        })
    if "dmarc=fail" in auth_str:
        rule_score += 30
        indicators.append({
            "indicator_type": "DMARC_POLICY_REJECTION",
            "title": "DMARC Alignment Check Failed",
            "description": "The message failed sender alignment validation under the declared DMARC policy.",
            "severity": "HIGH",
            "evidence": inspected_headers.get("auth_results")
        })

    # 4. Urgent / Social Engineering Lexicon
    combined_text = f"{parsed_subject}\n{parsed_body}".lower()
    matched_urgencies = []
    for pattern in URGENT_PHRASES:
        if re.search(pattern, combined_text, re.IGNORECASE):
            matched_urgencies.append(pattern)
    if matched_urgencies:
        rule_score += min(len(matched_urgencies) * 15, 35)
        indicators.append({
            "indicator_type": "SOCIAL_ENGINEERING_URGENCY",
            "title": "Urgency and Psychological Pressure",
            "description": "Email contains artificial urgency and coercive language designed to bypass critical judgment.",
            "severity": "HIGH" if len(matched_urgencies) > 1 else "MEDIUM",
            "evidence": f"Detected trigger patterns ({len(matched_urgencies)} matches)"
        })

    # 5. Credential Harvesting Signals
    matched_harvests = []
    for pattern in CREDENTIAL_HARVEST_PHRASES:
        if re.search(pattern, combined_text, re.IGNORECASE):
            matched_harvests.append(pattern)
    if matched_harvests:
        rule_score += 30
        indicators.append({
            "indicator_type": "CREDENTIAL_HARVESTING_INTENT",
            "title": "Credential or Sensitive Data Solicitation",
            "description": "Explicit solicitation of user credentials, payment details, or security PINs detected.",
            "severity": "CRITICAL",
            "evidence": "Requests login credentials or financial validation"
        })

    # 6. Attachment Threat Analysis
    for att in attachments:
        fname = att.get("filename", "").lower()
        # Double extension check (e.g., photo.jpg.exe)
        double_ext_match = re.search(r'\.[a-z0-9]{2,4}\.([a-z0-9]{2,4})$', fname)
        if double_ext_match:
            rule_score += 45
            indicators.append({
                "indicator_type": "SUSPICIOUS_ATTACHMENT_DOUBLE_EXTENSION",
                "title": f"Dangerous Double Extension: {att.get('filename')}",
                "description": f"Attachment '{att.get('filename')}' uses deceptive double extension concealing an executable.",
                "severity": "CRITICAL",
                "evidence": fname
            })
        for ext in SUSPICIOUS_EXTENSIONS:
            if fname.endswith(ext):
                rule_score += 40
                indicators.append({
                    "indicator_type": "SUSPICIOUS_ATTACHMENT_EXTENSION",
                    "title": f"Restricted Executable / Script Attachment: {att.get('filename')}",
                    "description": f"Attachment '{att.get('filename')}' has high-risk extension '{ext}'.",
                    "severity": "CRITICAL",
                    "evidence": f"File: {fname} ({att.get('size', 0)} bytes)"
                })
                break

    # 7. Extract URLs from body
    url_matches = re.findall(r'https?://[^\s<>"\']+', parsed_body)
    extracted_urls = list(dict.fromkeys(url_matches))[:10]  # Deduplicate, top 10

    # Cap score at 100
    rule_score = min(max(rule_score, 0.0), 100.0)

    return {
        "sender": parsed_sender,
        "sender_address": sender_addr,
        "sender_domain": sender_domain,
        "reply_to": parsed_reply_to,
        "subject": parsed_subject,
        "body_preview": parsed_body[:500] if parsed_body else "",
        "attachments": attachments,
        "extracted_urls": extracted_urls,
        "indicators": indicators,
        "rule_score": rule_score,
        "headers": inspected_headers
    }
