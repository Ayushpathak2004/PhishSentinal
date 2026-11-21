import base64
import io
import re
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse, parse_qs
import cv2
import numpy as np
from PIL import Image

from backend.app.detectors.website_detector import analyze_website_url
from backend.app.utils.typosquatting import KNOWN_SHORTENERS

PAYMENT_SCHEMES = ["upi://", "bitcoin:", "ethereum:", "solana:", "lightning:", "paypal.me/", "venmo://"]

def decode_qr_image(image_bytes: bytes) -> Optional[str]:
    """
    Decodes QR code from binary image data using OpenCV QRCodeDetector.
    """
    try:
        # Load via PIL first to handle various image formats, convert to RGB
        pil_img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        cv_img = np.array(pil_img)
        # Convert RGB to BGR for OpenCV
        cv_img = cv_img[:, :, ::-1].copy()

        detector = cv2.QRCodeDetector()
        data, points, _ = detector.detectAndDecode(cv_img)
        if data:
            return data.strip()
            
        # Try grayscale with thresholding if standard detection fails
        gray = cv2.cvtColor(cv_img, cv2.COLOR_BGR2GRAY)
        data, points, _ = detector.detectAndDecode(gray)
        if data:
            return data.strip()

        # Try adaptive threshold
        thresh = cv2.adaptiveThreshold(gray, 255, cv2.ADAPTIVE_THRESH_GAUSSIAN_C, cv2.THRESH_BINARY, 11, 2)
        data, points, _ = detector.detectAndDecode(thresh)
        if data:
            return data.strip()
    except Exception as e:
        return None
    return None

def analyze_qr_payload(
    decoded_text: Optional[str] = None,
    image_bytes: Optional[bytes] = None,
    manual_content: Optional[str] = None
) -> Dict[str, Any]:
    """
    Decodes QR image (if provided) and analyzes payload for malicious links,
    payment scams, deceptive redirects, or unauthorized intent.
    NEVER initiates payments or opens destinations automatically.
    """
    indicators = []
    rule_score = 0.0
    content = decoded_text

    # Decode from image if raw bytes provided and content not yet extracted
    if not content and image_bytes:
        content = decode_qr_image(image_bytes)

    if not content and manual_content:
        content = manual_content.strip()

    if not content:
        return {
            "decoded_content": "",
            "content_type": "UNKNOWN_OR_UNREADABLE",
            "rule_score": 60.0,
            "indicators": [{
                "indicator_type": "QR_DECODE_FAILURE",
                "title": "Unreadable or Obfuscated QR Matrix",
                "description": "Unable to decode a standard QR matrix from the submitted image. Malicious actors sometimes distort QR codes to bypass automated security scanners.",
                "severity": "MEDIUM",
                "evidence": "Image decode returned 0 bytes"
            }],
            "destination_analysis": {}
        }

    content_lower = content.lower()
    content_type = "TEXT"
    destination_analysis = {}

    # 1. Payment URI Detection (Quishing / Payment Hijacking)
    is_payment = any(scheme in content_lower for scheme in PAYMENT_SCHEMES)
    if is_payment:
        content_type = "PAYMENT_INSTRUCTION"
        rule_score += 35
        indicators.append({
            "indicator_type": "QR_PAYMENT_INSTRUCTION",
            "title": "Payment Initiation Directive Detected",
            "description": "The QR code attempts to trigger a financial transfer protocol (UPI/Crypto/PayPal). Crucial Safety Guard: Automated execution is locked.",
            "severity": "HIGH",
            "evidence": content[:120]
        })

        # Deep inspection of UPI URI if applicable
        if "upi://pay" in content_lower:
            parsed = urlparse(content)
            qs = parse_qs(parsed.query)
            pa = qs.get("pa", [""])[0]  # Payee address / VPA
            pn = qs.get("pn", [""])[0]  # Payee name
            am = qs.get("am", [""])[0]  # Amount
            tn = qs.get("tn", [""])[0]  # Transaction note
            
            # Check for social engineering in transaction note
            scam_keywords = ["fine", "penalty", "power", "electricity", "lottery", "gift", "refund", "kyc", "overdue"]
            if any(k in tn.lower() for k in scam_keywords):
                rule_score += 45
                indicators.append({
                    "indicator_type": "QR_PAYMENT_SCAM_NOTE",
                    "title": "Deceptive Payment Solicitation Note",
                    "description": f"The transaction memo '{tn}' exhibits typical payment fraud keywords coercing immediate transfer.",
                    "severity": "CRITICAL",
                    "evidence": f"Note: {tn} | VPA: {pa}"
                })

    # 2. Web URL Inspection
    elif content_lower.startswith(("http://", "https://", "www.")) or re.match(r'^[a-zA-Z0-9-]+\.[a-zA-Z]{2,}', content):
        content_type = "WEB_URL"
        url_target = content if content_lower.startswith(("http://", "https://")) else f"https://{content}"
        
        # Run website detector logic
        web_res = analyze_website_url(url_target)
        destination_analysis = web_res
        rule_score += web_res.get("rule_score", 0.0)
        
        # Merge website indicators
        for ind in web_res.get("indicators", []):
            indicators.append(ind)

        # Check if URL uses shortener
        parsed_url = urlparse(url_target)
        hostname = (parsed_url.hostname or "").lower()
        if any(shortener in hostname for shortener in KNOWN_SHORTENERS):
            rule_score += 25
            indicators.append({
                "indicator_type": "QR_SHORTENED_URL",
                "title": "QR Encodes Shortened URL",
                "description": f"The QR embeds a shortened link ({hostname}), concealing the true final destination from physical scanners.",
                "severity": "HIGH",
                "evidence": hostname
            })

    # 3. WiFi or Shell Payload
    elif content_lower.startswith("wifi:"):
        content_type = "WIFI_CONFIG"
        indicators.append({
            "indicator_type": "QR_WIFI_PROVISION",
            "title": "WiFi Network Configuration",
            "description": "QR code encodes automated WiFi credentials.",
            "severity": "LOW",
            "evidence": content[:60]
        })
    elif any(cmd in content_lower for cmd in ["curl ", "wget ", "powershell", "cmd.exe", "rm -rf", "eval("]):
        content_type = "COMMAND_PAYLOAD"
        rule_score += 85
        indicators.append({
            "indicator_type": "QR_COMMAND_EXPLOIT",
            "title": "Malicious Command / Exploit String",
            "description": "QR contains shell command injection syntax intended to trigger local execution on vulnerable mobile interpreters.",
            "severity": "CRITICAL",
            "evidence": content[:80]
        })

    rule_score = min(max(rule_score, 0.0), 100.0)

    return {
        "decoded_content": content,
        "content_type": content_type,
        "rule_score": rule_score,
        "indicators": indicators,
        "destination_analysis": destination_analysis
    }
