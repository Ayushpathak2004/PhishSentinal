import time
import os
import uuid
import email
from email import policy
from typing import Dict, Any, Optional, List
from backend.app.detectors.email_detector import analyze_email_content
from backend.app.detectors.website_detector import analyze_website_url
from backend.app.detectors.qr_detector import analyze_qr_payload, decode_qr_image
from backend.app.utils.security import compute_sha256, compute_md5

class FileAgent:
    """
    Agent 1: File Agent
    Purpose: Input collection, format validation, protocol normalization,
             and initial threat extraction.
    """
    AGENT_NAME = "File Agent"
    ROLE = "Input Collection & Protocol Normalization"

    @staticmethod
    def _extract_email_attachment_bytes(raw_content: str) -> Dict[str, bytes]:
        """Collect raw attachment bytes for the Enforcer (never persisted)."""
        attachments: Dict[str, bytes] = {}
        if not raw_content:
            return attachments
        try:
            message = email.message_from_string(raw_content, policy=policy.default)
            for part in message.walk():
                filename = part.get_filename()
                if not filename:
                    continue
                payload = part.get_payload(decode=True)
                if payload:
                    attachments[filename] = payload
        except Exception:
            return attachments
        return attachments

    @classmethod
    async def process(
        cls,
        task_id: str,
        scan_type: str,
        raw_input: Dict[str, Any]
    ) -> Dict[str, Any]:
        start_time = time.time()
        private_payload: Dict[str, Any] = {}

        normalized_data = {
            "task_id": task_id,
            "scan_type": scan_type,
            "input_reference": "",
            "raw_preview": "",
            "extracted_urls": [],
            "attachments_metadata": [],
            "hashes": {},
            "raw_analysis": {},
            "status": "SUCCESS",
            "errors": []
        }

        try:
            if scan_type == "EMAIL":
                raw_content = raw_input.get("raw_content", "")
                sender = raw_input.get("sender", "")
                subject = raw_input.get("subject", "")
                body = raw_input.get("body", "")
                attachments = raw_input.get("attachments", [])

                if raw_content:
                    content_bytes = raw_content.encode("utf-8")
                    normalized_data["hashes"] = {
                        "sha256": compute_sha256(content_bytes),
                        "md5": compute_md5(content_bytes)
                    }

                email_res = analyze_email_content(
                    raw_content=raw_content,
                    sender=sender,
                    subject=subject,
                    body=body,
                    attachments_metadata=attachments
                )
                
                normalized_data["input_reference"] = email_res.get("subject") or email_res.get("sender") or "Unspecified Email"
                normalized_data["raw_preview"] = email_res.get("body_preview", "")
                normalized_data["extracted_urls"] = email_res.get("extracted_urls", [])
                normalized_data["attachments_metadata"] = email_res.get("attachments", [])
                normalized_data["raw_analysis"] = email_res

                # Raw attachment bytes are handed to the Enforcer through a
                # non-persisted channel so quarantined files are the real
                # attachments rather than placeholders.
                attachment_bytes = cls._extract_email_attachment_bytes(raw_content)
                if attachment_bytes:
                    private_payload["attachment_bytes"] = attachment_bytes

            elif scan_type == "WEBSITE":
                url = raw_input.get("url", "").strip()
                normalized_data["input_reference"] = url
                normalized_data["raw_preview"] = url
                
                url_bytes = url.encode("utf-8")
                normalized_data["hashes"] = {
                    "sha256": compute_sha256(url_bytes),
                    "md5": compute_md5(url_bytes)
                }

                web_res = analyze_website_url(url)
                normalized_data["raw_analysis"] = web_res
                normalized_data["extracted_urls"] = [web_res.get("url", url)]

            elif scan_type == "QR":
                image_bytes = raw_input.get("image_bytes")
                manual_content = raw_input.get("manual_content")
                filename = raw_input.get("filename", "qr_code.png")
                
                normalized_data["input_reference"] = filename

                if image_bytes:
                    normalized_data["hashes"] = {
                        "sha256": compute_sha256(image_bytes),
                        "md5": compute_md5(image_bytes)
                    }
                    # Keep raw bytes out of agent output: it is persisted to JSON
                    # columns and returned to the API. The Enforcer receives the
                    # original bytes through the non-persisted raw_input channel.
                    normalized_data["attachments_metadata"] = [{
                        "filename": filename,
                        "size": len(image_bytes),
                        "content_type": "image/png",
                        "sha256": compute_sha256(image_bytes)
                    }]

                qr_res = analyze_qr_payload(
                    image_bytes=image_bytes,
                    manual_content=manual_content
                )
                
                decoded = qr_res.get("decoded_content", "")
                normalized_data["raw_preview"] = decoded[:200]
                normalized_data["raw_analysis"] = qr_res
                if qr_res.get("content_type") == "WEB_URL":
                    normalized_data["extracted_urls"] = [decoded]
            else:
                raise ValueError(f"Unsupported scan type: {scan_type}")

        except Exception as e:
            normalized_data["status"] = "ERROR"
            normalized_data["errors"].append(str(e))

        execution_time = time.time() - start_time
        summary = (
            f"Ingested {scan_type} input reference '{normalized_data['input_reference'][:45]}'. "
            f"Extracted {len(normalized_data['extracted_urls'])} URLs, "
            f"{len(normalized_data['attachments_metadata'])} attachments, SHA-256 hash calculated."
        )

        output = {
            "agent_name": cls.AGENT_NAME,
            "role": cls.ROLE,
            "task_id": task_id,
            "status": normalized_data["status"],
            "execution_time_ms": round(execution_time * 1000, 2),
            "summary": summary,
            "data": normalized_data
        }
        if private_payload:
            output["_private"] = private_payload
        return output
