"""Shared email text normalization for training and inference."""

import re
from typing import Any, Dict, Optional

_EMAIL_ADDRESS = re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b")
_URL = re.compile(r"\b(?:https?://|www\.)\S+", re.IGNORECASE)
_LONG_NUMBER = re.compile(r"\b(?:\+?\d[\d\s().-]{6,}\d)\b")


def build_email_text(subject: Optional[str], body: Optional[str]) -> str:
    text = f"{subject or ''}\n{body or ''}".lower()
    text = _URL.sub(" URLTOKEN ", text)
    text = _EMAIL_ADDRESS.sub(" EMAILTOKEN ", text)
    return _LONG_NUMBER.sub(" NUMTOKEN ", text)


def email_text_for_scan(raw_analysis: Dict[str, Any], raw_input: Dict[str, Any]) -> str:
    subject = raw_input.get("subject") or raw_analysis.get("subject") or ""
    body = (
        raw_input.get("body")
        or raw_analysis.get("body_preview")
        or raw_input.get("raw_content")
        or ""
    )
    return build_email_text(subject, body)
