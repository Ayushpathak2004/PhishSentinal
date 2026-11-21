import base64
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Request
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database.session import get_db
from backend.app.models.models import Scan, ThreatIndicator
from backend.app.schemas.schemas import WebsiteScanRequest, ScanResponse
from backend.app.agents.orchestrator import AgentOrchestrator

router = APIRouter(prefix="", tags=["Scanners"])


async def _json_body(http_request: Request) -> dict:
    """
    Return a JSON object body when the request uses application/json.

    FastAPI treats routes with File/Form parameters as multipart endpoints, so
    the Pydantic body model is ignored for JSON requests. Parsing the raw body
    here lets the same endpoint accept both JSON and multipart/form-data.
    """
    content_type = http_request.headers.get("content-type", "").lower()
    if "application/json" not in content_type:
        return {}

    try:
        payload = await http_request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON request body")

    if payload is None:
        return {}
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="JSON request body must be an object")
    return payload


@router.post("/scan/email")
async def scan_email(
    http_request: Request,
    file: Optional[UploadFile] = File(None),
    raw_content: Optional[str] = Form(None),
    sender: Optional[str] = Form(None),
    subject: Optional[str] = Form(None),
    body: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Scans email content for phishing, impersonation, SPF/DMARC anomalies,
    and credential harvesting. Supports JSON bodies, multipart form fields,
    or an uploaded .eml/.txt/.msg file.
    """
    payload = await _json_body(http_request)

    email_text = raw_content or payload.get("raw_content") or ""
    parsed_sender = sender or payload.get("sender") or ""
    parsed_subject = subject or payload.get("subject") or ""
    parsed_body = body or payload.get("body") or ""
    attachments_meta = []

    if file:
        filename = file.filename or ""
        if not filename.lower().endswith((".eml", ".txt", ".msg")):
            raise HTTPException(status_code=400, detail="Only .eml, .txt, or .msg email files are accepted")
        content_bytes = await file.read()
        email_text = content_bytes.decode("utf-8", errors="ignore")
        if not parsed_subject:
            parsed_subject = filename

    if not email_text and not (parsed_sender or parsed_subject or parsed_body):
        raise HTTPException(status_code=400, detail="No email content, sender, or subject provided for analysis")

    raw_input = {
        "raw_content": email_text,
        "sender": parsed_sender,
        "subject": parsed_subject,
        "body": parsed_body,
        "attachments": attachments_meta
    }

    result = await AgentOrchestrator.run_pipeline("EMAIL", raw_input, db)
    return result

@router.post("/scan/website")
async def scan_website(
    request: WebsiteScanRequest,
    db: Session = Depends(get_db)
):
    """
    Safely inspects a URL for SSRF, typosquatting, entropy, and deceptive paths.
    """
    url = request.url.strip()
    if not url:
        raise HTTPException(status_code=400, detail="URL cannot be empty")

    raw_input = {"url": url}
    result = await AgentOrchestrator.run_pipeline("WEBSITE", raw_input, db)
    return result

@router.post("/scan/qr")
async def scan_qr(
    http_request: Request,
    file: Optional[UploadFile] = File(None),
    manual_content: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    """
    Decodes QR image and evaluates embedded URLs, payment schemas, or exploit directives.
    Accepts JSON bodies, multipart form fields, or an uploaded image.
    Never initiates payments or opens destinations automatically.
    """
    payload = await _json_body(http_request)

    image_bytes = None
    filename = "qr_upload.png"
    text_content = manual_content or payload.get("manual_content")
    image_base64 = payload.get("image_base64")

    if file:
        filename = file.filename or filename
        image_bytes = await file.read()
    elif image_base64:
        try:
            b64_str = image_base64
            if "," in b64_str:
                b64_str = b64_str.split(",", 1)[1]
            image_bytes = base64.b64decode(b64_str, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="Invalid base64 QR image string")

    if not image_bytes and not text_content:
        raise HTTPException(status_code=400, detail="Provide an image file, base64 QR image, or text payload")

    raw_input = {
        "image_bytes": image_bytes,
        "filename": filename,
        "manual_content": text_content
    }

    result = await AgentOrchestrator.run_pipeline("QR", raw_input, db)
    return result

@router.get("/scans")
def list_scans(
    scan_type: Optional[str] = None,
    risk_level: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(Scan)
    if scan_type:
        query = query.filter(Scan.scan_type == scan_type.upper())
    if risk_level:
        query = query.filter(Scan.risk_level == risk_level.upper())
        
    total = query.count()
    scans = query.order_by(desc(Scan.created_at)).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "items": [
            {
                "id": s.id,
                "scan_type": s.scan_type,
                "input_reference": s.input_reference,
                "risk_score": s.risk_score,
                "risk_level": s.risk_level,
                "confidence": s.confidence,
                "fraud_probability": s.fraud_probability,
                "summary": s.summary,
                "created_at": s.created_at
            }
            for s in scans
        ]
    }

@router.get("/scans/{scan_id}")
def get_scan(scan_id: str, db: Session = Depends(get_db)):
    scan = db.query(Scan).filter(Scan.id == scan_id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    indicators = db.query(ThreatIndicator).filter(ThreatIndicator.scan_id == scan_id).all()
    
    return {
        "id": scan.id,
        "scan_type": scan.scan_type,
        "input_reference": scan.input_reference,
        "risk_score": scan.risk_score,
        "risk_level": scan.risk_level,
        "confidence": scan.confidence,
        "fraud_probability": scan.fraud_probability,
        "summary": scan.summary,
        "created_at": scan.created_at,
        "indicators": [
            {
                "indicator_type": i.indicator_type,
                "title": i.title,
                "description": i.description,
                "severity": i.severity,
                "evidence": i.evidence
            }
            for i in indicators
        ],
        "full_result": scan.full_result
    }
