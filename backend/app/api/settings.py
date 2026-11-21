from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from pydantic import BaseModel
from typing import Optional

from backend.app.database.session import get_db, SessionLocal
from backend.app.core.config import settings
from backend.app.models.models import SystemSetting, BlocklistEntry
from backend.app.api.auth import require_admin

router = APIRouter(prefix="", tags=["Settings & Intel"])

# key -> (settings attribute, converter)
PERSISTED_SETTINGS = {
    "threshold_low_max": ("THRESHOLD_LOW_MAX", int),
    "threshold_moderate_max": ("THRESHOLD_MODERATE_MAX", int),
    "threshold_high_max": ("THRESHOLD_HIGH_MAX", int),
    "threshold_critical_min": ("THRESHOLD_CRITICAL_MIN", int),
    "groq_model": ("GROQ_MODEL", str),
    "groq_api_key": ("GROQ_API_KEY", str),
}


class SettingsUpdateSchema(BaseModel):
    threshold_low_max: Optional[int] = None
    threshold_moderate_max: Optional[int] = None
    threshold_high_max: Optional[int] = None
    threshold_critical_min: Optional[int] = None
    groq_api_key: Optional[str] = None
    groq_model: Optional[str] = None


def load_settings_from_db(db: Optional[Session] = None) -> None:
    """Load persisted settings into the in-memory settings object at startup."""
    owns_session = db is None
    if owns_session:
        db = SessionLocal()
    try:
        rows = db.query(SystemSetting).filter(SystemSetting.key.in_(PERSISTED_SETTINGS.keys())).all()
        for row in rows:
            attr, converter = PERSISTED_SETTINGS[row.key]
            try:
                value = converter(row.value)
            except (TypeError, ValueError):
                continue
            setattr(settings, attr, value)
    finally:
        if owns_session:
            db.close()


def _persist_setting(db: Session, key: str, value) -> None:
    row = db.query(SystemSetting).filter(SystemSetting.key == key).first()
    text = str(value)
    if row:
        row.value = text
    else:
        db.add(SystemSetting(key=key, value=text))


@router.get("/settings")
def get_settings(db: Session = Depends(get_db)):
    groq_configured = bool(settings.GROQ_API_KEY.strip())
    masked_key = (
        f"{settings.GROQ_API_KEY[:4]}...{settings.GROQ_API_KEY[-4:]}"
        if groq_configured and len(settings.GROQ_API_KEY) > 8
        else ("Configured" if groq_configured else "Not Set")
    )

    return {
        "threshold_low_max": settings.THRESHOLD_LOW_MAX,
        "threshold_moderate_max": settings.THRESHOLD_MODERATE_MAX,
        "threshold_high_max": settings.THRESHOLD_HIGH_MAX,
        "threshold_critical_min": settings.THRESHOLD_CRITICAL_MIN,
        "groq_api_key_configured": groq_configured,
        "groq_api_key_preview": masked_key,
        "groq_model": settings.GROQ_MODEL,
        "auto_quarantine_enabled": True,
        "auto_blocklist_enabled": True
    }


@router.post("/settings")
def update_settings(
    update: SettingsUpdateSchema,
    db: Session = Depends(get_db),
    _admin: object = Depends(require_admin),
):
    values = {
        "threshold_low_max": update.threshold_low_max,
        "threshold_moderate_max": update.threshold_moderate_max,
        "threshold_high_max": update.threshold_high_max,
        "threshold_critical_min": update.threshold_critical_min,
        "groq_api_key": update.groq_api_key.strip() if update.groq_api_key and update.groq_api_key.strip() else None,
        "groq_model": update.groq_model.strip() if update.groq_model and update.groq_model.strip() else None,
    }

    low = values["threshold_low_max"] if values["threshold_low_max"] is not None else settings.THRESHOLD_LOW_MAX
    moderate = values["threshold_moderate_max"] if values["threshold_moderate_max"] is not None else settings.THRESHOLD_MODERATE_MAX
    high = values["threshold_high_max"] if values["threshold_high_max"] is not None else settings.THRESHOLD_HIGH_MAX
    critical = values["threshold_critical_min"] if values["threshold_critical_min"] is not None else settings.THRESHOLD_CRITICAL_MIN

    if not (0 <= low < moderate < high < critical <= 100):
        raise HTTPException(
            status_code=400,
            detail="Thresholds must satisfy 0 <= low < moderate < high < critical <= 100",
        )

    for key, value in values.items():
        if value is None:
            continue
        attr, _ = PERSISTED_SETTINGS[key]
        setattr(settings, attr, value)
        _persist_setting(db, key, value)

    db.commit()

    return {
        "success": True,
        "message": "Policy settings updated and persisted successfully."
    }


@router.get("/threat-intel")
def get_threat_intelligence(db: Session = Depends(get_db)):
    blocklist = db.query(BlocklistEntry).filter(BlocklistEntry.is_active == True).all()

    return {
        "active_blocklist_count": len(blocklist),
        "blocklist_entries": [
            {
                "id": b.id,
                "type": b.entry_type,
                "value": b.value,
                "reason": b.reason,
                "severity": b.severity,
                "added_by": b.added_by,
                "created_at": b.created_at
            }
            for b in blocklist
        ],
        "attack_patterns": [
            {"name": "Zero-Day BEC Impersonation", "description": "Display name spoofing and mismatched Reply-To routing targeting executive finance.", "frequency": "High"},
            {"name": "Typosquatted Brand Domains", "description": "IDN homoglyphs and single-character permutations spoofing PayPal, Microsoft, and Google.", "frequency": "Critical"},
            {"name": "Quishing (Malicious QR Matrix)", "description": "QR codes overlaying legitimate restaurant/payment QR stickers directing victims to credential harvesters.", "frequency": "Elevated"},
            {"name": "DGA Botnet Landing Pages", "description": "High-entropy algorithmic subdomains hosting automated exploit and phishing kits.", "frequency": "Moderate"}
        ]
    }
