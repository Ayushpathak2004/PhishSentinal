from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.app.database.session import get_db
from backend.app.models.models import Scan, Incident, QuarantinedFile, AgentExecution

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

@router.get("/stats")
def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Computes real operational metrics aggregated directly from database tables.
    """
    total_scans = db.query(Scan).count()
    emails_analyzed = db.query(Scan).filter(Scan.scan_type == "EMAIL").count()
    websites_analyzed = db.query(Scan).filter(Scan.scan_type == "WEBSITE").count()
    qr_analyzed = db.query(Scan).filter(Scan.scan_type == "QR").count()
    
    threats_detected = db.query(Scan).filter(Scan.risk_score >= 20.0).count()
    critical_threats = db.query(Scan).filter(Scan.risk_score >= 70.0).count()
    files_quarantined = db.query(QuarantinedFile).count()
    incidents_resolved = db.query(Incident).filter(Incident.status == "RESOLVED").count()

    # Risk level distribution
    distribution = {
        "SAFE": db.query(Scan).filter(Scan.risk_level == "SAFE").count(),
        "MODERATE": db.query(Scan).filter(Scan.risk_level == "MODERATE").count(),
        "HIGH": db.query(Scan).filter(Scan.risk_level == "HIGH").count(),
        "CRITICAL": db.query(Scan).filter(Scan.risk_level == "CRITICAL").count()
    }

    # Recent scans for activity stream
    recent_scans = db.query(Scan).order_by(desc(Scan.created_at)).limit(8).all()
    recent_activity = [
        {
            "id": s.id,
            "type": s.scan_type,
            "reference": s.input_reference,
            "score": s.risk_score,
            "level": s.risk_level,
            "timestamp": s.created_at.isoformat()
        }
        for s in recent_scans
    ]

    return {
        "total_scans": total_scans,
        "emails_analyzed": emails_analyzed,
        "websites_analyzed": websites_analyzed,
        "qr_analyzed": qr_analyzed,
        "threats_detected": threats_detected,
        "critical_threats": critical_threats,
        "files_quarantined": files_quarantined,
        "incidents_resolved": incidents_resolved,
        "risk_distribution": distribution,
        "recent_activity": recent_activity
    }

@router.get("/activity")
def get_activity_feed(limit: int = 20, db: Session = Depends(get_db)):
    scans = db.query(Scan).order_by(desc(Scan.created_at)).limit(limit).all()
    return [
        {
            "id": s.id,
            "scan_type": s.scan_type,
            "input_reference": s.input_reference,
            "risk_score": s.risk_score,
            "risk_level": s.risk_level,
            "summary": s.summary,
            "created_at": s.created_at
        }
        for s in scans
    ]
