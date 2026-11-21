from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.database.session import get_db
from backend.app.models.models import Incident, ActionLog, Scan, ThreatIndicator
from backend.app.schemas.schemas import IncidentResponse, IncidentUpdate

router = APIRouter(prefix="/incidents", tags=["Incidents"])

@router.get("")
def list_incidents(
    severity: Optional[str] = None,
    status: Optional[str] = None,
    incident_type: Optional[str] = None,
    limit: int = 50,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(Incident)
    if severity:
        query = query.filter(Incident.severity == severity.upper())
    if status:
        query = query.filter(Incident.status == status.upper())
    if incident_type:
        query = query.filter(Incident.incident_type == incident_type.upper())
        
    total = query.count()
    items = query.order_by(desc(Incident.created_at)).offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "items": [
            {
                "id": inc.id,
                "scan_id": inc.scan_id,
                "title": inc.title,
                "incident_type": inc.incident_type,
                "severity": inc.severity,
                "status": inc.status,
                "assigned_action": inc.assigned_action,
                "potential_impact": inc.potential_impact,
                "resolution_notes": inc.resolution_notes,
                "created_at": inc.created_at,
                "updated_at": inc.updated_at
            }
            for inc in items
        ]
    }

@router.get("/{incident_id}")
def get_incident(incident_id: str, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    scan = db.query(Scan).filter(Scan.id == incident.scan_id).first() if incident.scan_id else None
    indicators = db.query(ThreatIndicator).filter(ThreatIndicator.scan_id == incident.scan_id).all() if incident.scan_id else []
    actions = db.query(ActionLog).filter(ActionLog.incident_id == incident_id).order_by(ActionLog.created_at).all()
    
    return {
        "incident": {
            "id": incident.id,
            "scan_id": incident.scan_id,
            "title": incident.title,
            "incident_type": incident.incident_type,
            "severity": incident.severity,
            "status": incident.status,
            "assigned_action": incident.assigned_action,
            "potential_impact": incident.potential_impact,
            "resolution_notes": incident.resolution_notes,
            "created_at": incident.created_at,
            "updated_at": incident.updated_at
        },
        "scan": {
            "id": scan.id,
            "input_reference": scan.input_reference,
            "risk_score": scan.risk_score,
            "risk_level": scan.risk_level,
            "summary": scan.summary
        } if scan else None,
        "threat_indicators": [
            {
                "title": i.title,
                "indicator_type": i.indicator_type,
                "severity": i.severity,
                "description": i.description,
                "evidence": i.evidence
            }
            for i in indicators
        ],
        "action_logs": [
            {
                "id": a.id,
                "agent_name": a.agent_name,
                "action_type": a.action_type,
                "action_details": a.action_details,
                "performed_by": a.performed_by,
                "created_at": a.created_at
            }
            for a in actions
        ]
    }

@router.patch("/{incident_id}")
def update_incident(incident_id: str, update_in: IncidentUpdate, db: Session = Depends(get_db)):
    incident = db.query(Incident).filter(Incident.id == incident_id).first()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
        
    if update_in.status:
        incident.status = update_in.status.upper()
    if update_in.resolution_notes:
        incident.resolution_notes = update_in.resolution_notes
    if update_in.assigned_action:
        incident.assigned_action = update_in.assigned_action
        
    # Log manual update
    log = ActionLog(
        incident_id=incident_id,
        agent_name="SOC Analyst",
        action_type="INCIDENT_UPDATE",
        action_details=f"Updated status to {incident.status}. Notes: {incident.resolution_notes}",
        performed_by="SOC_Analyst"
    )
    db.add(log)
    db.commit()
    db.refresh(incident)
    
    return {
        "success": True,
        "message": "Incident updated successfully",
        "incident": {
            "id": incident.id,
            "status": incident.status,
            "resolution_notes": incident.resolution_notes
        }
    }
