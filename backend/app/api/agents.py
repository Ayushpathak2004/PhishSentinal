from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session
from sqlalchemy import func, desc

from backend.app.database.session import get_db
from backend.app.models.models import AgentExecution

router = APIRouter(prefix="/agents", tags=["Agents"])

AGENTS_METADATA = [
    {
        "name": "File Agent",
        "role": "Input Collection & Protocol Normalization",
        "description": "Parses MIME envelopes, decodes QR images, extracts raw URLs, attachments, and cryptographic hashes."
    },
    {
        "name": "Risk Score Agent",
        "role": "Threat Assessment & Fraud Probability Estimation",
        "description": "Combines deterministic rule heuristics, scikit-learn Random Forest inference, and Groq LLM contextual reasoning."
    },
    {
        "name": "Policy Agent",
        "role": "Intelligent Security Decision-Making",
        "description": "Applies configurable safety thresholds, checks financial impact, and issues binding security actions."
    },
    {
        "name": "Enforcer Agent",
        "role": "Security Response Execution",
        "description": "Safely quarantines malicious uploads to local storage, inserts malicious domains into the internal blocklist, and wraps suspicious links."
    },
    {
        "name": "Vault Keeper",
        "role": "Recovery, Auditing & Incident Management",
        "description": "Maintains cryptographic incident history, verifies baseline file hashes before restoration, and formulates recovery plans."
    }
]

@router.get("")
def get_agents_status(db: Session = Depends(get_db)):
    """
    Returns live health, latency, throughput, and last decision for all five agents.
    """
    agents_status = []

    for meta in AGENTS_METADATA:
        name = meta["name"]
        
        # Aggregates from DB
        completed_tasks = db.query(AgentExecution).filter(AgentExecution.agent_name == name).count()
        avg_time = db.query(func.avg(AgentExecution.execution_time)).filter(AgentExecution.agent_name == name).scalar() or 0.0
        
        # Last execution record
        last_exec = db.query(AgentExecution).filter(AgentExecution.agent_name == name).order_by(desc(AgentExecution.created_at)).first()
        
        agents_status.append({
            "name": name,
            "role": meta["role"],
            "description": meta["description"],
            "status": "ONLINE",
            "completed_tasks": completed_tasks,
            "avg_latency_ms": round(float(avg_time) * 1000.0, 1),
            "last_active": last_exec.created_at.isoformat() if last_exec else None,
            "recent_decision": last_exec.output_summary if last_exec else "Standby - Waiting for scan ingestion."
        })

    return agents_status

@router.get("/activity")
def get_agents_activity_log(limit: int = 30, db: Session = Depends(get_db)):
    """
    Returns chronological audit trail of agent executions.
    """
    executions = db.query(AgentExecution).order_by(desc(AgentExecution.created_at)).limit(limit).all()
    return [
        {
            "id": e.id,
            "scan_id": e.scan_id,
            "agent_name": e.agent_name,
            "task_id": e.task_id,
            "status": e.status,
            "output_summary": e.output_summary,
            "execution_time_ms": round(e.execution_time * 1000, 1),
            "created_at": e.created_at
        }
        for e in executions
    ]
