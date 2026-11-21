from datetime import datetime
from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field

# User & Auth
class UserBase(BaseModel):
    username: str
    email: str
    role: str = "analyst"

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(UserBase):
    id: str
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserResponse

# Scans
class EmailScanRequest(BaseModel):
    raw_content: Optional[str] = None
    sender: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None

class WebsiteScanRequest(BaseModel):
    url: str

class QRScanRequest(BaseModel):
    image_base64: Optional[str] = None
    manual_content: Optional[str] = None

class ThreatIndicatorSchema(BaseModel):
    indicator_type: str
    title: str
    description: str
    severity: str  # LOW, MEDIUM, HIGH, CRITICAL
    evidence: Optional[str] = None

class AgentTimelineEvent(BaseModel):
    agent_name: str
    task_id: str
    step_number: int
    status: str  # PENDING, RUNNING, SUCCESS, FAILED
    execution_time_ms: float
    summary: str
    details: Optional[Dict[str, Any]] = None

class ScanResponse(BaseModel):
    id: str
    scan_type: str
    input_reference: str
    risk_score: float
    risk_level: str
    confidence: float
    fraud_probability: float
    summary: str
    indicators: List[ThreatIndicatorSchema]
    recommended_action: str
    timeline: List[AgentTimelineEvent]
    agent_outputs: Dict[str, Any]
    incident_id: Optional[str] = None
    created_at: datetime

    class Config:
        from_attributes = True

# Dashboard
class DashboardStats(BaseModel):
    total_scans: int
    emails_analyzed: int
    websites_analyzed: int
    qr_analyzed: int
    threats_detected: int
    critical_threats: int
    files_quarantined: int
    incidents_resolved: int
    risk_distribution: Dict[str, int]
    recent_activity: List[Dict[str, Any]]

# Incidents
class IncidentResponse(BaseModel):
    id: str
    scan_id: Optional[str]
    title: str
    incident_type: str
    severity: str
    status: str
    assigned_action: Optional[str]
    potential_impact: str
    resolution_notes: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True

class IncidentUpdate(BaseModel):
    status: Optional[str] = None
    resolution_notes: Optional[str] = None
    assigned_action: Optional[str] = None

# Quarantine
class QuarantinedFileResponse(BaseModel):
    id: str
    scan_id: Optional[str]
    original_filename: str
    file_size: int
    file_hash: str
    quarantine_reason: str
    status: str
    restored_at: Optional[datetime]
    restored_by: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True

class RestoreFileRequest(BaseModel):
    authorized_by: str
    reason: str
    verify_integrity: bool = True

# Agent Status
class AgentStatusSchema(BaseModel):
    name: str
    role: str
    status: str  # ACTIVE, IDLE, BUSY
    completed_tasks: int
    success_rate: float
    avg_latency_ms: float
    last_active: Optional[datetime]
    recent_decision: Optional[str]

# Settings
class PolicySettingsSchema(BaseModel):
    threshold_low_max: int = 19
    threshold_moderate_max: int = 39
    threshold_high_max: int = 69
    threshold_critical_min: int = 70
    groq_api_key_configured: bool = False
    groq_model: str = "openai/gpt-oss-120b"
    auto_quarantine_enabled: bool = True
    auto_blocklist_enabled: bool = True
