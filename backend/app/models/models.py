import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Integer, Float, Text, DateTime, ForeignKey, Boolean, JSON
from sqlalchemy.orm import relationship
from backend.app.database.session import Base

def generate_uuid():
    return str(uuid.uuid4())

def utcnow() -> datetime:
    """Naive UTC timestamp, compatible with SQLite's DateTime storage."""
    return datetime.now(timezone.utc).replace(tzinfo=None)

class User(Base):
    __tablename__ = "users"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    username = Column(String(50), unique=True, index=True, nullable=False)
    email = Column(String(100), unique=True, index=True, nullable=False)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default="analyst")  # admin, analyst, auditor
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

class Scan(Base):
    __tablename__ = "scans"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_type = Column(String(20), nullable=False)  # EMAIL, WEBSITE, QR
    input_reference = Column(String(500), nullable=False)  # Subject/URL/Image name
    raw_content_preview = Column(Text, nullable=True)
    risk_score = Column(Float, nullable=False, default=0.0)  # 0 to 100
    risk_level = Column(String(20), nullable=False)  # SAFE, LOW, MODERATE, HIGH, CRITICAL
    confidence = Column(Float, default=0.85)  # 0.0 to 1.0
    fraud_probability = Column(Float, default=0.0)  # 0.0 to 1.0
    summary = Column(Text, nullable=True)
    full_result = Column(JSON, nullable=True)  # Detailed serialized multi-agent results
    created_at = Column(DateTime, default=utcnow, index=True)
    
    # Relationships
    indicators = relationship("ThreatIndicator", back_populates="scan", cascade="all, delete-orphan")
    incident = relationship("Incident", back_populates="scan", uselist=False)

class ThreatIndicator(Base):
    __tablename__ = "threat_indicators"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=False, index=True)
    indicator_type = Column(String(50), nullable=False)  # e.g., TYPOSQUATTING, SUSPICIOUS_ATTACHMENT
    title = Column(String(200), nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String(20), nullable=False)  # LOW, MEDIUM, HIGH, CRITICAL
    evidence = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow)
    
    scan = relationship("Scan", back_populates="indicators")

class AgentExecution(Base):
    __tablename__ = "agent_executions"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), nullable=True, index=True)
    agent_name = Column(String(50), nullable=False, index=True)  # File Agent, Risk Score Agent, Policy Agent, Enforcer Agent, Vault Keeper
    task_id = Column(String(36), nullable=False, index=True)
    status = Column(String(20), nullable=False)  # SUCCESS, FAILED, RUNNING
    input_summary = Column(Text, nullable=True)
    output_summary = Column(Text, nullable=True)
    execution_time = Column(Float, default=0.0)  # in seconds
    details = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)

class Incident(Base):
    __tablename__ = "incidents"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), ForeignKey("scans.id"), nullable=True, unique=True)
    title = Column(String(255), nullable=False)
    incident_type = Column(String(50), nullable=False)  # PHISHING_EMAIL, MALICIOUS_URL, ROGUE_QR
    severity = Column(String(20), nullable=False)  # LOW, MODERATE, HIGH, CRITICAL
    status = Column(String(30), default="OPEN")  # OPEN, UNDER_REVIEW, CONTAINED, RESOLVED, FALSE_POSITIVE
    assigned_action = Column(String(100), nullable=True)  # QUARANTINE_FILE, BLOCKLIST_DOMAIN, USER_WARNING
    potential_impact = Column(String(50), default="MODERATE")  # LOW, MODERATE, HIGH, CRITICAL
    resolution_notes = Column(Text, nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    
    scan = relationship("Scan", back_populates="incident")
    action_logs = relationship("ActionLog", back_populates="incident", cascade="all, delete-orphan")

class QuarantinedFile(Base):
    __tablename__ = "quarantined_files"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    scan_id = Column(String(36), nullable=True, index=True)
    original_filename = Column(String(255), nullable=False)
    stored_filename = Column(String(255), nullable=False)
    file_path = Column(String(500), nullable=False)
    file_size = Column(Integer, default=0)
    file_hash = Column(String(64), nullable=False, index=True)  # SHA-256
    md5_hash = Column(String(32), nullable=True)
    quarantine_reason = Column(Text, nullable=False)
    status = Column(String(30), default="QUARANTINED")  # QUARANTINED, RESTORED, DELETED
    restored_at = Column(DateTime, nullable=True)
    restored_by = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=utcnow, index=True)

class ActionLog(Base):
    __tablename__ = "action_logs"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    incident_id = Column(String(36), ForeignKey("incidents.id"), nullable=True, index=True)
    agent_name = Column(String(50), nullable=True)
    action_type = Column(String(50), nullable=False)  # QUARANTINE, BLOCKLIST, ALERT, APPROVAL, RESTORE, REJECT
    action_details = Column(Text, nullable=False)
    performed_by = Column(String(50), default="SYSTEM_AGENT")
    reversible = Column(Boolean, default=True)
    reversed = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow, index=True)
    
    incident = relationship("Incident", back_populates="action_logs")

class BlocklistEntry(Base):
    __tablename__ = "blocklist_entries"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    entry_type = Column(String(20), nullable=False)  # URL, DOMAIN, IP, SENDER_EMAIL
    value = Column(String(500), nullable=False, unique=True, index=True)
    reason = Column(Text, nullable=False)
    severity = Column(String(20), default="HIGH")
    added_by = Column(String(50), default="ENFORCER_AGENT")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

class SystemSetting(Base):
    __tablename__ = "system_settings"
    
    id = Column(String(36), primary_key=True, default=generate_uuid)
    key = Column(String(50), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=False)
    description = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
