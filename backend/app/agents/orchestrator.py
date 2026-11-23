import uuid
import time
from typing import Dict, Any, List
from sqlalchemy.orm import Session

from backend.app.models.models import Scan, ThreatIndicator, AgentExecution, User
from backend.app.agents.file_agent import FileAgent
from backend.app.agents.risk_score_agent import RiskScoreAgent
from backend.app.agents.policy_agent import PolicyAgent
from backend.app.agents.enforcer_agent import EnforcerAgent
from backend.app.agents.vault_keeper import VaultKeeper

class AgentOrchestrator:
    """
    Central Orchestrator: Coordinates the multi-agent cybersecurity pipeline.
    Maintains task IDs, logs agent executions to database, handles partial failures gracefully,
    and constructs verifiable end-to-end audit timelines.
    """

    @classmethod
    async def run_pipeline(
        cls,
        scan_type: str,
        raw_input: Dict[str, Any],
        db: Session
    ) -> Dict[str, Any]:
        task_id = str(uuid.uuid4())
        scan_id = str(uuid.uuid4())
        timeline = []
        agent_outputs = {}

        # Helper to log execution into database and timeline
        def record_agent_step(agent_name: str, step_num: int, output: Dict[str, Any]):
            exec_time = output.get("execution_time_ms", 0.0) / 1000.0
            timeline.append({
                "agent_name": agent_name,
                "task_id": task_id,
                "step_number": step_num,
                "status": output.get("status", "SUCCESS"),
                "execution_time_ms": output.get("execution_time_ms", 0.0),
                "summary": output.get("summary", ""),
                "details": output.get("data")
            })

            # DB persistence for AgentExecution
            try:
                db_exec = AgentExecution(
                    scan_id=scan_id,
                    agent_name=agent_name,
                    task_id=task_id,
                    status=output.get("status", "SUCCESS"),
                    input_summary=f"Task {task_id[:8]} - Step {step_num}",
                    output_summary=output.get("summary", "")[:250],
                    execution_time=exec_time,
                    details=output.get("data")
                )
                db.add(db_exec)
                db.commit()
            except Exception as e:
                db.rollback()
                print(f"Error logging agent execution: {e}")

        def error_output(agent_name: str, role: str, step_num: int, error: Exception) -> Dict[str, Any]:
            """JSON-serializable placeholder so one failed agent cannot abort the pipeline."""
            return {
                "agent_name": agent_name,
                "role": role,
                "task_id": task_id,
                "status": "ERROR",
                "execution_time_ms": 0.0,
                "summary": f"Agent failed at step {step_num}: {str(error)[:200]}",
                "data": {
                    "error": str(error)[:500],
                    "step_number": step_num,
                    "scan_type": scan_type,
                    "input_reference": str(raw_input.get("url") or raw_input.get("subject") or raw_input.get("filename") or "Target")[:490]
                }
            }

        # STEP 1: File Agent
        try:
            file_out = await FileAgent.process(task_id=task_id, scan_type=scan_type, raw_input=raw_input)
        except Exception as e:
            file_out = error_output(FileAgent.AGENT_NAME, FileAgent.ROLE, 1, e)
        # Private payloads (raw attachment bytes) are never persisted or
        # returned to the client — only passed to the Enforcer below.
        private_payload = file_out.pop("_private", None) or {}
        agent_outputs["file_agent"] = file_out
        record_agent_step(FileAgent.AGENT_NAME, 1, file_out)

        # STEP 2: Risk Score Agent
        try:
            risk_out = await RiskScoreAgent.process(
                task_id=task_id,
                file_agent_output=file_out,
                raw_input=raw_input,
            )
        except Exception as e:
            risk_out = error_output(RiskScoreAgent.AGENT_NAME, RiskScoreAgent.ROLE, 2, e)
        agent_outputs["risk_score_agent"] = risk_out
        record_agent_step(RiskScoreAgent.AGENT_NAME, 2, risk_out)

        # STEP 3: Policy Agent
        try:
            policy_out = await PolicyAgent.process(task_id=task_id, risk_agent_output=risk_out)
        except Exception as e:
            policy_out = error_output(PolicyAgent.AGENT_NAME, PolicyAgent.ROLE, 3, e)
        agent_outputs["policy_agent"] = policy_out
        record_agent_step(PolicyAgent.AGENT_NAME, 3, policy_out)

        # STEP 4: Enforcer Agent
        try:
            enforcer_out = await EnforcerAgent.process(
                task_id=task_id,
                file_agent_output=file_out,
                policy_agent_output=policy_out,
                db=db,
                raw_input=raw_input,
                private_payload=private_payload
            )
        except Exception as e:
            enforcer_out = error_output(EnforcerAgent.AGENT_NAME, EnforcerAgent.ROLE, 4, e)
        agent_outputs["enforcer_agent"] = enforcer_out
        record_agent_step(EnforcerAgent.AGENT_NAME, 4, enforcer_out)

        # STEP 5: Vault Keeper
        try:
            vault_out = await VaultKeeper.process(
                task_id=task_id,
                scan_id=scan_id,
                file_agent_output=file_out,
                risk_agent_output=risk_out,
                policy_agent_output=policy_out,
                enforcer_agent_output=enforcer_out,
                db=db
            )
        except Exception as e:
            vault_out = error_output(VaultKeeper.AGENT_NAME, VaultKeeper.ROLE, 5, e)
        agent_outputs["vault_keeper"] = vault_out
        record_agent_step(VaultKeeper.AGENT_NAME, 5, vault_out)

        # STEP 6: Save Scan Record in DB
        file_data = file_out.get("data", {})
        risk_data = risk_out.get("data", {})
        policy_data = policy_out.get("data", {})
        vault_data = vault_out.get("data", {})

        scan_record = Scan(
            id=scan_id,
            scan_type=scan_type,
            input_reference=file_data.get("input_reference", "Target")[:490],
            raw_content_preview=file_data.get("raw_preview", "")[:1000],
            risk_score=risk_data.get("risk_score", 0.0),
            risk_level=risk_data.get("risk_level", "SAFE"),
            confidence=risk_data.get("confidence", 0.8),
            fraud_probability=risk_data.get("fraud_probability", 0.0),
            summary=risk_data.get("groq_analysis", {}).get("risk_summary") or risk_out.get("summary", ""),
            full_result={
                "timeline": timeline,
                "agent_outputs": agent_outputs,
                "recommended_action": risk_data.get("recommended_action", ""),
                "incident_id": vault_data.get("incident_id")
            }
        )
        db.add(scan_record)

        # Record Threat Indicators
        indicators = risk_data.get("indicators", [])
        for ind in indicators:
            db_ind = ThreatIndicator(
                scan_id=scan_id,
                indicator_type=ind.get("indicator_type", "ANOMALY")[:48],
                title=ind.get("title", "Anomaly")[:190],
                description=ind.get("description", ""),
                severity=ind.get("severity", "MEDIUM"),
                evidence=str(ind.get("evidence", ""))[:500]
            )
            db.add(db_ind)

        db.commit()

        return {
            "id": scan_id,
            "scan_type": scan_type,
            "input_reference": file_data.get("input_reference", "Target"),
            "risk_score": risk_data.get("risk_score", 0.0),
            "risk_level": risk_data.get("risk_level", "SAFE"),
            "confidence": risk_data.get("confidence", 0.8),
            "fraud_probability": risk_data.get("fraud_probability", 0.0),
            "summary": scan_record.summary,
            "indicators": indicators,
            "recommended_action": risk_data.get("recommended_action", ""),
            "timeline": timeline,
            "agent_outputs": agent_outputs,
            "incident_id": vault_data.get("incident_id"),
            "created_at": scan_record.created_at
        }
