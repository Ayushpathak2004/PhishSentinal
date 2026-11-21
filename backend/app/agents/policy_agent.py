import time
from typing import Dict, Any
from backend.app.core.config import settings

class PolicyAgent:
    """
    Agent 3: Policy Agent
    Purpose: Intelligent security decision-making and policy enforcement evaluation.
             Translates risk scores and threat telemetry into concrete, binding security actions.
    """
    AGENT_NAME = "Policy Agent"
    ROLE = "Security Policy & Decision Engine"

    @classmethod
    async def process(
        cls,
        task_id: str,
        risk_agent_output: Dict[str, Any],
        custom_thresholds: Dict[str, int] = None
    ) -> Dict[str, Any]:
        start_time = time.time()
        risk_data = risk_agent_output.get("data", {})
        score = risk_data.get("risk_score", 0.0)
        confidence = risk_data.get("confidence", 0.8)
        indicators = risk_data.get("indicators", [])

        # Thresholds
        thresh = custom_thresholds or {
            "low_max": settings.THRESHOLD_LOW_MAX,
            "moderate_max": settings.THRESHOLD_MODERATE_MAX,
            "high_max": settings.THRESHOLD_HIGH_MAX,
            "critical_min": settings.THRESHOLD_CRITICAL_MIN
        }

        # Determine decision & mandatory enforcement directives
        if score >= thresh["critical_min"]:
            action = "BLOCK_QUARANTINE"
            action_label = "Automated Containment & Quarantine"
            user_warning = "CRITICAL THREAT DETECTED: Automated containment active. Do not access or download."
            requires_human_approval_to_restore = True
            log_incident = True
            severity = "CRITICAL"
        elif score > thresh["moderate_max"]:
            action = "WARN_REVIEW"
            action_label = "High Warning & SOC Review"
            user_warning = "HIGH RISK: Strong phishing or deceptive indicators identified. Interaction strongly discouraged."
            requires_human_approval_to_restore = False
            log_incident = True
            severity = "HIGH"
        elif score > thresh["low_max"]:
            action = "CAUTION"
            action_label = "Cautionary Flag"
            user_warning = "MODERATE RISK: Verify sender and destination through an independent communication channel."
            requires_human_approval_to_restore = False
            log_incident = False
            severity = "MODERATE"
        else:
            action = "ALLOW"
            action_label = "Permitted - Normal Processing"
            user_warning = "No significant malicious indicators detected. Standard operational safeguards apply."
            requires_human_approval_to_restore = False
            log_incident = False
            severity = "LOW"

        # Financial impact assessment
        has_credential = any(ind.get("indicator_type") in ("CREDENTIAL_HARVESTING_INTENT", "SUSPICIOUS_LOGIN_PATH") for ind in indicators)
        has_payment = any("PAYMENT" in ind.get("indicator_type", "") for ind in indicators)
        
        if has_payment or has_credential:
            financial_risk = "HIGH_FINANCIAL_EXPOSURE"
            potential_impact = "CRITICAL" if score >= settings.THRESHOLD_CRITICAL_MIN else "HIGH"
        else:
            financial_risk = "STANDARD"
            potential_impact = severity

        execution_time = time.time() - start_time
        summary = (
            f"Policy Decision: {action} ({action_label}). "
            f"Evaluated against threshold criteria (Score: {score}). "
            f"Incident logging: {log_incident}, Financial exposure: {financial_risk}."
        )

        return {
            "agent_name": cls.AGENT_NAME,
            "role": cls.ROLE,
            "task_id": task_id,
            "status": "SUCCESS",
            "execution_time_ms": round(execution_time * 1000, 2),
            "summary": summary,
            "data": {
                "decision": action,
                "action_label": action_label,
                "user_warning": user_warning,
                "severity": severity,
                "log_incident": log_incident,
                "potential_impact": potential_impact,
                "financial_risk": financial_risk,
                "requires_approval_to_restore": requires_human_approval_to_restore,
                "thresholds_applied": thresh
            }
        }
