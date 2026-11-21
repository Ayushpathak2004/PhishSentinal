import time
from typing import Dict, Any, List

from ml.preprocessing.features import extract_features_from_scan
from ml.evaluation.predict import predict_fraud_score
from backend.app.services.groq_service import analyze_with_groq
from backend.app.core.config import settings

class RiskScoreAgent:
    """
    Agent 2: Risk Score Agent
    Purpose: Threat assessment and fraud probability estimation using a hybrid
             tri-layer detection engine (Rules + ML Inference + Groq Reasoning).
    """
    AGENT_NAME = "Risk Score Agent"
    ROLE = "Threat Assessment & Fraud Probability Estimation"

    @classmethod
    async def process(
        cls,
        task_id: str,
        file_agent_output: Dict[str, Any]
    ) -> Dict[str, Any]:
        start_time = time.time()
        file_data = file_agent_output.get("data", {})
        scan_type = file_data.get("scan_type", "UNKNOWN")
        raw_analysis = file_data.get("raw_analysis", {})
        
        # 1. Deterministic Rule Score & Indicators
        rule_score = float(raw_analysis.get("rule_score", 0.0))
        indicators = raw_analysis.get("indicators", [])

        # 2. Machine Learning Inference
        ml_features = extract_features_from_scan(scan_type, raw_analysis)
        ml_result = predict_fraud_score(ml_features)
        ml_prob = float(ml_result.get("fraud_probability", 0.0))
        ml_confidence = float(ml_result.get("confidence", 0.85))

        # 3. Hybrid Calibrated Score Synthesis
        # Weighting: 55% deterministic rule score, 45% ML probability scaled to 100
        combined_score = (rule_score * 0.55) + ((ml_prob * 100.0) * 0.45)
        # Cap score between 0 and 100
        combined_score = round(min(max(combined_score, 0.0), 100.0), 1)

        # Risk Classification — derived from the same configurable thresholds
        # used by PolicyAgent so labels and decisions can never disagree.
        if combined_score >= settings.THRESHOLD_CRITICAL_MIN:
            risk_level = "CRITICAL"
        elif combined_score > settings.THRESHOLD_MODERATE_MAX:
            risk_level = "HIGH"
        elif combined_score > settings.THRESHOLD_LOW_MAX:
            risk_level = "MODERATE"
        else:
            risk_level = "SAFE"

        # Explicit Uncertainty Handling
        # If no indicators triggered but domain is brand new or input is unverified, cap confidence
        if len(indicators) == 0:
            confidence = min(ml_confidence, 0.78)
            confidence_note = "No overt signatures observed. Baseline risk assigned with conservative confidence."
        else:
            confidence = min(max(ml_confidence, 0.82), 0.98)
            confidence_note = f"High confidence based on {len(indicators)} correlating heuristic signals."

        # 4. Groq Contextual Analysis Layer
        groq_result = await analyze_with_groq(
            scan_type=scan_type,
            subject_or_target=file_data.get("input_reference", ""),
            raw_content=file_data.get("raw_preview", ""),
            detected_indicators=indicators,
            preliminary_score=combined_score
        )

        execution_time = time.time() - start_time
        summary = (
            f"Assessed {risk_level} threat level (Score: {combined_score}/100, "
            f"Fraud Prob: {ml_prob:.2f}, Confidence: {confidence:.2f}). "
            f"Identified {len(indicators)} security indicators via Hybrid Rules+ML+LLM."
        )

        return {
            "agent_name": cls.AGENT_NAME,
            "role": cls.ROLE,
            "task_id": task_id,
            "status": "SUCCESS",
            "execution_time_ms": round(execution_time * 1000, 2),
            "summary": summary,
            "data": {
                "risk_score": combined_score,
                "risk_level": risk_level,
                "fraud_probability": round(ml_prob, 3),
                "confidence": round(confidence, 2),
                "confidence_note": confidence_note,
                "indicators": indicators,
                "rule_score": rule_score,
                "ml_analysis": ml_result,
                "groq_analysis": groq_result,
                "recommended_action": groq_result.get("recommended_mitigation", "Review findings.")
            }
        }
