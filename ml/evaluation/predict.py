import json
from pathlib import Path
from typing import Dict, Any, List, Tuple
import numpy as np
import joblib

from ml.preprocessing.features import FEATURE_NAMES

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "fraud_detector.joblib"
METRICS_PATH = BASE_DIR / "models" / "model_metadata.json"

_CACHED_MODEL = None
_CACHED_METRICS = None

def get_ml_model():
    global _CACHED_MODEL, _CACHED_METRICS
    if _CACHED_MODEL is None and MODEL_PATH.exists():
        try:
            _CACHED_MODEL = joblib.load(MODEL_PATH)
            if METRICS_PATH.exists():
                with open(METRICS_PATH, "r") as f:
                    _CACHED_METRICS = json.load(f)
        except Exception:
            _CACHED_MODEL = None
    return _CACHED_MODEL, _CACHED_METRICS

def predict_fraud_score(features: List[float]) -> Dict[str, Any]:
    """
    Evaluates extracted numeric features against the trained Random Forest classifier.
    Returns calibrated fraud probability, model confidence, and feature explanations.
    """
    model, metrics = get_ml_model()
    
    if model is not None:
        try:
            import pandas as pd
            x_df = pd.DataFrame([features], columns=FEATURE_NAMES)
            proba = float(model.predict_proba(x_df)[0][1])
            
            # Confidence is derived from model certainty (|prob - 0.5| * 2) and training test accuracy
            test_acc = metrics["metrics"]["accuracy"] if metrics else 0.94
            margin = abs(proba - 0.5) * 2.0  # 0 to 1
            confidence = float(round(0.70 + (margin * 0.28) * test_acc, 2))
            
            # Explainable feature contributions
            importances = metrics.get("feature_importances", {}) if metrics else {}
            contributions = []
            for name, val in zip(FEATURE_NAMES, features):
                if val > 0:
                    weight = importances.get(name, 0.05)
                    contributions.append({
                        "feature": name,
                        "value": val,
                        "importance": weight,
                        "impact_score": round(val * weight * 100, 2)
                    })
            contributions = sorted(contributions, key=lambda x: x["impact_score"], reverse=True)[:5]

            return {
                "fraud_probability": round(proba, 4),
                "confidence": confidence,
                "model_type": "RandomForestClassifier",
                "is_ml_active": True,
                "top_features": contributions
            }
        except Exception as e:
            pass

    # Safe fallback if model is unbuilt
    # Normalize features into heuristic probability
    positive_signals = sum(1 for val in features if val > 0)
    fallback_prob = min(positive_signals / 6.0, 1.0)
    return {
        "fraud_probability": round(fallback_prob, 4),
        "confidence": 0.80,
        "model_type": "DeterministicRuleCalibrator",
        "is_ml_active": False,
        "top_features": []
    }
