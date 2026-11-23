"""URL task inference inputs and artifact locations."""

from pathlib import Path
from typing import Any, Dict

import pandas as pd

from ml.preprocessing.features import FEATURE_NAMES, extract_features_from_scan

MODEL_PATH = Path(__file__).resolve().parent / "models" / "url_fraud_detector.joblib"
METADATA_PATH = Path(__file__).resolve().parent / "models" / "url_model_metadata.json"


def features_for_scan(scan_type: str, raw_analysis: Dict[str, Any]) -> pd.DataFrame:
    features = extract_features_from_scan(scan_type, raw_analysis)
    return pd.DataFrame([features], columns=FEATURE_NAMES)
