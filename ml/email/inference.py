"""Email classifier artifact locations and inference text preparation."""

from pathlib import Path

from ml.email.features import email_text_for_scan

MODEL_PATH = Path(__file__).resolve().parent / "models" / "email_phishing_detector.joblib"
METADATA_PATH = Path(__file__).resolve().parent / "models" / "email_model_metadata.json"


__all__ = ["METADATA_PATH", "MODEL_PATH", "email_text_for_scan"]
