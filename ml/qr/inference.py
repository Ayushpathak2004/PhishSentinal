"""QR task inference input preparation and artifact locations."""

from pathlib import Path

from ml.qr.preprocessing import preprocess_qr_image

MODEL_PATH = Path(__file__).resolve().parent / "models" / "qr_quishing_detector.joblib"
METADATA_PATH = Path(__file__).resolve().parent / "models" / "qr_model_metadata.json"

__all__ = ["METADATA_PATH", "MODEL_PATH", "preprocess_qr_image"]
