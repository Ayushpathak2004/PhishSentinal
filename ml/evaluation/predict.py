import json
import logging
from typing import Any, Dict, List, Optional, Tuple

import joblib

from ml.email.inference import (
    METADATA_PATH as EMAIL_METADATA_PATH,
    MODEL_PATH as EMAIL_MODEL_PATH,
    email_text_for_scan,
)
from ml.qr.inference import (
    METADATA_PATH as QR_METADATA_PATH,
    MODEL_PATH as QR_MODEL_PATH,
    preprocess_qr_image,
)
from ml.url.inference import (
    FEATURE_NAMES,
    METADATA_PATH as URL_METADATA_PATH,
    MODEL_PATH as URL_MODEL_PATH,
    features_for_scan,
)

MODEL_CONFIG = {
    "url": {
        "model_path": URL_MODEL_PATH,
        "metadata_path": URL_METADATA_PATH,
    },
    "qr": {
        "model_path": QR_MODEL_PATH,
        "metadata_path": QR_METADATA_PATH,
    },
    "email": {
        "model_path": EMAIL_MODEL_PATH,
        "metadata_path": EMAIL_METADATA_PATH,
    },
}

logger = logging.getLogger(__name__)
_MODEL_CACHE: Dict[str, Any] = {}
_MODEL_ERRORS: Dict[str, str] = {}


def _read_metadata(task: str) -> Optional[Dict[str, Any]]:
    config = MODEL_CONFIG[task]
    path = config["metadata_path"]
    if not path.is_file():
        return None
    try:
        with path.open("r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError) as exc:
        logger.exception("Could not read %s model metadata at %s", task, path)
        _MODEL_ERRORS[task] = f"Model metadata could not be read: {exc}"
        return None


def _get_model(task: str) -> Tuple[Any, Optional[Dict[str, Any]]]:
    if task not in _MODEL_CACHE:
        config = MODEL_CONFIG[task]
        model_path = config["model_path"]
        if not model_path.is_file():
            return None, _read_metadata(task)
        try:
            _MODEL_CACHE[task] = joblib.load(model_path)
        except Exception as exc:
            logger.exception("Could not load %s classifier from %s", task, model_path)
            _MODEL_CACHE[task] = None
            _MODEL_ERRORS[task] = f"Model could not be loaded: {exc}"
    return _MODEL_CACHE[task], _read_metadata(task)


def _unavailable(task: str, reason: str) -> Dict[str, Any]:
    return {
        "fraud_probability": None,
        "confidence": 0.0,
        "model_type": f"{task.upper()} model unavailable",
        "is_ml_active": False,
        "status": "unavailable",
        "reason": reason,
        "top_features": [],
    }


def _predict(task: str, features: Any) -> Dict[str, Any]:
    model, metadata = _get_model(task)
    if model is None:
        reason = _MODEL_ERRORS.get(task)
        if not reason:
            reason = (
                f"The {task.upper()} model has not been trained. "
                "Run `py -m ml.training.train_models`."
            )
        return _unavailable(task, reason)

    try:
        probabilities = model.predict_proba(features)[0]
        classes = list(model.classes_)
        if 1 not in classes:
            raise ValueError(f"{task.upper()} model is missing the positive class label 1.")
        fraud_probability = float(probabilities[classes.index(1)])
        test_accuracy = (
            metadata.get("metrics", {}).get("test", {}).get("accuracy", 0.0)
            if metadata
            else 0.0
        )
        margin = abs(fraud_probability - 0.5) * 2.0
        confidence = float(round(0.70 + (margin * 0.28 * test_accuracy), 2))
        contributions = []
        if task == "url" and metadata:
            importances = metadata.get("feature_importances", {})
            for name, value in zip(FEATURE_NAMES, features.iloc[0].tolist()):
                if value > 0:
                    weight = importances.get(name, 0.05)
                    contributions.append({
                        "feature": name,
                        "value": value,
                        "importance": weight,
                        "impact_score": round(value * weight * 100, 2),
                    })
            contributions.sort(key=lambda item: item["impact_score"], reverse=True)

        return {
            "fraud_probability": round(fraud_probability, 4),
            "confidence": confidence,
            "model_type": metadata.get("model_type", task.upper()) if metadata else task.upper(),
            "is_ml_active": True,
            "status": "active",
            "top_features": contributions[:5],
        }
    except Exception as exc:
        logger.exception("%s classifier prediction failed", task.upper())
        _MODEL_ERRORS[task] = f"Prediction failed: {exc}"
        return _unavailable(task, _MODEL_ERRORS[task])


def predict_scan(
    scan_type: str,
    raw_analysis: Dict[str, Any],
    raw_input: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Choose only the classifier trained for the scan's data type."""
    raw_input = raw_input or {}

    if scan_type == "WEBSITE":
        feature_frame = features_for_scan(scan_type, raw_analysis)
        return _predict("url", feature_frame)

    if scan_type == "QR":
        image_bytes = raw_input.get("image_bytes")
        if image_bytes:
            if raw_analysis.get("content_type") == "UNKNOWN_OR_UNREADABLE":
                return _unavailable(
                    "qr",
                    "The QR detector could not decode this image; the image classifier is skipped for unrecognized inputs.",
                )
            try:
                image_features = preprocess_qr_image(image_bytes)
            except Exception as exc:
                logger.exception("Could not prepare QR image for ML classification")
                return _unavailable("qr", f"QR image could not be prepared for ML classification: {exc}")
            return _predict("qr", image_features)

        if raw_analysis.get("content_type") == "WEB_URL":
            feature_frame = features_for_scan(scan_type, raw_analysis)
            return _predict("url", feature_frame)

        return _unavailable(
            "qr",
            "The QR image classifier requires an uploaded image; no trained model applies to this manual payload.",
        )

    if scan_type == "EMAIL":
        return _predict("email", [email_text_for_scan(raw_analysis, raw_input)])

    return _unavailable(scan_type.lower(), f"No classifier is configured for scan type {scan_type}.")


def get_model_metrics() -> Dict[str, Any]:
    """Return persisted training and test metrics for the UI and API."""
    models = []
    for task, display_name in (
        ("url", "Website / URL"),
        ("qr", "QR / Quishing"),
        ("email", "Email / phishing-spam"),
    ):
        config = MODEL_CONFIG[task]
        metadata = _read_metadata(task)
        model_exists = config["model_path"].is_file()
        metadata_exists = metadata is not None
        if task in _MODEL_ERRORS:
            status = "error"
        elif model_exists and metadata_exists:
            status = "trained"
        else:
            status = "not_trained"
        reason = _MODEL_ERRORS.get(task)
        if status == "not_trained" and not reason:
            reason = f"Model has not been trained. Run `py -m ml.training.train_models`."
        models.append({
            "task": task,
            "display_name": display_name,
            "status": status,
            "model_type": metadata.get("model_type") if metadata else None,
            "dataset_source": metadata.get("dataset_source") if metadata else None,
            "dataset_samples": metadata.get("dataset_samples") if metadata else None,
            "metrics": metadata.get("metrics") if metadata else None,
            "trained_at": metadata.get("trained_at") if metadata else None,
            "reason": reason,
        })

    return {"models": models}
