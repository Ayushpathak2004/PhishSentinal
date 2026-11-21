"""
Train the fraud model on an external URL-feature CSV.

Maps the supplied dataset onto the project's fixed 15-feature contract, backs up
the existing synthetic model, and writes the retrained model + metadata.
"""

import json
import shutil
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    confusion_matrix,
    classification_report,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from ml.preprocessing.features import FEATURE_NAMES
from backend.app.utils.typosquatting import HIGH_VALUE_BRANDS, KNOWN_SHORTENERS

BASE_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BASE_DIR.parent
_DATASET_CANDIDATES = (
    BASE_DIR / "datasets" / "url_features_extracted1.csv",
    REPO_ROOT / "url_features_extracted1.csv",
)
DATASET_PATH = next((p for p in _DATASET_CANDIDATES if p.exists()), _DATASET_CANDIDATES[0])
MODEL_PATH = BASE_DIR / "models" / "fraud_detector.joblib"
METRICS_PATH = BASE_DIR / "models" / "model_metadata.json"
MAPPED_PATH = BASE_DIR / "datasets" / "external_mapped.csv"
BACKUP_DIR = BASE_DIR / "models" / "backups"

SENSITIVE_KEYWORDS = ("login", "signin", "verify", "secure", "wallet", "banking", "account", "update")
URGENCY_TERMS = ("urgent", "immediate", "suspended", "terminate", "action", "verify", "expire")
HARVEST_TERMS = ("password", "login", "verify", "credential", "account", "banking")


def _host_from_url(url: str) -> str:
    try:
        from urllib.parse import urlparse

        return (urlparse(url if "://" in url else "https://" + url).hostname or "").lower()
    except Exception:
        return ""


def map_to_features(df: pd.DataFrame) -> pd.DataFrame:
    """Map the external CSV columns to the fixed FEATURE_NAMES order."""
    out = pd.DataFrame(index=df.index)

    urls = df["URL"].astype(str)
    hosts = urls.map(_host_from_url)
    lower_urls = urls.str.lower()

    out["url_length"] = df["url_length"]
    out["domain_length"] = df["domain_name_length"]
    out["num_dots"] = df["dot_count"]
    out["num_hyphens"] = df["has_hyphen_in_domain"]  # binary flag only
    out["has_ip"] = df["has_ip_address"]
    out["has_at_symbol"] = lower_urls.str.contains("@", regex=False).astype(int)
    out["domain_entropy"] = df["url_entropy"]  # URL entropy, not domain entropy
    out["is_shortener"] = hosts.map(
        lambda h: int(any(s in h for s in KNOWN_SHORTENERS)) if h else 0
    )
    out["has_sensitive_keyword"] = lower_urls.map(
        lambda u: int(any(k in u for k in SENSITIVE_KEYWORDS))
    )
    out["has_brand_mention"] = hosts.map(
        lambda h: int(any(b in h and h != b for b in HIGH_VALUE_BRANDS)) if h else 0
    )
    out["urgency_count"] = lower_urls.map(lambda u: sum(t in u for t in URGENCY_TERMS))
    out["credential_harvest_count"] = lower_urls.map(lambda u: sum(t in u for t in HARVEST_TERMS))
    out["sender_reply_mismatch"] = 0  # not available in a URL-only dataset
    out["has_executable_attachment"] = df["suspicious_file_extension"]
    out["dmarc_spf_failure"] = 0  # not available in a URL-only dataset

    return out[FEATURE_NAMES].fillna(0)


def main():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    raw = pd.read_csv(DATASET_PATH)
    raw = raw.dropna(subset=["ClassLabel"]).copy()
    raw["ClassLabel"] = raw["ClassLabel"].astype(int)

    X = map_to_features(raw)
    y = raw["ClassLabel"]

    print(f"Loaded {len(raw)} labelled rows from {DATASET_PATH.name}")
    print("Class distribution:", y.value_counts().sort_index().to_dict())

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=100,
        max_depth=12,
        random_state=42,
        n_jobs=-1,
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]

    metrics = {
        "accuracy": float(accuracy_score(y_test, y_pred)),
        "precision": float(precision_score(y_test, y_pred, zero_division=0)),
        "recall": float(recall_score(y_test, y_pred, zero_division=0)),
        "f1_score": float(f1_score(y_test, y_pred, zero_division=0)),
        "confusion_matrix": confusion_matrix(y_test, y_pred).tolist(),
        "roc_auc": float(roc_auc_score(y_test, y_proba)),
    }

    importances = {
        name: float(round(imp, 4))
        for name, imp in zip(FEATURE_NAMES, clf.feature_importances_)
    }
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    # Back up the existing synthetic model before overwriting it.
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for path in (MODEL_PATH, METRICS_PATH):
        if path.exists():
            shutil.copy2(path, BACKUP_DIR / f"{stamp}_{path.name}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    mapped = X.copy()
    mapped["ClassLabel"] = y
    mapped.to_csv(MAPPED_PATH, index=False)

    import joblib

    joblib.dump(clf, MODEL_PATH)

    metadata = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "features": FEATURE_NAMES,
        "metrics": {k: (round(v, 4) if isinstance(v, float) else v) for k, v in metrics.items()},
        "feature_importances": sorted_importances,
        "dataset_samples": len(raw),
        "dataset_source": DATASET_PATH.name,
        "class_distribution": {str(k): int(v) for k, v in y.value_counts().sort_index().items()},
        "test_split": 0.2,
        "notes": (
            "Trained on an external URL dataset. Some of the 15 model features are not "
            "present in the source data and were derived from the URL or set to 0 "
            "(sender_reply_mismatch, dmarc_spf_failure); domain_entropy is approximated "
            "by url_entropy."
        ),
    }
    with open(METRICS_PATH, "w") as handle:
        json.dump(metadata, handle, indent=2)

    print("\n=== External-dataset training complete ===")
    print(f"Accuracy :  {metrics['accuracy'] * 100:.2f}%")
    print(f"Precision:  {metrics['precision'] * 100:.2f}%")
    print(f"Recall:     {metrics['recall'] * 100:.2f}%")
    print(f"F1 score:   {metrics['f1_score'] * 100:.2f}%")
    print(f"ROC AUC:    {metrics['roc_auc'] * 100:.2f}%")
    print("Confusion matrix:", metrics["confusion_matrix"])
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, digits=4, zero_division=0))
    print("Top features:", list(sorted_importances.items())[:5])
    print(f"\nModel saved to: {MODEL_PATH}")
    print(f"Metadata saved to: {METRICS_PATH}")


if __name__ == "__main__":
    main()
