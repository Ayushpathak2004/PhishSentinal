"""
Train the fraud model on an external URL-feature CSV.

Maps the supplied dataset onto the project's fixed 15-feature contract, backs up
the existing URL model, and writes the retrained URL model + metadata.
"""

import json
import shutil
from datetime import datetime
from pathlib import Path

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

from ml.preprocessing.features import FEATURE_NAMES, extract_features_from_scan

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "datasets" / "url_features_extracted1.csv"
MODEL_PATH = BASE_DIR / "models" / "url_fraud_detector.joblib"
METRICS_PATH = BASE_DIR / "models" / "url_model_metadata.json"
MAPPED_PATH = BASE_DIR / "datasets" / "external_mapped.csv"
BACKUP_DIR = BASE_DIR / "models" / "backups"

def map_to_features(df: pd.DataFrame) -> pd.DataFrame:
    """Extract training features with the same normalization used at inference."""
    urls = df["URL"].fillna("").astype(str)
    rows = [
        extract_features_from_scan("WEBSITE", {"url": url})
        for url in urls
    ]
    out = pd.DataFrame(rows, index=df.index, columns=FEATURE_NAMES)
    out["has_executable_attachment"] = pd.to_numeric(
        df["suspicious_file_extension"], errors="coerce"
    ).fillna(0)
    return out.fillna(0)


def map_source_labels(labels: pd.Series) -> pd.Series:
    """Map dataset labels (0=malicious, 1=benign) to model labels (1=malicious)."""
    source_labels = labels.astype(int)
    if set(source_labels.unique()) != {0, 1}:
        raise ValueError("URL dataset ClassLabel must contain both source labels 0 and 1.")
    return (source_labels == 0).astype(int)


def main():
    if not DATASET_PATH.exists():
        raise FileNotFoundError(f"Dataset not found: {DATASET_PATH}")

    raw = pd.read_csv(DATASET_PATH)
    raw = raw.dropna(subset=["ClassLabel"]).copy()
    raw["ClassLabel"] = raw["ClassLabel"].astype(int)
    source_labels = raw["ClassLabel"]

    X = map_to_features(raw)
    y = map_source_labels(source_labels)

    print(f"Loaded {len(raw)} labelled rows from {DATASET_PATH.name}")
    print("Source label distribution:", source_labels.value_counts().sort_index().to_dict())
    print("Model label distribution (1=malicious):", y.value_counts().sort_index().to_dict())

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

    def evaluate(features, labels):
        predictions = clf.predict(features)
        return {
            "accuracy": float(accuracy_score(labels, predictions)),
            "precision": float(precision_score(labels, predictions, zero_division=0)),
            "recall": float(recall_score(labels, predictions, zero_division=0)),
            "f1_score": float(f1_score(labels, predictions, zero_division=0)),
        }

    train_metrics = evaluate(X_train, y_train)
    test_metrics = evaluate(X_test, y_test)
    test_metrics["confusion_matrix"] = confusion_matrix(y_test, y_pred).tolist()
    test_metrics["roc_auc"] = float(roc_auc_score(y_test, y_proba))

    importances = {
        name: float(round(imp, 4))
        for name, imp in zip(FEATURE_NAMES, clf.feature_importances_)
    }
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    # Back up any existing URL model before replacing it.
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for path in (MODEL_PATH, METRICS_PATH):
        if path.exists():
            shutil.copy2(path, BACKUP_DIR / f"{stamp}_{path.name}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    mapped = X.copy()
    mapped["SourceClassLabel"] = source_labels
    mapped["ClassLabel"] = y
    mapped.to_csv(MAPPED_PATH, index=False)

    import joblib

    joblib.dump(clf, MODEL_PATH)

    metadata = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "features": FEATURE_NAMES,
        "metrics": {
            "train": {k: round(v, 4) for k, v in train_metrics.items()},
            "test": {
                k: (round(v, 4) if isinstance(v, float) else v)
                for k, v in test_metrics.items()
            },
        },
        "feature_importances": sorted_importances,
        "dataset_samples": len(raw),
        "dataset_source": DATASET_PATH.name,
        "class_distribution": {str(k): int(v) for k, v in y.value_counts().sort_index().items()},
        "source_class_distribution": {
            str(k): int(v) for k, v in source_labels.value_counts().sort_index().items()
        },
        "label_mapping": {
            "source": {"0": "malicious", "1": "benign"},
            "model": {"0": "benign", "1": "malicious"},
        },
        "test_split": 0.2,
        "trained_at": datetime.now().astimezone().isoformat(),
        "notes": (
            "URL features are derived using the same normalization as inference. "
            "Email-only features are zero for this URL dataset; the executable-file "
            "feature uses the source dataset's suspicious_file_extension field."
        ),
    }
    with open(METRICS_PATH, "w") as handle:
        json.dump(metadata, handle, indent=2)

    print("\n=== External-dataset training complete ===")
    print(f"Training accuracy : {train_metrics['accuracy'] * 100:.2f}%")
    print(f"Training precision: {train_metrics['precision'] * 100:.2f}%")
    print(f"Testing accuracy  : {test_metrics['accuracy'] * 100:.2f}%")
    print(f"Testing precision : {test_metrics['precision'] * 100:.2f}%")
    print(f"Testing recall    : {test_metrics['recall'] * 100:.2f}%")
    print(f"Testing F1 score  : {test_metrics['f1_score'] * 100:.2f}%")
    print(f"Testing ROC AUC   : {test_metrics['roc_auc'] * 100:.2f}%")
    print("Testing confusion matrix:", test_metrics["confusion_matrix"])
    print("\nClassification report:")
    print(classification_report(y_test, y_pred, digits=4, zero_division=0))
    print("Top features:", list(sorted_importances.items())[:5])
    print(f"\nModel saved to: {MODEL_PATH}")
    print(f"Metadata saved to: {METRICS_PATH}")
    return metadata


if __name__ == "__main__":
    main()
