"""Train the email phishing/spam text classifier from the pinned HF dataset."""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Tuple

import numpy as np
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.naive_bayes import MultinomialNB
from sklearn.pipeline import Pipeline

from ml.email.features import build_email_text

DATASET_ID = "puyang2025/seven-phishing-email-datasets"
DATASET_REVISION = "b7f3f8d99ebd4fd0af0a5afe027420e53f08d1a4"
BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "models" / "email_phishing_detector.joblib"
METADATA_PATH = BASE_DIR / "models" / "email_model_metadata.json"
BACKUP_DIR = BASE_DIR / "models" / "backups"


def _prepare_split(split: Any, split_name: str) -> Tuple[list, np.ndarray]:
    required_columns = {"text", "subject", "label"}
    columns = set(getattr(split, "column_names", []))
    if not required_columns.issubset(columns):
        raise ValueError(
            f"Email dataset {split_name!r} split is missing columns: "
            f"{sorted(required_columns - columns)}"
        )

    texts = [
        build_email_text(subject, body)
        for subject, body in zip(split["subject"], split["text"])
    ]
    labels = np.asarray(split["label"], dtype=np.int64)
    if not texts or len(texts) != len(labels):
        raise ValueError(f"Email dataset {split_name!r} split is empty or misaligned.")
    if not set(np.unique(labels)).issubset({0, 1}) or len(np.unique(labels)) != 2:
        raise ValueError("Email dataset labels must contain both classes 0 (ham) and 1 (phishing/spam).")
    return texts, labels


def _metrics(model: Pipeline, texts: list, labels: np.ndarray) -> Dict[str, float]:
    predictions = model.predict(texts)
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1_score": float(f1_score(labels, predictions, zero_division=0)),
    }


def main() -> Dict[str, Any]:
    try:
        from datasets import load_dataset
    except ImportError as exc:
        raise RuntimeError(
            "The `datasets` package is required for email training. "
            "Install dependencies with `python -m pip install -r backend/requirements.txt`."
        ) from exc

    print(f"Loading {DATASET_ID} at revision {DATASET_REVISION}...", flush=True)
    dataset = load_dataset(DATASET_ID, revision=DATASET_REVISION)
    if "train" not in dataset or "test" not in dataset:
        raise ValueError("Expected `train` and `test` splits in the email dataset.")

    train_texts, train_labels = _prepare_split(dataset["train"], "train")
    test_texts, test_labels = _prepare_split(dataset["test"], "test")
    if set(np.unique(train_labels)) != set(np.unique(test_labels)):
        raise ValueError("Email train and test splits must contain the same classes.")

    model = Pipeline([
        ("tfidf", TfidfVectorizer(
            lowercase=False,
            ngram_range=(1, 2),
            min_df=2,
            max_features=75_000,
            sublinear_tf=True,
            dtype=np.float32,
        )),
        ("classifier", MultinomialNB(alpha=0.1)),
    ])
    print(
        f"Fitting TF-IDF + MultinomialNB on {len(train_texts):,} training emails...",
        flush=True,
    )
    model.fit(train_texts, train_labels)
    print("Calculating training and held-out test metrics...", flush=True)
    train_metrics = _metrics(model, train_texts, train_labels)
    test_metrics = _metrics(model, test_texts, test_labels)

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for path in (MODEL_PATH, METADATA_PATH):
        if path.exists():
            shutil.copy2(path, BACKUP_DIR / f"{stamp}_{path.name}")

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    import joblib

    joblib.dump(model, MODEL_PATH)
    class_distribution = {
        str(label): int(count)
        for label, count in zip(*np.unique(train_labels, return_counts=True))
    }
    metadata = {
        "task": "Email phishing/spam classification",
        "model_type": "TfidfVectorizer + MultinomialNB",
        "features": ["subject", "text"],
        "positive_class": 1,
        "class_names": {"0": "benign/ham", "1": "phishing/spam"},
        "dataset_source": DATASET_ID,
        "dataset_revision": DATASET_REVISION,
        "dataset_samples": len(train_labels) + len(test_labels),
        "training_samples": len(train_labels),
        "test_samples": len(test_labels),
        "class_distribution": class_distribution,
        "test_class_distribution": {
            str(label): int(count)
            for label, count in zip(*np.unique(test_labels, return_counts=True))
        },
        "metrics": {
            "train": {key: round(value, 4) for key, value in train_metrics.items()},
            "test": {key: round(value, 4) for key, value in test_metrics.items()},
        },
        "trained_at": datetime.now().astimezone().isoformat(),
        "notes": (
            "Label 1 includes phishing and other spam/unwanted messages. The corpus "
            "combines historical datasets; it may contain PII and has mixed source "
            "licenses. URLs, email addresses, and long numbers are replaced with "
            "tokens before training. The supplied test split may still contain "
            "near-duplicates or related email threads."
        ),
    }
    with METADATA_PATH.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)

    print("\n=== Email Phishing/Spam Model ===")
    print(f"Dataset: {DATASET_ID} ({len(train_labels)} train, {len(test_labels)} test)")
    print(f"Training accuracy : {train_metrics['accuracy'] * 100:.2f}%")
    print(f"Training precision: {train_metrics['precision'] * 100:.2f}%")
    print(f"Testing accuracy  : {test_metrics['accuracy'] * 100:.2f}%")
    print(f"Testing precision : {test_metrics['precision'] * 100:.2f}%")
    print(f"Model saved to: {MODEL_PATH}")
    print(f"Metrics saved to: {METADATA_PATH}")
    return metadata


if __name__ == "__main__":
    main()
