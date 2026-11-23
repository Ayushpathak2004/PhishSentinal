import io
import json
import pickle
import shutil
import zipfile
from datetime import datetime
from pathlib import Path

import numpy as np
from sklearn.ensemble import ExtraTreesClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.model_selection import train_test_split

from ml.qr.preprocessing import QR_IMAGE_SIZE

BASE_DIR = Path(__file__).resolve().parent
DATASET_PATH = BASE_DIR / "datasets" / "QuishingDataset.zip"
MODEL_PATH = BASE_DIR / "models" / "qr_quishing_detector.joblib"
METRICS_PATH = BASE_DIR / "models" / "qr_model_metadata.json"
BACKUP_DIR = BASE_DIR / "models" / "backups"
MAX_PICKLE_BYTES = 100_000_000


class _NumpyArrayUnpickler(pickle.Unpickler):
    """Only allow the NumPy globals needed by the supplied array files."""

    def find_class(self, module, name):
        allowed = {
            ("numpy", "ndarray"): np.ndarray,
            ("numpy", "dtype"): np.dtype,
        }
        multiarray = getattr(np, "_core", None)
        if multiarray is None:
            multiarray = np.core
        allowed[("numpy.core.multiarray", "_reconstruct")] = multiarray.multiarray._reconstruct
        allowed[("numpy._core.multiarray", "_reconstruct")] = multiarray.multiarray._reconstruct
        if (module, name) in allowed:
            return allowed[(module, name)]
        raise pickle.UnpicklingError(f"Blocked pickle global: {module}.{name}")


def _read_dataset():
    if not DATASET_PATH.is_file():
        raise FileNotFoundError(f"Quishing dataset not found: {DATASET_PATH}")

    with zipfile.ZipFile(DATASET_PATH) as archive:
        image_info = archive.getinfo("qr_codes_29.pickle")
        label_info = archive.getinfo("qr_codes_29_labels.pickle")
        if image_info.file_size > MAX_PICKLE_BYTES or label_info.file_size > MAX_PICKLE_BYTES:
            raise ValueError("Quishing dataset arrays exceed the permitted size.")
        image_bytes = archive.read(image_info)
        label_bytes = archive.read(label_info)

    images = _NumpyArrayUnpickler(io.BytesIO(image_bytes)).load()
    labels = _NumpyArrayUnpickler(io.BytesIO(label_bytes)).load()
    if not isinstance(images, np.ndarray) or not isinstance(labels, np.ndarray):
        raise ValueError("Quishing dataset must contain NumPy image and label arrays.")
    if images.ndim != 3 or images.shape[1:] != (QR_IMAGE_SIZE, QR_IMAGE_SIZE):
        raise ValueError(f"Expected QR images shaped (samples, {QR_IMAGE_SIZE}, {QR_IMAGE_SIZE}).")
    if labels.ndim != 1 or len(labels) != len(images):
        raise ValueError("QR image and label counts do not match.")
    if not set(np.unique(labels)).issubset({0, 1}) or len(np.unique(labels)) != 2:
        raise ValueError("QR dataset labels must contain both binary classes 0 and 1.")
    if not np.isin(images, (0, 1)).all():
        raise ValueError("QR image values must be binary (0 or 1).")

    return images.reshape(len(images), -1).astype(np.uint8), labels.astype(np.uint8)


def _classification_metrics(model, features, labels):
    predictions = model.predict(features)
    return {
        "accuracy": float(accuracy_score(labels, predictions)),
        "precision": float(precision_score(labels, predictions, zero_division=0)),
        "recall": float(recall_score(labels, predictions, zero_division=0)),
        "f1_score": float(f1_score(labels, predictions, zero_division=0)),
    }


def main():
    features, labels = _read_dataset()
    x_train, x_test, y_train, y_test = train_test_split(
        features,
        labels,
        test_size=0.2,
        random_state=42,
        stratify=labels,
    )
    model = ExtraTreesClassifier(
        n_estimators=100,
        max_features="sqrt",
        min_samples_leaf=2,
        class_weight="balanced",
        n_jobs=-1,
        random_state=42,
    )
    model.fit(x_train, y_train)

    train_metrics = _classification_metrics(model, x_train, y_train)
    test_metrics = _classification_metrics(model, x_test, y_test)

    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    for path in (MODEL_PATH, METRICS_PATH):
        if path.exists():
            shutil.copy2(path, BACKUP_DIR / f"{stamp}_{path.name}")

    import joblib

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL_PATH)
    metadata = {
        "task": "QR quishing image classification",
        "model_type": "ExtraTreesClassifier",
        "features": "Flattened 69x69 binary QR image pixels",
        "positive_class": 1,
        "class_names": {"0": "benign", "1": "quishing"},
        "dataset_source": DATASET_PATH.name,
        "dataset_samples": int(len(labels)),
        "class_distribution": {
            str(label): int(count)
            for label, count in zip(*np.unique(labels, return_counts=True))
        },
        "test_split": 0.2,
        "metrics": {
            "train": {key: round(value, 4) for key, value in train_metrics.items()},
            "test": {key: round(value, 4) for key, value in test_metrics.items()},
        },
        "trained_at": datetime.now().astimezone().isoformat(),
        "notes": "Label 1 is treated as quishing; validate this mapping against the dataset's original documentation.",
    }
    with METRICS_PATH.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, indent=2)

    print("\n=== QR Quishing Model ===")
    print(f"Dataset: {DATASET_PATH.name} ({len(labels)} labeled images)")
    print(f"Training accuracy : {train_metrics['accuracy'] * 100:.2f}%")
    print(f"Training precision: {train_metrics['precision'] * 100:.2f}%")
    print(f"Testing accuracy  : {test_metrics['accuracy'] * 100:.2f}%")
    print(f"Testing precision : {test_metrics['precision'] * 100:.2f}%")
    print(f"Testing recall    : {test_metrics['recall'] * 100:.2f}%")
    print(f"Testing F1 score  : {test_metrics['f1_score'] * 100:.2f}%")
    print(f"Model saved to: {MODEL_PATH}")
    print(f"Metrics saved to: {METRICS_PATH}")
    return metadata


if __name__ == "__main__":
    main()
