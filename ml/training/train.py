import json
import random
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
import joblib

from ml.preprocessing.features import FEATURE_NAMES

BASE_DIR = Path(__file__).resolve().parent.parent
DATASET_PATH = BASE_DIR / "datasets" / "training_dataset.csv"
MODEL_PATH = BASE_DIR / "models" / "fraud_detector.joblib"
METRICS_PATH = BASE_DIR / "models" / "model_metadata.json"

def generate_benchmark_dataset(num_samples: int = 1200) -> pd.DataFrame:
    """
    Generates a deterministic, reproducible benchmark dataset representing
    phishing, malicious URLs, scam QR payloads, and legitimate traffic.
    """
    random.seed(42)
    np.random.seed(42)
    records = []

    for i in range(num_samples):
        # 50% benign, 50% malicious
        is_fraud = 1 if i % 2 == 1 else 0
        
        if is_fraud:
            # Malicious / Phishing pattern distributions
            url_length = int(np.random.normal(75, 25))
            domain_length = int(np.random.normal(22, 6))
            num_dots = int(np.random.choice([2, 3, 4, 5], p=[0.2, 0.4, 0.3, 0.1]))
            num_hyphens = int(np.random.choice([0, 1, 2, 3], p=[0.2, 0.4, 0.3, 0.1]))
            has_ip = 1 if random.random() < 0.22 else 0
            has_at_symbol = 1 if random.random() < 0.15 else 0
            domain_entropy = float(np.random.normal(3.8, 0.4))
            is_shortener = 1 if random.random() < 0.28 else 0
            has_sensitive_keyword = 1 if random.random() < 0.72 else 0
            has_brand_mention = 1 if random.random() < 0.65 else 0
            urgency_count = int(np.random.choice([1, 2, 3, 4], p=[0.4, 0.35, 0.2, 0.05])) if random.random() < 0.75 else 0
            credential_harvest_count = int(np.random.choice([1, 2, 3], p=[0.5, 0.35, 0.15])) if random.random() < 0.68 else 0
            sender_reply_mismatch = 1 if random.random() < 0.55 else 0
            has_executable_attachment = 1 if random.random() < 0.32 else 0
            dmarc_spf_failure = 1 if random.random() < 0.62 else 0
        else:
            # Legitimate pattern distributions
            url_length = int(np.random.normal(28, 10))
            domain_length = int(np.random.normal(12, 4))
            num_dots = int(np.random.choice([1, 2], p=[0.7, 0.3]))
            num_hyphens = 0 if random.random() < 0.85 else 1
            has_ip = 0
            has_at_symbol = 0
            domain_entropy = float(np.random.normal(2.5, 0.3))
            is_shortener = 1 if random.random() < 0.05 else 0
            has_sensitive_keyword = 1 if random.random() < 0.10 else 0
            has_brand_mention = 0
            urgency_count = 0 if random.random() < 0.92 else 1
            credential_harvest_count = 0
            sender_reply_mismatch = 0
            has_executable_attachment = 0
            dmarc_spf_failure = 0 if random.random() < 0.95 else 1

        records.append({
            "url_length": max(url_length, 5),
            "domain_length": max(domain_length, 3),
            "num_dots": max(num_dots, 1),
            "num_hyphens": max(num_hyphens, 0),
            "has_ip": has_ip,
            "has_at_symbol": has_at_symbol,
            "domain_entropy": round(max(domain_entropy, 0.5), 2),
            "is_shortener": is_shortener,
            "has_sensitive_keyword": has_sensitive_keyword,
            "has_brand_mention": has_brand_mention,
            "urgency_count": urgency_count,
            "credential_harvest_count": credential_harvest_count,
            "sender_reply_mismatch": sender_reply_mismatch,
            "has_executable_attachment": has_executable_attachment,
            "dmarc_spf_failure": dmarc_spf_failure,
            "label": is_fraud
        })

    df = pd.DataFrame(records)
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(DATASET_PATH, index=False)
    print(f"Generated and saved dataset with {len(df)} samples to {DATASET_PATH}")
    return df

def train_and_evaluate_model():
    df = generate_benchmark_dataset(num_samples=1500)
    
    X = df[FEATURE_NAMES]
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    
    clf = RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42)
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    y_proba = clf.predict_proba(X_test)[:, 1]
    
    acc = float(accuracy_score(y_test, y_pred))
    prec = float(precision_score(y_test, y_pred))
    rec = float(recall_score(y_test, y_pred))
    f1 = float(f1_score(y_test, y_pred))
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    # Feature importances
    importances = {name: float(round(imp, 4)) for name, imp in zip(FEATURE_NAMES, clf.feature_importances_)}
    # Sort by importance
    sorted_importances = dict(sorted(importances.items(), key=lambda item: item[1], reverse=True))

    metadata = {
        "model_type": "RandomForestClassifier",
        "n_estimators": 100,
        "features": FEATURE_NAMES,
        "metrics": {
            "accuracy": round(acc, 4),
            "precision": round(prec, 4),
            "recall": round(rec, 4),
            "f1_score": round(f1, 4),
            "confusion_matrix": cm
        },
        "feature_importances": sorted_importances,
        "dataset_samples": len(df),
        "test_split": 0.2
    }
    
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(clf, MODEL_PATH)
    with open(METRICS_PATH, "w") as f:
        json.dump(metadata, f, indent=2)
        
    print("=== Model Training and Evaluation Complete ===")
    print(f"Accuracy:  {acc * 100:.2f}%")
    print(f"Precision: {prec * 100:.2f}%")
    print(f"Recall:    {rec * 100:.2f}%")
    print(f"F1 Score:  {f1 * 100:.2f}%")
    print("Top Features:", list(sorted_importances.items())[:5])
    return metadata

if __name__ == "__main__":
    train_and_evaluate_model()
