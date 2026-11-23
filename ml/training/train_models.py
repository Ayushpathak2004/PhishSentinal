from ml.url.train import main as train_url_model
from ml.qr.train import main as train_qr_model
from ml.email.train import main as train_email_model


def _print_metrics_summary(url_metadata, qr_metadata, email_metadata):
    print("\n=== Training and Testing Metrics Summary ===")
    print(
        f"{'Model':<58} {'Train Accuracy':>15} {'Train Precision':>16} "
        f"{'Test Accuracy':>14} {'Test Precision':>15}"
    )
    for name, metadata in (
        ("Website / URL", url_metadata),
        ("QR / Quishing", qr_metadata),
        ("Email / phishing-spam", email_metadata),
    ):
        train_metrics = metadata["metrics"]["train"]
        test_metrics = metadata["metrics"]["test"]
        model_name = f"{name} ({metadata['model_type']})"
        print(
            f"{model_name:<58} "
            f"{train_metrics['accuracy'] * 100:>14.2f}% "
            f"{train_metrics['precision'] * 100:>15.2f}% "
            f"{test_metrics['accuracy'] * 100:>13.2f}% "
            f"{test_metrics['precision'] * 100:>14.2f}%"
        )


def main():
    print("Training task-specific classifiers...")
    url_metadata = train_url_model()
    qr_metadata = train_qr_model()
    email_metadata = train_email_model()
    _print_metrics_summary(url_metadata, qr_metadata, email_metadata)
    return {"url": url_metadata, "qr": qr_metadata, "email": email_metadata}


if __name__ == "__main__":
    main()
