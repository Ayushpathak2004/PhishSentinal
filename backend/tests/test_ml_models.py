import asyncio
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import AsyncMock, patch

import numpy as np
from PIL import Image

import ml.training.train_models as train_models
from backend.app.api.ml_metrics import router as ml_metrics_router
from backend.app.agents.risk_score_agent import RiskScoreAgent
from ml.email.features import build_email_text
from ml.evaluation.predict import predict_scan
from ml.preprocessing.qr_image import QR_IMAGE_SIZE, preprocess_qr_image


class _StubClassifier:
    classes_ = np.array([0, 1])

    def predict_proba(self, features):
        return np.array([[0.2, 0.8]])


class MlModelRoutingTests(unittest.TestCase):
    def test_combined_training_prints_metrics_for_each_task(self):
        url_metadata = {
            "model_type": "RandomForestClassifier",
            "metrics": {
                "train": {"accuracy": 0.9, "precision": 0.8},
                "test": {"accuracy": 0.85, "precision": 0.75},
            },
        }
        qr_metadata = {
            "model_type": "ExtraTreesClassifier",
            "metrics": {
                "train": {"accuracy": 0.95, "precision": 0.9},
                "test": {"accuracy": 0.8, "precision": 0.7},
            },
        }
        email_metadata = {
            "model_type": "TfidfVectorizer + MultinomialNB",
            "metrics": {
                "train": {"accuracy": 0.92, "precision": 0.91},
                "test": {"accuracy": 0.88, "precision": 0.87},
            },
        }
        output = io.StringIO()

        with (
            patch("ml.training.train_models.train_url_model", return_value=url_metadata),
            patch("ml.training.train_models.train_qr_model", return_value=qr_metadata),
            patch("ml.training.train_models.train_email_model", return_value=email_metadata),
            redirect_stdout(output),
        ):
            train_models.main()

        text = output.getvalue()
        self.assertIn("Training and Testing Metrics Summary", text)
        self.assertIn("Website / URL (RandomForestClassifier)", text)
        self.assertIn("90.00%", text)
        self.assertIn("75.00%", text)
        self.assertIn("QR / Quishing (ExtraTreesClassifier)", text)
        self.assertIn("Email / phishing-spam (TfidfVectorizer + MultinomialNB)", text)
        self.assertIn("92.00%", text)
        self.assertIn("87.00%", text)

    def test_website_scan_uses_url_classifier(self):
        with patch("ml.evaluation.predict._get_model") as get_model:
            get_model.return_value = (
                _StubClassifier(),
                {"model_type": "URLModel", "metrics": {"test": {"accuracy": 0.9}}},
            )
            result = predict_scan("WEBSITE", {"url": "https://example.com"})

        get_model.assert_called_once_with("url")
        self.assertTrue(result["is_ml_active"])
        self.assertEqual(result["fraud_probability"], 0.8)

    def test_uploaded_qr_image_uses_qr_classifier(self):
        image_buffer = io.BytesIO()
        Image.new("L", (20, 20), color=255).save(image_buffer, format="PNG")

        with patch("ml.evaluation.predict._get_model") as get_model:
            get_model.return_value = (
                _StubClassifier(),
                {"model_type": "QRModel", "metrics": {"test": {"accuracy": 0.9}}},
            )
            result = predict_scan(
                "QR",
                {"content_type": "TEXT"},
                {"image_bytes": image_buffer.getvalue()},
            )

        get_model.assert_called_once_with("qr")
        self.assertTrue(result["is_ml_active"])
        self.assertEqual(result["fraud_probability"], 0.8)

    def test_unreadable_qr_image_does_not_use_qr_classifier(self):
        with patch("ml.evaluation.predict._get_model") as get_model:
            result = predict_scan(
                "QR",
                {"content_type": "UNKNOWN_OR_UNREADABLE"},
                {"image_bytes": b"not-a-decodable-qr"},
            )

        get_model.assert_not_called()
        self.assertFalse(result["is_ml_active"])
        self.assertIn("image classifier is skipped", result["reason"])

    def test_email_scan_uses_email_classifier_only(self):
        with patch("ml.evaluation.predict._get_model") as get_model:
            get_model.return_value = (
                _StubClassifier(),
                {"model_type": "EmailModel", "metrics": {"test": {"accuracy": 0.9}}},
            )
            result = predict_scan(
                "EMAIL",
                {"subject": "Urgent", "body_preview": "Verify your account"},
            )

        get_model.assert_called_once_with("email")
        self.assertTrue(result["is_ml_active"])
        self.assertEqual(result["fraud_probability"], 0.8)

    def test_email_training_and_inference_normalize_identifiers(self):
        text = build_email_text(
            "Please verify",
            "Contact me at person@example.com, https://example.com/a and 555-123-4567",
        )

        self.assertIn("EMAILTOKEN", text)
        self.assertIn("URLTOKEN", text)
        self.assertIn("NUMTOKEN", text)
        self.assertNotIn("person@example.com", text)
        self.assertNotIn("https://example.com", text)

    def test_rules_only_scan_uses_rule_score_without_fabricated_probability(self):
        file_output = {
            "data": {
                "scan_type": "EMAIL",
                "raw_analysis": {"rule_score": 65, "indicators": [{"title": "rule hit"}]},
                "input_reference": "Email subject",
                "raw_preview": "",
            }
        }
        with (
            patch("ml.evaluation.predict._get_model", return_value=(None, None)),
            patch(
                "backend.app.agents.risk_score_agent.analyze_with_groq",
                new=AsyncMock(return_value={"recommended_mitigation": "Review"}),
            ),
        ):
            result = asyncio.run(RiskScoreAgent.process("task", file_output))

        self.assertEqual(result["data"]["risk_score"], 65)
        self.assertIsNone(result["data"]["fraud_probability"])
        self.assertFalse(result["data"]["ml_analysis"]["is_ml_active"])

    def test_qr_preprocessor_matches_training_input_shape(self):
        image_buffer = io.BytesIO()
        Image.new("L", (20, 20), color=255).save(image_buffer, format="PNG")

        features = preprocess_qr_image(image_buffer.getvalue())

        self.assertEqual(features.shape, (1, QR_IMAGE_SIZE * QR_IMAGE_SIZE))
        self.assertTrue(np.all(features == 1))

    def test_metrics_endpoint_reports_each_task_and_email_model_status(self):
        from fastapi import FastAPI
        from fastapi.testclient import TestClient

        app = FastAPI()
        app.include_router(ml_metrics_router, prefix="/api")
        response = TestClient(app).get("/api/ml/metrics")

        self.assertEqual(response.status_code, 200)
        models = {model["task"]: model for model in response.json()["models"]}
        self.assertEqual(set(models), {"url", "qr", "email"})
        email = models["email"]
        self.assertIn(email["status"], {"trained", "not_trained"})
        if email["status"] == "trained":
            self.assertEqual(
                email["dataset_source"],
                "puyang2025/seven-phishing-email-datasets",
            )
            self.assertIsNotNone(email["metrics"]["test"]["accuracy"])
            self.assertIsNotNone(email["metrics"]["test"]["precision"])
        else:
            self.assertIn("not been trained", email["reason"])


if __name__ == "__main__":
    unittest.main()
