import asyncio
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import qrcode
from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from backend.app.agents.enforcer_agent import EnforcerAgent
from backend.app.agents.file_agent import FileAgent
from backend.app.api.scans import router as scans_router
from backend.app.core.config import settings
from backend.app.database.session import Base, get_db
from backend.app.models.models import QuarantinedFile


def _make_qr_png(payload: str) -> bytes:
    qr = qrcode.QRCode(box_size=4, border=2)
    qr.add_data(payload)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")
    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


class ScanApiRegressionTests(unittest.TestCase):
    """
    Regression coverage for the JSON scan routes and QR image persistence bug.

    Uses a temporary SQLite database and quarantine directory so the real
    backend database is never touched.
    """

    def setUp(self):
        self._temp_dir = tempfile.TemporaryDirectory()
        temp_path = Path(self._temp_dir.name)
        self.quarantine_dir = temp_path / "quarantine"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)

        self.engine = create_engine(
            f"sqlite:///{temp_path / 'test.db'}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()

        def override_get_db():
            db = self.Session()
            try:
                yield db
            finally:
                db.close()

        self.app = FastAPI()
        self.app.include_router(scans_router, prefix="/api")
        self.app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(self.app)

        self._quarantine_patch = patch.object(
            settings, "QUARANTINE_DIR", self.quarantine_dir
        )
        self._quarantine_patch.start()

        # Keep regression tests offline and deterministic even when a local
        # backend/.env contains a Groq key.
        self._groq_patch = patch.object(settings, "GROQ_API_KEY", "")
        self._groq_patch.start()

    def tearDown(self):
        self._groq_patch.stop()
        self._quarantine_patch.stop()
        self.db.close()
        self.engine.dispose()
        self._temp_dir.cleanup()

    def test_email_scan_accepts_json_body(self):
        response = self.client.post(
            "/api/scan/email",
            json={
                "sender": "security@secure-chase-update.com",
                "subject": "Immediate action required: Unauthorized access detected",
                "body": "Your account has been suspended. Please enter your password within 24 hours.",
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["scan_type"], "EMAIL")
        self.assertGreaterEqual(body["risk_score"], 20.0)
        json.dumps(body)  # response must stay JSON-serializable

    def test_qr_manual_scan_accepts_json_body(self):
        response = self.client.post(
            "/api/scan/qr",
            json={
                "manual_content": (
                    "upi://pay?pa=scammer@okhdfc&pn=QuickRefund"
                    "&tn=Power%20bill%20overdue%20fine&am=2500"
                )
            },
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["scan_type"], "QR")
        self.assertGreaterEqual(body["risk_score"], 20.0)
        json.dumps(body)

    def test_qr_image_upload_is_json_serializable(self):
        image_bytes = _make_qr_png("MEETING-MEMO-12345")
        response = self.client.post(
            "/api/scan/qr",
            files={"file": ("qr_test.png", image_bytes, "image/png")},
        )
        self.assertEqual(response.status_code, 200, response.text)
        body = response.json()
        self.assertEqual(body["scan_type"], "QR")
        # The exact regression: raw bytes must not leak into persisted output.
        self.assertNotIn("raw_bytes", json.dumps(body))
        file_data = body["agent_outputs"]["file_agent"]["data"]
        self.assertEqual(len(file_data["attachments_metadata"]), 1)
        self.assertEqual(
            file_data["attachments_metadata"][0]["sha256"],
            file_data["hashes"]["sha256"],
        )

    def test_file_agent_output_is_json_serializable(self):
        image_bytes = _make_qr_png("SERIALIZATION-CHECK")
        output = asyncio.run(
            FileAgent.process(
                task_id="test-task",
                scan_type="QR",
                raw_input={"image_bytes": image_bytes, "filename": "qr.png"},
            )
        )
        json.dumps(output)

    def test_enforcer_quarantines_original_qr_bytes(self):
        raw_bytes = b"\x89PNG\r\n\x1a\nORIGINAL-QR-IMAGE-BYTES"
        file_output = {
            "data": {
                "scan_type": "QR",
                "attachments_metadata": [
                    {
                        "filename": "qr.png",
                        "size": len(raw_bytes),
                        "content_type": "image/png",
                    }
                ],
            }
        }
        policy_output = {
            "data": {
                "decision": "BLOCK_QUARANTINE",
                "action_label": "Block and quarantine",
            }
        }

        result = asyncio.run(
            EnforcerAgent.process(
                task_id="test-task",
                file_agent_output=file_output,
                policy_agent_output=policy_output,
                db=self.db,
                raw_input={"image_bytes": raw_bytes, "filename": "qr.png"},
            )
        )

        quarantined = result["data"]["quarantined_files"]
        self.assertEqual(len(quarantined), 1)
        record = (
            self.db.query(QuarantinedFile)
            .filter(QuarantinedFile.id == quarantined[0]["quarantine_id"])
            .first()
        )
        self.assertIsNotNone(record)
        self.assertEqual(Path(record.file_path).read_bytes(), raw_bytes)


if __name__ == "__main__":
    unittest.main()
