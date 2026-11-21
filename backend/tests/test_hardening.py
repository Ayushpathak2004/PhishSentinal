import asyncio
import io
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, patch

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from ml.preprocessing.features import FEATURE_NAMES, extract_features_from_scan
from backend.app.agents.enforcer_agent import EnforcerAgent
from backend.app.agents.orchestrator import AgentOrchestrator
from backend.app.agents.vault_keeper import VaultKeeper
from backend.app.agents.file_agent import FileAgent
from backend.app.api.auth import get_current_user
from backend.app.api.reports import router as reports_router
from backend.app.api import settings as settings_api
from backend.app.core.config import settings
from backend.app.database.session import Base, get_db
from backend.app.models.models import (
    Incident,
    QuarantinedFile,
    Scan,
    SystemSetting,
    User,
    utcnow,
)
from backend.app.utils.security import compute_sha256, create_access_token
from backend.app.utils.typosquatting import analyze_domain_typosquatting


class HardeningTests(unittest.TestCase):
    def setUp(self):
        self._temp = tempfile.TemporaryDirectory()
        root = Path(self._temp.name)
        self.quarantine_dir = root / "quarantine"
        self.restore_dir = root / "restored"
        self.quarantine_dir.mkdir(parents=True, exist_ok=True)
        self.restore_dir.mkdir(parents=True, exist_ok=True)

        self.engine = create_engine(
            f"sqlite:///{root / 'hardening.db'}",
            connect_args={"check_same_thread": False},
        )
        Base.metadata.create_all(bind=self.engine)
        self.Session = sessionmaker(autocommit=False, autoflush=False, bind=self.engine)
        self.db = self.Session()

        def override_get_db():
            session = self.Session()
            try:
                yield session
            finally:
                session.close()

        self.app = FastAPI()
        self.app.include_router(reports_router, prefix="/api")
        self.app.dependency_overrides[get_db] = override_get_db
        self.client = TestClient(self.app)

        self._patches = [
            patch.object(settings, "QUARANTINE_DIR", self.quarantine_dir),
            patch.object(settings, "RESTORE_DIR", self.restore_dir),
            patch.object(settings, "GROQ_API_KEY", ""),
            patch.object(settings, "REQUIRE_AUTH", False),
        ]
        for p in self._patches:
            p.start()

    def tearDown(self):
        for p in reversed(self._patches):
            p.stop()
        self.db.close()
        self.engine.dispose()
        self._temp.cleanup()

    def test_email_ml_features_use_body_preview(self):
        features = extract_features_from_scan("EMAIL", {
            "subject": "Urgent action required",
            "body_preview": "Please enter your password within 24 hours.",
            "sender_domain": "evil.example",
            "reply_to": "other@example.org",
        })
        self.assertGreater(features[FEATURE_NAMES.index("urgency_count")], 0)
        self.assertGreater(features[FEATURE_NAMES.index("credential_harvest_count")], 0)
        self.assertEqual(features[FEATURE_NAMES.index("sender_reply_mismatch")], 1.0)

    def test_homoglyph_detection_and_false_positive(self):
        homoglyph_types = [i["type"] for i in analyze_domain_typosquatting("paypa1.com")]
        self.assertIn("HOMOGLYPH_BRAND_SPOOFING", homoglyph_types)

        benign_types = [i["type"] for i in analyze_domain_typosquatting("pineapple.com")]
        self.assertFalse(
            {"BRAND_IMPERSONATION", "TYPOSQUATTING", "HOMOGLYPH_BRAND_SPOOFING"} & set(benign_types)
        )

    def test_restore_moves_file_and_sets_timestamp(self):
        payload = b"ORIGINAL-PAYLOAD"
        source = self.quarantine_dir / "restore_test.bin"
        source.write_bytes(payload)
        record = QuarantinedFile(
            original_filename="restore_test.bin",
            stored_filename="restore_test.bin",
            file_path=str(source),
            file_size=len(payload),
            file_hash=compute_sha256(payload),
            quarantine_reason="test",
            status="QUARANTINED",
        )
        self.db.add(record)
        self.db.commit()

        result = VaultKeeper.verify_and_restore_file(
            quarantine_id=record.id,
            authorized_by="Lead Analyst",
            reason="False positive",
            db=self.db,
        )
        self.assertTrue(result["success"], result)
        self.assertFalse(source.exists())
        self.assertEqual(Path(result["restored_path"]).read_bytes(), payload)
        self.db.refresh(record)
        self.assertEqual(record.status, "RESTORED")
        self.assertIsNotNone(record.restored_at)

    def test_restore_rejects_disabled_integrity_check(self):
        payload = b"PAYLOAD"
        source = self.quarantine_dir / "no_verify.bin"
        source.write_bytes(payload)
        record = QuarantinedFile(
            original_filename="no_verify.bin",
            stored_filename="no_verify.bin",
            file_path=str(source),
            file_size=len(payload),
            file_hash=compute_sha256(payload),
            quarantine_reason="test",
            status="QUARANTINED",
        )
        self.db.add(record)
        self.db.commit()
        result = VaultKeeper.verify_and_restore_file(
            quarantine_id=record.id,
            authorized_by="Analyst",
            reason="test",
            db=self.db,
            verify_integrity=False,
        )
        self.assertFalse(result["success"])
        self.assertTrue(source.exists())

    def test_pdf_report_escapes_untrusted_text(self):
        scan = Scan(
            scan_type="WEBSITE",
            input_reference="evil.com/?a=1&b=<script>alert(1)</script>",
            risk_score=95.0,
            risk_level="CRITICAL",
            summary="Payload <b>bold</b> & raw & markup",
            full_result={},
        )
        self.db.add(scan)
        self.db.commit()
        response = self.client.get(f"/api/reports/{scan.id}/pdf")
        self.assertEqual(response.status_code, 200, response.text[:200])
        self.assertTrue(response.content.startswith(b"%PDF"))

    def test_csv_export_escapes_formulas(self):
        incident = Incident(
            title="=cmd|'/c calc'!A0",
            incident_type="EMAIL_FRAUD",
            severity="HIGH",
            status="OPEN",
        )
        self.db.add(incident)
        self.db.commit()
        response = self.client.get("/api/reports/export/csv")
        self.assertEqual(response.status_code, 200)
        self.assertIn("'=cmd", response.text)
        self.assertNotIn("\n=cmd", response.text)

    def test_settings_are_persisted(self):
        update = settings_api.SettingsUpdateSchema(threshold_low_max=25)
        response = settings_api.update_settings(update, db=self.db, _admin=None)
        self.assertTrue(response["success"])
        self.assertEqual(settings.THRESHOLD_LOW_MAX, 25)
        self.assertIsNotNone(
            self.db.query(SystemSetting).filter(SystemSetting.key == "threshold_low_max").first()
        )

        settings.THRESHOLD_LOW_MAX = 19
        settings_api.load_settings_from_db(self.db)
        self.assertEqual(settings.THRESHOLD_LOW_MAX, 25)
        settings.THRESHOLD_LOW_MAX = 19  # restore for other tests

    def test_auth_can_be_enforced(self):
        with patch.object(settings, "REQUIRE_AUTH", True):
            with self.assertRaises(Exception) as ctx:
                get_current_user(token=None, db=self.db)
            self.assertEqual(getattr(ctx.exception, "status_code", None), 401)

            user = User(
                username="tester",
                email="tester@example.com",
                password_hash="unused",
                role="analyst",
            )
            self.db.add(user)
            self.db.commit()
            token = create_access_token({"sub": user.id, "username": user.username, "role": user.role})
            self.assertEqual(get_current_user(token=token, db=self.db).id, user.id)

    def test_orchestrator_survives_agent_failure(self):
        with patch.object(FileAgent, "process", new=AsyncMock(side_effect=RuntimeError("boom"))):
            result = asyncio.run(
                AgentOrchestrator.run_pipeline("EMAIL", {"subject": "test", "body": "hi"}, self.db)
            )
        self.assertEqual(result["agent_outputs"]["file_agent"]["status"], "ERROR")
        self.assertIsNotNone(self.db.query(Scan).filter(Scan.id == result["id"]).first())

    def test_enforcer_quarantines_real_email_attachment(self):
        payload = b"MZ\x90\x00MALICIOUS-EXECUTABLE"
        file_output = {
            "data": {
                "scan_type": "EMAIL",
                "attachments_metadata": [
                    {"filename": "invoice.pdf.exe", "size": len(payload), "content_type": "application/octet-stream"}
                ],
            }
        }
        policy_output = {
            "data": {"decision": "BLOCK_QUARANTINE", "action_label": "Block and quarantine"}
        }
        result = asyncio.run(
            EnforcerAgent.process(
                task_id="test-task",
                file_agent_output=file_output,
                policy_agent_output=policy_output,
                db=self.db,
                private_payload={"attachment_bytes": {"invoice.pdf.exe": payload}},
            )
        )
        quarantined = result["data"]["quarantined_files"]
        self.assertEqual(len(quarantined), 1)
        record = (
            self.db.query(QuarantinedFile)
            .filter(QuarantinedFile.id == quarantined[0]["quarantine_id"])
            .first()
        )
        self.assertEqual(Path(record.file_path).read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
