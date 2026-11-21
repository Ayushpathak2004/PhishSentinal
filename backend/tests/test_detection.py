import unittest
import os
from backend.app.detectors.email_detector import analyze_email_content
from backend.app.detectors.website_detector import analyze_website_url
from backend.app.detectors.qr_detector import analyze_qr_payload
from backend.app.utils.ssrf_protector import is_safe_url
from backend.app.agents.policy_agent import PolicyAgent
from backend.app.agents.vault_keeper import VaultKeeper
from backend.app.database.session import SessionLocal
from backend.app.models.models import QuarantinedFile
from backend.app.core.config import settings

class TestFraudDetectionPlatform(unittest.TestCase):

    def setUp(self):
        self.db = SessionLocal()

    def tearDown(self):
        self.db.close()

    # --- EMAIL TESTS ---
    def test_legitimate_email(self):
        res = analyze_email_content(
            sender="newsletter@acme-corp.com",
            subject="Quarterly Product Update and Team Highlights",
            body="Hello team, attached are the updates for Q3. Thanks for your hard work!"
        )
        self.assertLess(res["rule_score"], 20.0)
        self.assertEqual(len(res["indicators"]), 0)

    def test_fake_bank_urgent_wire(self):
        res = analyze_email_content(
            sender="security@secure-chase-update.com",
            subject="Immediate action required: Unauthorized access detected",
            body="Your account has been suspended. Please confirm your PIN and enter your password within 24 hours to restore access."
        )
        self.assertGreaterEqual(res["rule_score"], 50.0)
        types = [i["indicator_type"] for i in res["indicators"]]
        self.assertTrue(any("URGENCY" in t or "HARVESTING" in t for t in types))

    def test_sender_reply_to_mismatch(self):
        res = analyze_email_content(
            raw_content="From: Billing <billing@paypal.com>\nReply-To: refund-desk@evil-scammer.ru\nSubject: Invoice #89211\n\nPlease find your invoice."
        )
        types = [i["indicator_type"] for i in res["indicators"]]
        self.assertIn("SENDER_REPLY_TO_MISMATCH", types)
        self.assertGreaterEqual(res["rule_score"], 35.0)

    def test_suspicious_attachment(self):
        res = analyze_email_content(
            sender="hr@partner.com",
            subject="Contract Update",
            body="Review contract.",
            attachments_metadata=[{"filename": "contract_document.pdf.exe", "size": 25000}]
        )
        self.assertGreaterEqual(res["rule_score"], 40.0)
        types = [i["indicator_type"] for i in res["indicators"]]
        self.assertTrue(any("ATTACHMENT" in t for t in types))

    # --- WEBSITE TESTS ---
    def test_legitimate_website(self):
        res = analyze_website_url("https://www.wikipedia.org")
        self.assertLess(res["rule_score"], 20.0)

    def test_typosquatting_website(self):
        res = analyze_website_url("https://paypa1-security-check.xyz/login")
        self.assertGreaterEqual(res["rule_score"], 35.0)
        types = [i["indicator_type"] for i in res["indicators"]]
        self.assertTrue(any("TYPOSQUATTING" in t or "BRAND" in t or "TLD" in t for t in types))

    def test_ssrf_protection_private_ip(self):
        is_safe, reason, host = is_safe_url("http://192.168.1.1/admin")
        self.assertFalse(is_safe)
        self.assertIn("strictly blocked", reason)

    def test_ssrf_protection_metadata(self):
        is_safe, reason, host = is_safe_url("http://169.254.169.254/latest/meta-data/")
        self.assertFalse(is_safe)

    def test_url_userinfo_obfuscation(self):
        res = analyze_website_url("http://google.com@evil-attacker.ru/signin")
        self.assertGreaterEqual(res["rule_score"], 40.0)
        types = [i["indicator_type"] for i in res["indicators"]]
        self.assertIn("URL_USERINFO_OBFUSCATION", types)

    # --- QR TESTS ---
    def test_normal_text_qr(self):
        res = analyze_qr_payload(manual_content="Just a standard meeting memo note.")
        self.assertLess(res["rule_score"], 20.0)

    def test_quishing_payment_intent(self):
        res = analyze_qr_payload(manual_content="upi://pay?pa=scammer@okhdfc&pn=QuickRefund&tn=Power%20bill%20overdue%20fine&am=2500")
        self.assertEqual(res["content_type"], "PAYMENT_INSTRUCTION")
        self.assertGreaterEqual(res["rule_score"], 35.0)
        types = [i["indicator_type"] for i in res["indicators"]]
        self.assertTrue(any("PAYMENT" in t for t in types))

    def test_quarantine_integrity_verification(self):
        # Verify file verification in VaultKeeper
        demo_file = settings.QUARANTINE_DIR / "test_verify.bin"
        with open(demo_file, "wb") as f:
            f.write(b"SAMPLE_CONTENT_FOR_HASH_VERIFY")
        from backend.app.utils.security import compute_sha256
        sha = compute_sha256(b"SAMPLE_CONTENT_FOR_HASH_VERIFY")
        
        q_item = QuarantinedFile(
            original_filename="test_verify.bin",
            stored_filename="test_verify.bin",
            file_path=str(demo_file),
            file_size=len(b"SAMPLE_CONTENT_FOR_HASH_VERIFY"),
            file_hash=sha,
            quarantine_reason="Unit test verification",
            status="QUARANTINED"
        )
        self.db.add(q_item)
        self.db.commit()

        res = VaultKeeper.verify_and_restore_file(
            quarantine_id=q_item.id,
            authorized_by="Lead Analyst",
            reason="Verified test pass",
            db=self.db
        )
        self.assertTrue(res["success"])
        self.assertEqual(res["file_hash"], sha)

if __name__ == "__main__":
    unittest.main()
