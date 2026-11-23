# Testing & Verification Guide

The platform includes automated unit tests covering all core detectors, security safeguards, and multi-agent coordination.

## Running Test Suite

From the workspace root, run:

```powershell
py -m unittest backend/tests/test_ml_models.py backend/tests/test_detection.py backend/tests/test_api_scans.py backend/tests/test_hardening.py
```

`test_api_scans.py` and `test_hardening.py` create temporary SQLite databases,
quarantine directories, and restore directories, and disable the Groq call, so
they are isolated from local data and the network. `test_detection.py` still
writes to the real DB; back it up first if local data matters.

## Test Cases Breakdown

### 1. Email Detection Test Cases
- `test_legitimate_email`: Verifies standard business updates receive a SAFE score (< 20.0) and zero heuristic flags.
- `test_fake_bank_urgent_wire`: Verifies urgent credential harvesting emails trigger CRITICAL indicators.
- `test_sender_reply_to_mismatch`: Confirms detection of mismatched From and Reply-To domains.
- `test_suspicious_attachment`: Detects deceptive double extensions (`.pdf.exe`).

### 2. Website URL Test Cases
- `test_legitimate_website`: Validates legitimate domains pass cleanly.
- `test_typosquatting_website`: Detects brand impersonation (`paypa1-security-check.xyz`).
- `test_ssrf_protection_private_ip`: Verifies SSRF blocker halts access to RFC1918 private subnets (`192.168.1.1`).
- `test_ssrf_protection_metadata`: Verifies SSRF blocker rejects access to cloud metadata services (`169.254.169.254`).
- `test_url_userinfo_obfuscation`: Confirms detection of `@` userinfo deception tricks.

### 3. QR Code Test Cases
- `test_normal_text_qr`: Confirms safe classification for standard plaintext notes.
- `test_quishing_payment_intent`: Flags unauthorized payment solicitation URIs (`upi://pay`).

### 4. Quarantine & Vault Integrity
- `test_quarantine_integrity_verification`: Verifies cryptographic SHA-256 hash matching before file restoration is permitted.

### 5. API & Regression Test Cases
- `test_email_scan_accepts_json_body`: Confirms manual email scans accept a JSON body and return a scored result.
- `test_qr_manual_scan_accepts_json_body`: Confirms manual QR payload scans accept a JSON body.
- `test_qr_image_upload_is_json_serializable`: Uploads a generated QR image and confirms the response and persisted agent output contain no raw bytes.
- `test_file_agent_output_is_json_serializable`: Asserts the File Agent contract directly.
- `test_enforcer_quarantines_original_qr_bytes`: Confirms the Enforcer writes the actual uploaded QR image bytes to quarantine.

### 6. Security & Correctness Hardening
- `test_email_ml_features_use_body_preview`: Confirms email urgency/credential ML features are populated.
- `test_homoglyph_detection_and_false_positive`: Confirms homoglyph spoof detection and that `pineapple` is not flagged as `apple`.
- `test_restore_moves_file_and_sets_timestamp`: Confirms an authorized restore verifies the hash, moves the file out of quarantine, and records `restored_at`.
- `test_restore_rejects_disabled_integrity_check`: Confirms integrity verification cannot be bypassed.
- `test_pdf_report_escapes_untrusted_text`: Confirms malicious XML-like text cannot break PDF generation.
- `test_csv_export_escapes_formulas`: Confirms spreadsheet formula injection is neutralized.
- `test_settings_are_persisted`: Confirms settings survive a reload from `SystemSetting`.
- `test_auth_can_be_enforced`: Confirms `REQUIRE_AUTH=true` rejects anonymous access and accepts valid tokens.
- `test_orchestrator_survives_agent_failure`: Confirms a failing agent does not abort the pipeline.
- `test_enforcer_quarantines_real_email_attachment`: Confirms real MIME attachment bytes are quarantined.

## Full-system verification (running stack)

With the backend on `:8000` and Vite on `:5173`, run the smoke test:

```powershell
# From the repository root
powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1
powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1 -IncludeUnitTests
```

The first command exercises 16 live API checks (health, dashboard, agents, all
three scan modes including QR image upload, incidents, quarantine integrity,
reports CSV/PDF, settings, threat intel, auth). The second adds the Python unit and regression suite and restores the DB
afterwards. A fully working system reports
`RESULT: passed=17 failed=0` (or `16/0` without `-IncludeUnitTests`).

To point it at a different deployment:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1 -ApiBase "http://host:8000/api" -AnalystPassword "your-password"
```

## Manual UI verification matrix

| Page | Test case | Expected result |
|---|---|---|
| Overview | Load after a few scans | Stats/charts populate, no console errors |
| Email Scanner | Click **Load Phishing Sample** then scan | CRITICAL/HIGH with urgency/credential indicators |
| Email Scanner | Paste a benign email | SAFE/LOW |
| Email Scanner | Upload a `.eml` file | Scan completes, score shown |
| Website Scanner | Typosquat sample | BRAND/TYPOSQUATTING/HIGH_RISK_TLD indicators |
| Website Scanner | `http://192.168.1.1/admin` or metadata IP | SSRF_FORBIDDEN_TARGET, no outbound probe |
| QR Scanner | Paste UPI quishing payload | Payment + scam-note indicators, zero execution |
| QR Scanner | Upload a generated QR image | Decodes and scores; no 500 error |
| Threat Intel | After a CRITICAL scan | New blocklist entry appears |
| Agent Activity | Open page | 5 agents with timings and decisions |
| Incidents | Open detail, change status to CONTAINED | Update succeeds; action log added |
| Quarantine | Verify integrity | INTEGRITY_VERIFIED |
| Quarantine | Restore a quarantined file | File moves to `backend/storage/restored/`, `restored_at` set |
| Reports | Download PDF and CSV | PDF opens; CSV cells with `=`/`+`/`-`/`@` are prefixed with `'` |
| Settings | Change thresholds, save, restart backend | Values persist (SystemSetting) |
| Login | Sign in/out; enable `REQUIRE_AUTH=true` | Anonymous API calls return 401; token works |

## What else you can do with this project

- Add detectors: new phishing lexicons, DGA/entropy tuning, more QR payment schemes.
- Retrain a task-specific classifier with `py -m ml.url.train`,
  `py -m ml.qr.train`, or `py -m ml.email.train`; `py -m ml.training.train_models`
  trains all three and prints the train/test metrics summary. Their code and
  model artifacts are under matching task folders. Email training downloads
  the pinned dataset into the local Hugging Face cache; its source licenses
  should be reviewed before redistributing data or model artifacts.
- Wire real threat-intel feeds into `GET /api/threat-intel` and the blocklist.
- Enforce role-based access (admin / analyst / auditor) using the existing `role` column.
- Introduce Alembic migrations instead of `create_all` for schema changes.
- Add frontend tests (Vitest + React Testing Library or Playwright E2E).
- Code-split the frontend bundle (~835 kB) with lazy-loaded routes.
- Containerize with Docker and serve the built `dist/` behind a reverse proxy
  with an `/api` route; switch to PostgreSQL via `DATABASE_URL`.
- Add SOC workflow features: notifications (Slack/email webhooks), case notes,
  SLA timers, and analyst assignment.
