# AGENTS.md

Operating guide for AI coding agents working in this repository.

> **Read this file before changing code.** It documents the architecture, the
> commands that actually work on this machine, the contracts between the five
> agents, and the known defects that should not be accidentally made worse.
>
> Last verified: **2026-11-21** on Windows, Python **3.14.0**, Node **24.19.0**.

---

## 1. What this project is

**PhishSentinal** — a local, full-stack cybersecurity SaaS-style platform for detecting and responding to three attack vectors:

1. **Email fraud / phishing** — MIME parsing, BEC spoofing, `From`/`Reply-To` mismatch, SPF/DMARC failures, urgency and credential-harvesting language, dangerous attachments.
2. **Website fraud / malicious URLs** — SSRF protection, typosquatting and IDN/Punycode checks, high-risk TLDs, Shannon-entropy DGA detection, suspicious login paths, safe HTTP probe.
3. **QR code fraud / quishing** — OpenCV matrix decoding, UPI/crypto/payment directives, shortened URLs, shell-command payloads, zero-execution safety.

A sequential five-agent pipeline performs ingestion → risk scoring → policy → enforcement → audit/recovery. Results are persisted in SQLite and exposed through a FastAPI REST API and a React dashboard.

### Stack

| Layer | Technology |
|---|---|
| Backend | Python 3.11+ (verified 3.14), FastAPI, Pydantic v2, SQLAlchemy 2.0, Uvicorn |
| Database | SQLite by default (`backend/cybersecurity_platform.db`); PostgreSQL-ready schema |
| ML | scikit-learn `RandomForestClassifier`, 15 numeric features, joblib model |
| LLM | Groq API (`openai/gpt-oss-120b`) with deterministic local fallback |
| Frontend | React 19, TypeScript, Vite 8, Tailwind CSS 4, React Router 7, Axios, Recharts, Lucide |
| Security tooling | OpenCV, Pillow, dnspython, httpx, ReportLab, hashlib/hmac |

---

## 2. Current verified state

These checks were run after restoring the missing `ml/` package and frontend
source, fixing all confirmed runtime bugs, completing the security hardening,
renaming the product to PhishSentinal, and retraining the ML model on the
external URL dataset:

| Check | Command | Result |
|---|---|---|
| Backend imports | `py -c "import backend.app.main"` | **OK** |
| Full test suite | `py -m unittest backend/tests/test_detection.py backend/tests/test_api_scans.py backend/tests/test_hardening.py -v` | **27/27 pass** |
| ML model | `py -m ml.training.train_external` | **Retrained on 101,218 external rows**; accuracy 99.05%, precision 98.37%, recall 99.08%, F1 98.73% |
| ML prediction | sample `predict_fraud_score(...)` | **OK**, `is_ml_active: true` |
| Groq live call | `analyze_with_groq(...)` with local `backend/.env` | **OK**, `is_groq_active: true` |
| Frontend install | `npm install` in `frontend/` | **OK**, 0 vulnerabilities |
| Frontend production build | `npm run build` | **OK** (~835 kB JS chunk warning) |
| Frontend lint | `npm run lint` | **Warnings only**, no new warnings |
| API smoke tests | health/dashboard/agents/email-file | **OK** |

**All previously confirmed runtime bugs are fixed and regression-tested.**
Highlights: JSON scan routes, QR image upload, seeded quarantine hash, email ML
text features, real quarantine restore, PDF/CSV escaping, persistent settings,
configurable auth enforcement, SSRF hardening, and failure-tolerant pipeline.
See §12 for the few documented design limitations that remain.

---

## 3. Repository map

```
Majorproject2/
├── AGENTS.md                       ← this file
├── README.md                       ← human-facing quick start
├── url_features_extracted1.csv     ← user-supplied training dataset (101,218 URLs)
├── .gitignore
├── backend/
│   ├── .env.example                ← copy to backend/.env
│   ├── requirements.txt
│   ├── cybersecurity_platform.db   ← local SQLite DB (gitignored)
│   ├── app/
│   │   ├── main.py                 ← FastAPI app, routers, CORS, security headers, demo seed
│   │   ├── agents/
│   │   │   ├── orchestrator.py     ← runs the 5 agents, logs AgentExecution, saves Scan
│   │   │   ├── file_agent.py       ← Agent 1: ingestion / normalization / hashes
│   │   │   ├── risk_score_agent.py ← Agent 2: rules + ML + Groq
│   │   │   ├── policy_agent.py     ← Agent 3: threshold decision engine
│   │   │   ├── enforcer_agent.py   ← Agent 4: quarantine / blocklist / URL wrapping
│   │   │   └── vault_keeper.py     ← Agent 5: incident, audit, recovery, restore verification
│   │   ├── api/
│   │   │   ├── auth.py             ← register / login / OAuth2 token / me / auth dependencies
│   │   │   ├── scans.py            ← scan endpoints + scan history
│   │   │   ├── dashboard.py        ← dashboard stats / activity
│   │   │   ├── agents.py           ← agent status / execution log
│   │   │   ├── incidents.py        ← incident list / detail / update
│   │   │   ├── quarantine.py       ← quarantine list / verify / restore
│   │   │   ├── reports.py          ← summary / CSV / PDF
│   │   │   └── settings.py         ← persisted thresholds, Groq config, threat intel
│   │   ├── core/config.py          ← settings, paths, .env loading
│   │   ├── database/session.py     ← SQLAlchemy engine/session/Base
│   │   ├── detectors/
│   │   │   ├── email_detector.py
│   │   │   ├── website_detector.py
│   │   │   └── qr_detector.py
│   │   ├── models/models.py        ← 9 SQLAlchemy tables
│   │   ├── schemas/schemas.py      ← Pydantic request/response models
│   │   ├── services/groq_service.py← Groq call + sanitization + fallback
│   │   └── utils/
│   │       ├── security.py         ← PBKDF2 passwords, HMAC-signed tokens, hashes
│   │       ├── ssrf_protector.py   ← private-IP / metadata blocking
│   │       └── typosquatting.py    ← brand list, TLDs, shorteners, Levenshtein, homoglyphs, public suffixes
│   ├── storage/
│   │   ├── uploads/                ← reserved (currently unused)
│   │   ├── quarantine/             ← isolated files
│   │   ├── restored/               ← files released by an authorized restore
│   │   └── reports/                ← reserved (PDFs are streamed, not saved)
│   └── tests/test_detection.py     ← 12 unit tests
│       tests/test_api_scans.py     ← 5 API regression tests (isolated temp DB)
│       tests/test_hardening.py     ← 10 security/correctness regression tests
├── scripts/
│   └── smoke_test.ps1              ← 16 live API checks (+27 Python tests with -IncludeUnitTests)
├── docs/
│   ├── architecture.md
│   ├── methodology.md
│   ├── api_documentation.md
│   └── testing.md
├── ml/
│   ├── datasets/training_dataset.csv
│   ├── datasets/external_mapped.csv     ← mapped external training rows
│   ├── training/train_external.py      ← retrain on external dataset
│   ├── evaluation/predict.py       ← model loading, prediction, fallback
│   ├── models/fraud_detector.joblib
│   ├── models/model_metadata.json
│   ├── preprocessing/features.py   ← FEATURE_NAMES + extract_features_from_scan
│   └── training/train.py           ← synthetic dataset generator + training
└── frontend/
    ├── index.html
    ├── package.json / package-lock.json
    ├── vite.config.ts              ← dev proxy: /api → http://localhost:8000
    ├── tsconfig*.json
    ├── public/
    ├── src/
    │   ├── App.tsx                 ← routes
    │   ├── main.tsx
    │   ├── components/             ← Navbar, Sidebar, RiskScoreGauge, ThreatIndicatorsList, AgentTimeline
    │   ├── pages/                  ← 11 pages incl. LoginPage (see §9)
    │   ├── services/api.ts         ← Axios client
    │   └── types/index.ts          ← response types
    └── dist/                       ← generated build (gitignored)
```

> `frontend/node_modules/` and `frontend/dist/` are generated/ignored. Do not hand-edit `dist/`.

---

## 4. Quick start (Windows PowerShell)

Run all Python commands **from the repository root**. The backend uses absolute imports (`backend.app...`, `ml...`), so running `python backend/app/main.py` directly will fail.

### 4.1 Prerequisites

- Python 3.11+ (this machine has 3.14)
- Node.js 20+ (this machine has 24.19)
- `py` launcher available

### 4.2 Backend

```powershell
# From repo root
py -m venv venv
.\venv\Scripts\Activate.ps1

py -m pip install -r backend/requirements.txt

# Create local config (never commit .env)
Copy-Item backend\.env.example backend\.env
# Edit backend\.env if you have a Groq key; otherwise the app uses the local fallback.

# Optional: retrain the ML model (model + dataset are committed)
py -m ml.training.train

# Start API on http://localhost:8000
py -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

- Swagger: `http://localhost:8000/docs`
- ReDoc: `http://localhost:8000/redoc`
- Health: `http://localhost:8000/api/health`

The first import creates the SQLite schema and seeds demo data if the DB is empty. Default analyst login: **`analyst` / `CyberGuard2026!`**. Change this for anything beyond local demo use.

### 4.3 Frontend

```powershell
cd frontend
npm install
npm run dev        # http://localhost:5173, proxies /api to :8000
```

Production build and lint:

```powershell
npm run build      # tsc -b && vite build
npm run lint       # oxlint
```

### 4.4 Tests

```powershell
# From repo root
py -m unittest backend/tests/test_detection.py backend/tests/test_api_scans.py backend/tests/test_hardening.py -v
```

> `test_detection.py` is **not isolated**: it writes a `QuarantinedFile` row to
> the real `backend/cybersecurity_platform.db` and creates
> `backend/storage/quarantine/test_verify.bin`. Back up the DB before running if
> you care about local data:
>
> ```powershell
> Copy-Item backend\cybersecurity_platform.db "$env:TEMP\cyberguard_backup.db"
> py -m unittest backend/tests/test_detection.py -v
> Copy-Item "$env:TEMP\cyberguard_backup.db" backend\cybersecurity_platform.db
> ```
>
> `test_api_scans.py` and `test_hardening.py` are isolated (temporary DB,
> quarantine and restore directories) and can be run on their own without
> touching local data.

### 4.5 Resetting local data

Stop the backend, delete `backend/cybersecurity_platform.db`, and restart. `main.py` recreates the schema and seeds demo rows. Do not delete `backend/storage/quarantine/` blindly if you want to keep demo files.

---

## 5. Architecture

### 5.1 Request lifecycle

```
POST /api/scan/{email|website|qr}
        │
        ▼
backend/app/api/scans.py
        │  builds raw_input dict
        ▼
AgentOrchestrator.run_pipeline(scan_type, raw_input, db)
        │
        ├─ 1. FileAgent.process        → normalize, hash, run detector
        ├─ 2. RiskScoreAgent.process   → rule score + ML + Groq
        ├─ 3. PolicyAgent.process      → decision from thresholds
        ├─ 4. EnforcerAgent.process    → quarantine / blocklist (DB writes)
        ├─ 5. VaultKeeper.process      → incident + action logs (DB writes)
        │
        ├─ AgentExecution rows per step (JSON `details`)
        └─ Scan + ThreatIndicator rows at the end
        │
        ▼
ScanResponse-shaped dict → frontend
```

The orchestrator returns:

```json
{
  "id": "...",
  "scan_type": "EMAIL",
  "input_reference": "...",
  "risk_score": 88.5,
  "risk_level": "CRITICAL",
  "confidence": 0.96,
  "fraud_probability": 0.94,
  "summary": "...",
  "indicators": [],
  "recommended_action": "...",
  "timeline": [],
  "agent_outputs": { "file_agent": {}, "risk_score_agent": {}, "policy_agent": {}, "enforcer_agent": {}, "vault_keeper": {} },
  "incident_id": "...",
  "created_at": "..."
}
```

### 5.2 Agent contracts

Every agent returns:

```python
{
  "agent_name": str,
  "role": str,
  "task_id": str,
  "status": "SUCCESS" | "ERROR" | "FAILED",
  "execution_time_ms": float,
  "summary": str,
  "data": dict,          # MUST be JSON-serializable
}
```

| # | Agent | File | Consumes | Key `data` keys | Side effects |
|---|---|---|---|---|---|
| 1 | File Agent | `agents/file_agent.py` | `task_id`, `scan_type`, `raw_input` | `input_reference`, `raw_preview`, `extracted_urls`, `attachments_metadata`, `hashes`, `raw_analysis` | None |
| 2 | Risk Score Agent | `agents/risk_score_agent.py` | `file_agent_output` | `risk_score`, `risk_level`, `fraud_probability`, `confidence`, `confidence_note`, `indicators`, `rule_score`, `ml_analysis`, `groq_analysis`, `recommended_action` | None |
| 3 | Policy Agent | `agents/policy_agent.py` | `risk_agent_output` | `decision`, `action_label`, `user_warning`, `severity`, `log_incident`, `potential_impact`, `financial_risk`, `requires_approval_to_restore`, `thresholds_applied` | None |
| 4 | Enforcer Agent | `agents/enforcer_agent.py` | file + policy output, `db`, optional `raw_input`, optional `private_payload` | `decision_executed`, `actions_taken`, `quarantined_files`, `neutralized_urls` | Writes `BlocklistEntry`, `QuarantinedFile`, quarantine files; commits |
| 5 | Vault Keeper | `agents/vault_keeper.py` | all previous + `db` | `incident_id`, `damage_assessment`, `recovery_plan`, `audit_status` | Writes `Incident`, `ActionLog`; links quarantine rows; commits |

**Critical contract:** the orchestrator persists `output["data"]` into JSON columns
(`AgentExecution.details`, `Scan.full_result`). Never put `bytes`, `datetime`, ORM
objects, or other non-JSON values into an agent's `data`.

The QR path respects this by keeping upload bytes out of agent output entirely:
`FileAgent` records only filename/size/content type/SHA-256, and the orchestrator
passes the original `raw_input` to the Enforcer as a **non-persisted** channel.
The Enforcer uses `raw_input["image_bytes"]` when it needs to quarantine the
actual uploaded QR image. Email attachments use an additional non-persisted
`private_payload` channel from `FileAgent` so the real MIME attachment bytes are
quarantined instead of placeholders. Each agent step is wrapped in `try/except`,
so a failed agent records an `ERROR` output instead of aborting the pipeline.

### 5.3 Risk scoring

`RiskScoreAgent` combines three layers:

1. **Deterministic rules** — `rule_score` 0–100 from the detector.
2. **ML** — `RandomForestClassifier` probability 0–1 (`ml/evaluation/predict.py`); deterministic fallback if the model is missing.
3. **Groq** — explanation and mitigation; never overrides the numeric score.

Formula:

```text
combined = (rule_score * 0.55) + ((ml_probability * 100) * 0.45)
combined = round(clamp(combined, 0, 100), 1)
```

Hardcoded risk levels in `risk_score_agent.py`:

| Score | Level |
|---|---|
| `>= 70` | `CRITICAL` |
| `>= 40` | `HIGH` |
| `>= 20` | `MODERATE` |
| `< 20` | `SAFE` |

### 5.4 Policy decisions

`PolicyAgent` uses configurable thresholds (`backend/.env` / `config.py`):

| Score | Decision | Severity | Incident? |
|---|---|---|---|
| `>= THRESHOLD_CRITICAL_MIN` (70) | `BLOCK_QUARANTINE` | `CRITICAL` | Yes |
| `> THRESHOLD_MODERATE_MAX` (39) | `WARN_REVIEW` | `HIGH` | Yes |
| `> THRESHOLD_LOW_MAX` (19) | `CAUTION` | `MODERATE` | No |
| else | `ALLOW` | `LOW` | No |

`VaultKeeper` also creates an incident when `score >= 40` even if policy did not
request one. Note that risk **labels** are hardcoded while policy **decisions** are
configurable; if thresholds are changed, the two can disagree (§12.3).

### 5.5 Enforcement and storage

- Quarantine files go to `backend/storage/quarantine/` with names like
  `quarantine_<12hex>_<original_filename>`.
- Blocklist entries go to `blocklist_entries` (URLs, domains, IPs, sender emails).
- Suspicious URLs are returned wrapped as `/safe-redirect?target=...&blocked=true`;
  there is no actual redirect handler in the backend.
- Enforcement is intentionally **application-managed only**: never modify the
  Windows firewall, registry, hosts file, or external network settings.

### 5.6 Groq behavior

`backend/app/services/groq_service.py`:

- Reads `GROQ_API_KEY` / `GROQ_MODEL` from `backend/.env`.
- Sanitizes untrusted content with regexes and a 1,500-character cap.
- Requests strict JSON and validates it with `GroqAnalysisResult`.
- Falls back to deterministic local text if the key is missing, the call fails,
  or the response is non-200. Fallback sets `is_groq_active: false`.

---

## 6. Detection engines

### 6.1 Email (`detectors/email_detector.py`)

`analyze_email_content(raw_content, sender, subject, body, attachments_metadata)`:

- Parses raw MIME with `email.message_from_string(..., policy=default)`.
- Extracts `From`, `Reply-To`, `Subject`, `Received-SPF`,
  `Authentication-Results`, `DKIM-Signature`, `Return-Path`, body text, and attachments.
- Scores:
  - sender/reply-to domain mismatch: `+35`
  - typosquatting / brand indicators: `+40` each
  - SPF fail/softfail: `+25`
  - DMARC fail: `+30`
  - urgency phrases: `+15` each, capped at `+35`
  - credential-harvesting phrases: `+30`
  - double extension: `+45`
  - suspicious executable/script extension: `+40`
- Extracts up to 10 unique `http(s)` URLs from the body.
- Returns `rule_score`, `indicators`, `sender`, `sender_address`, `sender_domain`,
  `reply_to`, `subject`, `body_preview`, `attachments`, `extracted_urls`, `headers`.

### 6.2 Website (`detectors/website_detector.py`)

`analyze_website_url(url)`:

1. SSRF/private-IP guard via `utils/ssrf_protector.py`; blocked targets return
   `rule_score: 95` and a `SSRF_FORBIDDEN_TARGET` indicator.
2. Raw-IP hostname (`+45`).
3. More than 3 hostname labels (`+25`).
4. `@` userinfo obfuscation (`+40`).
5. Shannon entropy > 3.8 on a >10-char main domain (`+30`).
6. Typosquatting/brand checks (`+35` per indicator).
7. Sensitive path keywords such as `/login`, `/verify`, `/wallet` (`+20`).
8. Safe `HEAD` probe with a 1 s timeout, no redirect following; internal redirect
   destinations add `+50`.
9. Non-HTTPS URL (`+15`).

The probe verifies TLS (`verify=True`), never follows redirects automatically,
and never executes scripts or downloads payloads. A blocked SSRF target still
receives all lexical indicators; only the outbound probe is skipped.

### 6.3 QR (`detectors/qr_detector.py`)

`analyze_qr_payload(decoded_text, image_bytes, manual_content)`:

- Decodes with `cv2.QRCodeDetector` (Pillow → numpy → BGR), then grayscale and
  adaptive-threshold fallbacks.
- Payment schemes: `upi://`, `bitcoin:`, `ethereum:`, `solana:`, `lightning:`,
  `paypal.me/`, `venmo://` (`+35`).
- UPI `tn` note with scam keywords (`fine`, `penalty`, `power`, `electricity`,
  `lottery`, `gift`, `refund`, `kyc`, `overdue`) adds `+45`.
- Web URLs delegate to the website detector and merge indicators.
- Shortened URLs add `+25`.
- `wifi:` payloads are low severity.
- Shell/command payloads (`curl`, `wget`, `powershell`, `cmd.exe`, `rm -rf`,
  `eval(`) add `+85`.
- Unreadable QR returns `rule_score: 60` with a decode-failure indicator.
- **Never** executes payments or opens destinations.

### 6.4 ML (`ml/`)

- `FEATURE_NAMES` (order is the model contract):
  `url_length`, `domain_length`, `num_dots`, `num_hyphens`, `has_ip`,
  `has_at_symbol`, `domain_entropy`, `is_shortener`, `has_sensitive_keyword`,
  `has_brand_mention`, `urgency_count`, `credential_harvest_count`,
  `sender_reply_mismatch`, `has_executable_attachment`, `dmarc_spf_failure`.
- `extract_features_from_scan(scan_type, raw_analysis)` builds the 15-vector.
- `predict_fraud_score(features)` loads `ml/models/fraud_detector.joblib` once,
  returns probability, confidence, model type, and top feature contributions.
- If the model is missing or fails, it falls back to a deterministic
  `positive_signals / 6` heuristic with `is_ml_active: false`.
- `ml/training/train.py` still generates a **synthetic** 1,500-sample demo
  dataset (100% metrics, not real-world accuracy).
- `ml/training/train_external.py` retrains on `url_features_extracted1.csv`
  (101,218 labelled URLs). It maps the CSV onto the 15-feature contract, backs
  up the previous model into `ml/models/backups/`, and writes the new model +
  metadata. Current external-model metrics: accuracy 99.05%, precision 98.37%,
  recall 99.08%, F1 98.73%, ROC AUC 99.95%.
  - Note: `sender_reply_mismatch` and `dmarc_spf_failure` are set to 0 for this
    URL-only dataset; `domain_entropy` is approximated by `url_entropy`.

---

## 7. Data model (`backend/app/models/models.py`)

| Table | Purpose | Notes |
|---|---|---|
| `users` | analyst/admin/auditor accounts | UUID PK, PBKDF2 password hash, role, active flag |
| `scans` | every scan result | `full_result` JSON stores timeline + agent outputs |
| `threat_indicators` | per-scan findings | FK `scan_id`, cascade delete |
| `agent_executions` | per-agent audit log | `details` JSON, `execution_time` seconds |
| `incidents` | security incidents | one-to-one with `scans` via unique `scan_id` |
| `quarantined_files` | isolated file metadata | SHA-256 baseline, status, restore fields |
| `action_logs` | audit trail | FK `incidents.id`, agent/action details |
| `blocklist_entries` | enforced IoCs | unique `value`, active flag |
| `system_settings` | persisted thresholds / Groq config | written by `POST /api/settings`, loaded at startup |

- All IDs are UUID strings generated in Python.
- `Base.metadata.create_all(bind=engine)` runs at import. There is **no Alembic
  migration setup**. Schema changes require a dev DB reset or manual migration.
- Seed data (`main.py:seed_demo_data`) creates the `analyst` user, two demo scans,
  one incident, one blocklist entry, and a demo quarantined file.

---

## 8. API map

All routes are under `/api`. Swagger is the source of truth at runtime.
Protected routes depend on `get_current_user`: with `REQUIRE_AUTH=false` (demo
default) a missing token resolves to the seeded analyst; with `REQUIRE_AUTH=true`
a real bearer token is required. Auth, health, and docs are public.

### Auth (`api/auth.py`)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/auth/register` | Create user; public |
| `POST` | `/api/auth/login` | JSON credentials → HMAC-signed bearer token |
| `POST` | `/api/auth/token` | OAuth2 password-form flow used by Swagger authorize |
| `GET` | `/api/auth/me` | Current user |

### Scans (`api/scans.py`)

| Method | Path | Notes |
|---|---|---|
| `POST` | `/api/scan/email` | Accepts JSON body, multipart form fields, or an uploaded `.eml`/`.txt`/`.msg` file |
| `POST` | `/api/scan/website` | JSON `{ "url": "..." }` |
| `POST` | `/api/scan/qr` | Accepts JSON (`manual_content` / `image_base64`), multipart form fields, or an uploaded image |
| `GET` | `/api/scans` | Filters: `scan_type`, `risk_level`, `limit`, `offset` |
| `GET` | `/api/scans/{scan_id}` | Includes indicators and `full_result` |

### Dashboard (`api/dashboard.py`)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/dashboard/stats` | Counts, risk distribution, recent activity |
| `GET` | `/api/dashboard/activity?limit=` | Recent scans |

### Agents (`api/agents.py`)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/agents` | Five agents with task counts, average latency, last decision |
| `GET` | `/api/agents/activity?limit=` | Execution audit trail |

### Incidents (`api/incidents.py`)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/incidents` | Filters: `severity`, `status`, `incident_type`, `limit`, `offset` |
| `GET` | `/api/incidents/{id}` | Incident + scan + indicators + action logs |
| `PATCH` | `/api/incidents/{id}` | Update `status`, `resolution_notes`, `assigned_action`; writes an `ActionLog` |

### Quarantine (`api/quarantine.py`)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/quarantine` | Optional `status` filter |
| `GET` | `/api/quarantine/{id}/verify` | Re-hashes the file on disk against the baseline |
| `POST` | `/api/quarantine/{id}/restore` | Body: `authorized_by`, `reason`, `verify_integrity`; verifies hash then moves the file to `storage/restored/` and sets `restored_at` |

### Reports (`api/reports.py`)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/reports` | Executive summary metrics |
| `GET` | `/api/reports/export/csv` | CSV download of incidents |
| `GET` | `/api/reports/{scan_id}/pdf` | ReportLab PDF forensic report (streamed) |

### Settings / intel (`api/settings.py`)

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/settings` | Thresholds, Groq config status, masked key |
| `POST` | `/api/settings` | Admin-only; validates and persists thresholds/Groq config to `SystemSetting` |
| `GET` | `/api/threat-intel` | Active blocklist + static attack patterns |

### Health

| Method | Path | Notes |
|---|---|---|
| `GET` | `/api/health` | Status, version, `groq_configured`, engine description |

---

## 9. Frontend map

Routes are defined in `frontend/src/App.tsx`; navigation labels/icons are in
`frontend/src/components/Sidebar.tsx`.

| Route | Page | Purpose |
|---|---|---|
| `/` | `OverviewPage` | SOC dashboard, stats, charts, recent activity |
| `/email` | `EmailScannerPage` | Paste/upload email; sample buttons |
| `/website` | `WebsiteScannerPage` | URL scan with sample typosquat/SSRF cases |
| `/qr` | `QRScannerPage` | QR image upload or manual payload; zero-execution banner |
| `/intel` | `ThreatIntelPage` | Blocklist and attack-pattern directory |
| `/agents` | `AgentActivityPage` | Agent status, latency, execution log |
| `/incidents` | `IncidentManagementPage` | Incident list, status updates |
| `/quarantine` | `QuarantineVaultPage` | Quarantine list, verify, restore |
| `/reports` | `ReportsPage` | Summary, PDF/CSV downloads |
| `/settings` | `SettingsPage` | Thresholds and Groq configuration |
| `/login` | `LoginPage` | Bearer-token sign-in; token stored in `localStorage` |

Shared components: `Navbar`, `Sidebar`, `RiskScoreGauge`,
`ThreatIndicatorsList`, `AgentTimeline`.

API client: `frontend/src/services/api.ts` (`baseURL: '/api'`). A request
interceptor attaches `localStorage['phishsentinal_token']` as a bearer token when
present; `authApi` handles login/logout. Vite proxies `/api` to
`http://localhost:8000` in development (`vite.config.ts`). A production `dist/`
served without that proxy needs same-origin API routing or a reverse proxy.

Styling: Tailwind CSS 4 via `@tailwindcss/vite`, dark slate/cyan theme, no UI
component library. Charts use Recharts. Icons use `lucide-react`.

---

## 10. Conventions

### Backend

- Python 3.11+ style, type hints, `async def` for agent entry points.
- Use **absolute imports** from the repo root: `from backend.app...`, `from ml...`.
- Keep agent outputs JSON-serializable. No `bytes`, `datetime`, ORM instances, or
  numpy types in `data`.
- New detector: add to `backend/app/detectors/`, return a dict with at least
  `rule_score` and `indicators`. Indicator shape:
  `{indicator_type, title, description, severity, evidence}`.
- New agent: add to `backend/app/agents/`, call it from `orchestrator.py`, add its
  metadata to `api/agents.py:AGENTS_METADATA`, and record it via
  `record_agent_step`.
- New endpoint: create a router in `backend/app/api/`, include it in `main.py`
  under the `/api` prefix, add Pydantic schemas to `schemas.py`, and update
  `docs/api_documentation.md` plus the frontend client/types.
- Config: add fields to `backend/app/core/config.py` and document them in
  `backend/.env.example`. Never hardcode secrets.
- DB: models live in `models.py`. `create_all` does not alter existing tables.
  For schema changes, either reset the dev DB (and reseed) or add a real
  migration tool.
- Security invariants:
  - Keep the SSRF guard on every outbound URL path.
  - Keep the QR zero-execution rule (never initiate payments or navigation).
  - Keep enforcement non-invasive (no firewall/registry/hosts changes).
  - Sanitize untrusted content before LLM calls.
  - Escape untrusted text before ReportLab/HTML/CSV output.

### Frontend

- Add a page in `src/pages/`, a route in `App.tsx`, and a sidebar entry in
  `components/Sidebar.tsx`.
- Add API methods to `services/api.ts` and response types to `types/index.ts`.
  There is no shared schema/codegen; keep backend and frontend shapes in sync.
- Prefer local `useState`/`useEffect`; there is no Redux/global store in use.
- Follow the existing Tailwind dark-slate/cyan visual language and `lucide-react`
  icons.
- `npm run build` must pass. Do not add new lint warnings if avoidable.
- Do not edit `dist/` by hand; it is generated by `npm run build`.

### ML

- `FEATURE_NAMES` order is the model contract. Do not reorder or rename without
  retraining and updating `model_metadata.json`.
- Keep `extract_features_from_scan` aligned with the keys each detector returns.
- Retrain with `py -m ml.training.train`; this rewrites the dataset, joblib model,
  and metadata.
- The model is synthetic-data trained. Do not claim production accuracy.

### Tests

- Add detector tests to `backend/tests/test_detection.py`; API/route tests to
  `backend/tests/test_api_scans.py`; security/hardening tests to
  `backend/tests/test_hardening.py` (or new modules).
- `test_detection.py` hits the real SQLite DB and quarantine directory. Back up
  the DB before running if local data matters.
- `test_api_scans.py` is isolated: it builds a temporary SQLite DB, a temporary
  quarantine directory, and patches the Groq key off so tests stay offline.
  Follow that pattern for new API tests.
- Coverage gap: the orchestrator, auth, ML training, and Groq service are not
  covered. Add coverage when changing those areas.

---

## 11. Configuration

`backend/app/core/config.py` loads `backend/.env` via `python-dotenv`.

| Variable | Default | Notes |
|---|---|---|
| `PROJECT_NAME` | `PhishSentinal` | API title |
| `VERSION` | `1.0.0` | API version |
| `ENVIRONMENT` | `development` | `production` requires an explicit `SECRET_KEY` |
| `SECRET_KEY` | built-in dev fallback | **Change in any real deployment** |
| `ACCESS_TOKEN_EXPIRE_MINUTES` | `1440` (24 h) | Token lifetime |
| `REQUIRE_AUTH` | `false` | `true` enforces bearer tokens on all protected routes |
| `DEFAULT_ANALYST_PASSWORD` | `CyberGuard2026!` | Seeded demo analyst password |
| `MAX_UPLOAD_BYTES` | `5 MB` | Request body size cap |
| `RATE_LIMIT_PER_MINUTE` | `30` | Fixed-window limit for `/api/scan/*` per client |
| `GROQ_API_KEY` | empty | Empty → deterministic fallback |
| `GROQ_MODEL` | `openai/gpt-oss-120b` | Groq model |
| `DATABASE_URL` | `sqlite:///backend/cybersecurity_platform.db` | PostgreSQL URL supported |
| `THRESHOLD_LOW_MAX` | `19` | Policy band (persisted via `/api/settings`) |
| `THRESHOLD_MODERATE_MAX` | `39` | Policy band (persisted) |
| `THRESHOLD_HIGH_MAX` | `69` | Policy band (ordering validation) |
| `THRESHOLD_CRITICAL_MIN` | `70` | Policy band (persisted) |

Paths (resolved relative to `backend/`):

- `UPLOAD_DIR` → `backend/storage/uploads/`
- `QUARANTINE_DIR` → `backend/storage/quarantine/`
- `RESTORE_DIR` → `backend/storage/restored/` (files released by an authorized restore)
- `REPORT_DIR` → `backend/storage/reports/`

---

## 12. Resolved issues and remaining limitations

Every previously confirmed runtime bug and security finding has been fixed.
This section is kept as a changelog with the regression tests that guard it,
followed by the few design limitations that remain.

### 12.1 Fixed runtime bugs (regression-tested)

Regression tests live in `backend/tests/test_api_scans.py` and
`backend/tests/test_hardening.py`.

1. **JSON manual scans returned `400`.** — **FIXED**
   - `POST /api/scan/email` and `POST /api/scan/qr` declared a Pydantic body
     alongside `File`/`Form` parameters, so FastAPI treated every request as
     multipart/form-data and ignored JSON bodies.
   - Both routes now take a `Request` and use `_json_body()` to accept
     `application/json` while preserving multipart/form-data support.
   - Tests: `test_email_scan_accepts_json_body`,
     `test_qr_manual_scan_accepts_json_body`.

2. **QR image uploads returned `500` (`bytes` not JSON serializable).** — **FIXED**
   - `FileAgent` used to put raw image bytes into
     `attachments_metadata[0].raw_bytes`, which the orchestrator persisted into
     `AgentExecution.details` and `Scan.full_result`.
   - `FileAgent` now records only filename/size/content type/SHA-256. The
     orchestrator passes the original bytes to `EnforcerAgent` through the
     non-persisted `raw_input` channel, so a quarantined QR image is still the
     actual upload.
   - Tests: `test_file_agent_output_is_json_serializable`,
     `test_qr_image_upload_is_json_serializable`,
     `test_enforcer_quarantines_original_qr_bytes`.

3. **Seeded demo quarantine file failed integrity verification.** — **FIXED**
   - `seed_demo_data` wrote `b"DEMO_QUARANTINED_PAYLOAD_E3B0"` but stored the
     SHA-256 of the empty string as `file_hash`, with an incorrect `file_size`.
   - It now uses `compute_sha256(demo_payload)` and `len(demo_payload)`.
   - Existing local databases must be reset (delete the DB and restart) to pick
     up the corrected seed row.

4. **Email ML text features were always zero.** — **FIXED**
   - `ml/preprocessing/features.py` now reads `body_preview` (with `body` as a
     fallback), so `urgency_count` and `credential_harvest_count` are populated
     for email scans. The model was retrained afterwards.
   - Test: `test_email_ml_features_use_body_preview`.

5. **Quarantine "restore" did not restore a file.** — **FIXED**
   - `VaultKeeper.verify_and_restore_file` now moves the verified file to
     `backend/storage/restored/`, sets `restored_at`, updates `file_path`, and
     logs the release. Integrity verification cannot be disabled.
   - Tests: `test_restore_moves_file_and_sets_timestamp`,
     `test_restore_rejects_disabled_integrity_check`.

6. **PDF reports did not escape untrusted text.** — **FIXED**
   - `reports.py` escapes all scan/indicator/agent strings with
     `xml.sax.saxutils.escape` before building ReportLab `Paragraph`s. CSV
     exports also neutralize formula-injection prefixes.
   - Tests: `test_pdf_report_escapes_untrusted_text`,
     `test_csv_export_escapes_formulas`.

### 12.2 Fixed security hardening

- **Authentication enforcement — FIXED.** `get_current_user` now requires a real
  token when `REQUIRE_AUTH=true`; all protected routers declare it as a
  dependency. The OAuth2 token URL points to a working `/api/auth/token`
  endpoint. The frontend has a `/login` page and attaches the bearer token.
  Demo mode (`REQUIRE_AUTH=false`) is retained for local use.
- **Default credentials — MITIGATED.** The seeded password comes from
  `DEFAULT_ANALYST_PASSWORD`; override it for any non-demo deployment.
- **Default `SECRET_KEY` — FIXED.** `ENVIRONMENT=production` fails fast unless a
  real `SECRET_KEY` is configured.
- **Wildcard CORS — FIXED.** The app uses the explicit `settings.CORS_ORIGINS`
  allowlist instead of `*`.
- **Settings persistence — FIXED.** `POST /api/settings` writes to the
  `SystemSetting` table and is admin-only; startup loads persisted values back
  into memory. The Groq key is never returned in full.
- **SSRF hardening — FIXED (partial, see §12.3).** `is_safe_url` now checks A and
  AAAA records, fails closed when DNS cannot resolve, blocks internal-only
  suffixes, and the probe verifies TLS. Lexical indicators are still reported
  for blocked targets; only the outbound probe is skipped.
- **Upload/rate limits — FIXED.** `MAX_UPLOAD_BYTES` caps request bodies (HTTP
  413) and `RATE_LIMIT_PER_MINUTE` limits `/api/scan/*` per client (HTTP 429).
- **CSV formula injection — FIXED.** See §12.1 #6.
- **Prompt-injection defense — IMPROVED, NOT COMPLETE.** Still regex-based; see
  §12.3.

### 12.3 Fixed correctness issues

- **Risk labels vs policy thresholds — FIXED.** `RiskScoreAgent` derives labels
  from the same configured thresholds as `PolicyAgent`.
- **Homoglyph detection — FIXED.** `normalize_homoglyphs()` is applied before
  brand checks, adding `HOMOGLYPH_BRAND_SPOOFING` indicators.
- **Typosquatting false positives — FIXED.** Brand matching is boundary-aware
  (`pineapple` no longer matches `apple`), and common multi-part public suffixes
  such as `co.uk` are parsed correctly.
- **Email attachments are truly quarantined — FIXED.** Raw MIME attachment bytes
  travel through the non-persisted `private_payload` channel and are written to
  quarantine, not placeholders.
- **Orchestrator failure tolerance — FIXED.** Each agent step is wrapped in
  `try/except`; a failed agent records an `ERROR` output and the pipeline still
  produces a Scan record.
- **`datetime.utcnow()` deprecation — FIXED.** Models use the `utcnow()` helper;
  security and reports use timezone-aware UTC.
- **Chunked hashing — FIXED.** `compute_sha256_file()` streams quarantine files
  instead of reading them entirely into memory.

### 12.4 Remaining design limitations (not defects)

- **Demo auth defaults to off.** `REQUIRE_AUTH=false` keeps the local demo open.
  Set it to `true` (and override `DEFAULT_ANALYST_PASSWORD`) for any real use.
  The inherited limitation is that this is still a local demo, not a hardened
  multi-tenant identity system.
- **Synthetic ML dataset.** `ml/training/train.py` generates its own data and
  reports 100% accuracy. The model was retrained on 2026-11-21, but it is a
  demonstration, not a validated real-world fraud model.
- **Prompt-injection defense is regex-based.** `sanitize_untrusted_input` caps
  length and redacts a few markers; it is not a complete defense against a
  determined attacker.
- **SSRF TOCTOU remains.** DNS is checked and then `httpx` resolves again; true
  DNS-rebinding protection would require a pinned custom transport. Internal
  records, AAAA, fail-closed DNS and TLS verification are already handled.
- **No database migrations.** `create_all` does not alter existing tables. Plan
  a dev DB reset (or introduce Alembic) for schema changes.
- **Seed data runs at import.** `seed_demo_data()` is guarded by counts but still
  performs I/O when `main.py` is imported.
- **QR images are intentionally treated as attachments** and may be quarantined
  for critical QR findings. This is expected behavior.
- **`qrcode` is used only by tests** to generate QR image fixtures; backend code
  never generates QR codes.
- **Tooling:** `requirements.txt` uses `>=` ranges without a Python lockfile;
  frontend lint still reports pre-existing unused-import/`set-state-in-effect`
  warnings; the ~835 kB JS chunk is not code-split; there are no frontend tests.

Backend coverage is now split across `test_detection.py` (12 detector tests),
`test_api_scans.py` (5 API regression tests) and `test_hardening.py` (10
security/correctness tests). The orchestrator, auth, ML training and Groq
service are exercised indirectly but still lack dedicated unit tests.

---

## 13. Rules for agents

1. **Read this file, `README.md`, and `docs/` before changing behavior.**
2. **Preserve the security invariants:** SSRF guard, zero-execution QR handling,
   non-invasive containment, prompt-injection sanitization, hash verification.
3. **Keep agent outputs JSON-serializable.** This is a hard requirement, not a
   style preference.
4. **Run Python from the repo root** with `py -m ...`. Do not run
   `python backend/app/main.py` directly.
5. **Use Windows PowerShell syntax** in commands and docs (`Copy-Item`, `$env:TEMP`,
   `.\venv\Scripts\Activate.ps1`).
6. **Never commit** `backend/.env`, `backend/cybersecurity_platform.db`,
   `backend/storage/uploads/*`, `backend/storage/quarantine/*`,
   `backend/storage/reports/*`, `frontend/node_modules/`, or `frontend/dist/`.
7. **Do not modify the sibling `Desktop\Majorproject` folder.** This workspace is
   `Desktop\Majorproject2`; the sibling was only the source used to restore
   missing `ml/` and frontend files.
8. **When changing an API response**, update `frontend/src/types/index.ts`,
   `frontend/src/services/api.ts`, and `docs/api_documentation.md`.
9. **When changing ML features**, retrain and update `model_metadata.json`.
10. **When changing DB models**, plan a migration or a dev DB reset; do not assume
    `create_all` will update an existing table.
11. **When fixing a known issue, add a regression test** where practical.
12. **Run the checks before finishing:**
    - `py -c "import backend.app.main"`
    - `py -m unittest backend/tests/test_detection.py backend/tests/test_api_scans.py backend/tests/test_hardening.py -v`
    - `cd frontend; npm run build`
    - `cd frontend; npm run lint` (do not add new warnings)
    - `powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1 -IncludeUnitTests` (with stack running)
13. **Keep diffs focused.** Do not reformat unrelated files, rewrite generated
    output, or rename public API fields without a migration plan.
14. **Never weaken a security check to make a test pass.** Fix the test or the
    check with a documented rationale.

---

## 14. Definition of done

A change is complete when:

- [ ] The backend imports cleanly and the app starts.
- [ ] Relevant tests pass; new behavior has coverage where practical.
- [ ] `npm run build` passes; no new lint warnings.
- [ ] API/frontend types and docs are updated for response-shape changes.
- [ ] Agent output remains JSON-serializable.
- [ ] Security invariants are intact.
- [ ] No secrets, DB files, uploads, quarantine files, `node_modules`, or `dist`
      are added to version control.
- [ ] Known-issue behavior is either fixed or explicitly documented.

---

## 15. Where to change what

| Task | Primary files |
|---|---|
| Tune email rules | `backend/app/detectors/email_detector.py` |
| Tune URL/SSRF rules | `backend/app/detectors/website_detector.py`, `backend/app/utils/ssrf_protector.py` |
| Tune QR/quishing rules | `backend/app/detectors/qr_detector.py` |
| Tune brand/TLD/shortener lists | `backend/app/utils/typosquatting.py` |
| Change risk formula or labels | `backend/app/agents/risk_score_agent.py` |
| Change policy thresholds/decisions | `backend/app/agents/policy_agent.py`, `backend/app/core/config.py`, `backend/.env.example` |
| Change containment behavior | `backend/app/agents/enforcer_agent.py` |
| Change incident/audit/recovery behavior | `backend/app/agents/vault_keeper.py` |
| Add/modify API endpoints | `backend/app/api/*.py`, `backend/app/main.py`, `backend/app/schemas/schemas.py` |
| Add/modify DB tables | `backend/app/models/models.py`, `backend/app/database/session.py` |
| Change PDF/CSV reports | `backend/app/api/reports.py` |
| Change Groq prompt/fallback | `backend/app/services/groq_service.py` |
| Retrain/change ML | `ml/preprocessing/features.py`, `ml/training/train.py`, `ml/evaluation/predict.py` |
| Add a dashboard page | `frontend/src/pages/`, `frontend/src/App.tsx`, `frontend/src/components/Sidebar.tsx` |
| Add a frontend API call | `frontend/src/services/api.ts`, `frontend/src/types/index.ts` |
| Change visual theme | `frontend/src/index.css`, Tailwind classes in components/pages |
| Add tests | `backend/tests/test_detection.py` or a new test module |
| Update docs | `README.md`, `docs/*.md`, this file |
