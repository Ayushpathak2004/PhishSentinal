# PhishSenital — Multi-Agent Fraud Detection and Automated Cybersecurity Response System

An intelligent, production-minded cybersecurity SaaS platform engineered to detect, classify, investigate, and autonomously respond to digital fraud across three primary attack vectors:

1. **Email Fraud / Phishing Detection** (MIME parsing, BEC spoofing, SPF/DMARC analysis, credential harvesting, dangerous attachments).
2. **Website Fraud / Malicious URL Detection** (SSRF protection, typosquatting & IDN homoglyphs, high-risk TLDs, Shannon entropy DGA detection).
3. **QR Code Fraud / Quishing Detection** (OpenCV matrix decoding, payment scheme hijacking, shortened redirect analysis, zero-execution safety lock).

Built upon an autonomous **Five-Agent Multi-Agent Architecture** coordinating threat ingestion, risk scoring, policy decision-making, containment enforcement, and cryptographic recovery.

---

## Technology Stack

- **Frontend**: React 19, TypeScript, Vite, Tailwind CSS, Lucide React, Recharts, React Router v7, Axios.
- **Backend**: Python 3.14 / 3.11+, FastAPI, Pydantic v2, SQLAlchemy 2.0, Uvicorn, Python asyncio.
- **Database**: SQLite (local development, PostgreSQL-ready schema).
- **Machine Learning**: Scikit-Learn `RandomForestClassifier` (15 explainable numeric features).
- **AI Reasoning**: Groq API (`openai/gpt-oss-120b` / `openai/gpt-oss-20b`) with automatic fallback to local deterministic rule engine.
- **Cybersecurity & Forensics**: OpenCV (`cv2.QRCodeDetector`), Pillow, dnspython, ReportLab (PDF forensic reports), cryptography/hashlib.

---

## Five-Agent Multi-Agent Architecture

```
User Input (Email / Website / QR)
       │
       ▼
1. File Agent ───► Protocol Ingestion, MIME Parsing, URL & QR Extraction, SHA-256 Hashing
       │
       ▼
2. Risk Score Agent ──► Hybrid Engine: Deterministic Rules (55%) + ML Random Forest (45%) + Groq LLM
       │
       ▼
3. Policy Agent ──► Evaluates Configurable Thresholds:
                    • 0-19: ALLOW
                    • 20-39: CAUTION
                    • 40-69: WARN_REVIEW
                    • 70-100: BLOCK_QUARANTINE
       │
       ▼
4. Enforcer Agent ──► Non-Invasive Response: Isolates Files to Quarantine, Updates URL Blocklist,
                      Wraps Dangerous Links with Safety Interceptors
       │
       ▼
5. Vault Keeper ───► Logs Incidents, Verifies Baseline SHA-256 Hashes, Formulates Recovery Plans
```

---

## Quick Start Guide (Windows)

### Prerequisites
- Python 3.11+ (or Windows `py` launcher)
- Node.js v18+ and npm

### 1. Backend Setup

From the project root:

```powershell
# Optional: create and activate virtual environment
py -m venv venv
.\venv\Scripts\activate

# Install dependencies (already installed in workspace)
py -m pip install -r backend/requirements.txt

# Train / Verify the ML model (synthetic demo dataset)
py -m ml.training.train

# Or retrain on the external URL dataset (url_features_extracted1.csv)
py -m ml.training.train_external

# Launch the FastAPI backend server (Port 8000)
py -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

The backend starts at `http://localhost:8000` with Swagger docs available at `http://localhost:8000/docs`.

### 2. Frontend Setup

In a new terminal window:

```powershell
cd frontend

# Install dependencies (already completed)
npm install

# Start Vite development server
npm run dev
```

The frontend application opens at `http://localhost:5173`.

---

## Groq API Setup & Fallback System

1. Obtain a free API key from [Groq Console](https://console.groq.com).
2. Set the key in `backend/.env`:
   ```ini
   GROQ_API_KEY="gsk_your_groq_api_key_here"
   GROQ_MODEL="openai/gpt-oss-120b"
   ```
3. Alternatively, enter the key directly in the web UI under **Settings**.
4. **Graceful Fallback**: If no key is provided, the platform operates seamlessly using its local deterministic rule engine and trained machine learning models with zero loss of core functionality.

---

## Authentication (optional)

The local demo keeps `REQUIRE_AUTH=false`, so the console is open out of the box.
To require bearer tokens, add this to `backend/.env`:

```ini
REQUIRE_AUTH=true
DEFAULT_ANALYST_PASSWORD="choose-a-strong-password"
```

Then sign in from the **Sign in** button in the navbar (`analyst` / your password).
The frontend stores the token in `localStorage` and sends it on every API call.

---

## Automated Testing

Run the test suite:

```powershell
py -m unittest backend/tests/test_detection.py backend/tests/test_api_scans.py backend/tests/test_hardening.py
```

All 27 unit, API, and hardening tests execute in under 15 seconds. The API and
hardening tests use temporary databases, quarantine directories, and restore
directories, so they do not modify local scan data.

With the backend and frontend already running, verify the whole live stack with:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\smoke_test.ps1 -IncludeUnitTests
```

A healthy system reports `RESULT: passed=17 failed=0`. See `docs/testing.md` for
the manual UI test matrix and extension ideas.

---

## Application Navigation

1. **Overview Dashboard**: High-level SOC telemetry, Recharts data visualizations, risk distribution donut, recent scan feed.
2. **Email Scanner**: Paste email, upload `.eml`, or click **Load Phishing Sample** to test credential harvesting and spoofing detection.
3. **Website Scanner**: Enter URLs, test typosquatting (`paypa1-security-verification.xyz`), raw IPs, or SSRF probes.
4. **QR Scanner**: Upload QR image or paste QR payload. Includes **Zero-Execution Safety Protocol** locking all payment/navigation actions.
5. **Threat Intelligence**: Enforced database blocklist and attack pattern directory.
6. **Agent Activity**: Live status, latencies, completed tasks, and execution logs for all 5 agents.
7. **Incident Management**: Incident lifecycle triage, status updates (`OPEN` -> `CONTAINED` -> `RESOLVED`), and action logs.
8. **Quarantine Vault**: Isolated files, streamed SHA-256 integrity verification, and authorized restoration that moves verified files to `backend/storage/restored/`.
9. **Reports**: One-click PDF incident report generation via ReportLab and CSV spreadsheet export.
10. **Settings**: Configurable policy threshold bands and Groq API key configuration (persisted in SQLite).
11. **Login**: Bearer-token sign-in; enables `REQUIRE_AUTH=true` deployments.

---

## Security Safeguards

- **SSRF Prevention**: Blocks RFC1918 private IPs, loopback (`127.0.0.1`), link-local, cloud metadata services (`169.254.169.254`), internal-only DNS suffixes, and domains that resolve to private A/AAAA records. DNS failures fail closed; the HTTP probe verifies TLS.
- **Prompt Injection Defense**: Untrusted content is sanitized and length-capped prior to LLM evaluation.
- **Non-Invasive Containment**: Enforcements are restricted strictly to application-managed quarantine and blocklist tables.
- **Cryptographic Restoration**: Quarantined files are streamed through SHA-256 verification before an authorized restore moves them to `backend/storage/restored/`.
- **Report Safety**: PDF and CSV exports escape untrusted text and neutralize spreadsheet formula injection.
- **Abuse Limits**: Request bodies are capped (5 MB by default) and scan endpoints are rate-limited per client (30/min by default).
- **Protected Configuration**: Settings changes are admin-only and persisted; auth enforcement can be enabled with `REQUIRE_AUTH=true`.
