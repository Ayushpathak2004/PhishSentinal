# REST API Documentation

The platform provides a comprehensive OpenAPI-compliant backend interface. Interactive Swagger UI is accessible at `http://localhost:8000/docs`.

Protected routes require a bearer token when `REQUIRE_AUTH=true`. In the default
local-demo mode (`REQUIRE_AUTH=false`), a missing token resolves to the seeded
`analyst` user. Auth, health, and docs endpoints are always public.

## Authentication

- `POST /api/auth/login` — JSON `{"username", "password"}` → bearer token.
- `POST /api/auth/token` — OAuth2 password-form flow used by Swagger authorize.
- `GET /api/auth/me` — current user.

Send the token as `Authorization: Bearer <token>`. The frontend stores it in
`localStorage['phishsentinel_token']` and sends it automatically.

## Scanners

### `POST /api/scan/email`
Inspects email content or uploaded `.eml` files. Accepts either JSON or
`multipart/form-data`.
- **JSON Request Body**:
  ```json
  {
    "raw_content": "From: billing@paypal.com\nReply-To: bad@evil.ru...",
    "sender": "billing@paypal.com",
    "subject": "Urgent verification",
    "body": "Click here to login..."
  }
  ```
- **Multipart Form**: `file` (`.eml`, `.txt`, or `.msg`) and optional `raw_content`, `sender`, `subject`, `body` fields.

### `POST /api/scan/website`
Safely evaluates website URLs.
- **Request Body**:
  ```json
  {
    "url": "https://paypa1-security-login.xyz/account"
  }
  ```

### `POST /api/scan/qr`
Decodes and evaluates QR images or raw payloads. Accepts either JSON or
`multipart/form-data`.
- **Multipart Form**: `file` (`.png`, `.jpg`, `.jpeg`) and optional `manual_content`.
- **JSON Request Body**:
  ```json
  {
    "manual_content": "upi://pay?pa=scam@okhdfc&am=2000"
  }
  ```
  Or send a base64 image with `image_base64` (data-URI prefix is allowed).

Scan requests are limited to `MAX_UPLOAD_BYTES` (5 MB by default; HTTP 413) and
`RATE_LIMIT_PER_MINUTE` (30/min per client; HTTP 429).

---

## Incidents & Containment

### `GET /api/incidents`
Lists detected security incidents.
- Query parameters: `severity`, `status`, `limit`, `offset`.

### `PATCH /api/incidents/{id}`
Updates incident status and resolution notes.
- **Request Body**:
  ```json
  {
    "status": "CONTAINED",
    "resolution_notes": "Blocked domain on proxy perimeter."
  }
  ```

---

## Quarantine Vault

### `GET /api/quarantine`
Lists all files stored in application-managed quarantine.

### `GET /api/quarantine/{id}/verify`
Re-hashes the physical file on disk to verify cryptographic integrity against baseline SHA-256.

### `POST /api/quarantine/{id}/restore`
Verifies the file's SHA-256 against the baseline and moves it out of quarantine
into `backend/storage/restored/`. `restored_at`, `restored_by`, and an audit log
entry are recorded. Integrity verification cannot be disabled.
- **Request Body**:
  ```json
  {
    "authorized_by": "Senior SOC Analyst",
    "reason": "False positive verified.",
    "verify_integrity": true
  }
  ```

---

## Reports

### `GET /api/reports`
Returns executive threat metrics and recent critical scans.

### `GET /api/reports/{scan_id}/pdf`
Generates and downloads a formal PDF forensic investigation dossier.

### `GET /api/reports/export/csv`
Exports all incident records as a downloadable CSV spreadsheet. Cells beginning
with `=`, `+`, `-`, or `@` are prefixed with `'` to prevent spreadsheet formula
injection.

---

## Machine Learning

### `GET /api/ml/metrics`
Returns each task's model status, dataset, sample count, and saved training/test
accuracy and precision. Email metrics appear after training the email model
from the pinned dataset.

---

## Settings & Threat Intel

- `GET /api/settings` — current thresholds, Groq status, and a masked key preview.
- `POST /api/settings` — admin-only; validates and persists thresholds and Groq
  configuration to the `system_settings` table (loaded again at startup).
- `GET /api/threat-intel` — active blocklist entries and static attack patterns.
