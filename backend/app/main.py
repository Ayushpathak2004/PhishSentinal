from fastapi import FastAPI, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from collections import deque
from threading import Lock
import time

from backend.app.core.config import settings
from backend.app.database.session import engine, Base, SessionLocal
from backend.app.models.models import User, Scan, ThreatIndicator, Incident, AgentExecution, QuarantinedFile, ActionLog, BlocklistEntry
from backend.app.utils.security import hash_password, compute_sha256

# Import routers
from backend.app.api.auth import router as auth_router, get_current_user
from backend.app.api.settings import load_settings_from_db
from backend.app.api.scans import router as scans_router
from backend.app.api.dashboard import router as dashboard_router
from backend.app.api.agents import router as agents_router
from backend.app.api.incidents import router as incidents_router
from backend.app.api.quarantine import router as quarantine_router
from backend.app.api.reports import router as reports_router
from backend.app.api.settings import router as settings_router

# Initialize database schema
Base.metadata.create_all(bind=engine)

# Restore persisted policy/Groq settings (SystemSetting table) into memory.
load_settings_from_db()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description="PhishSenital: Multi-Agent Fraud Detection and Automated Cybersecurity Response System",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS — explicit allowlist; wildcard + credentials is invalid and unsafe.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request body size cap + simple fixed-window rate limit for scan endpoints.
_rate_buckets = {}
_rate_lock = Lock()


@app.middleware("http")
async def request_limits(request: Request, call_next):
    if request.method in ("POST", "PUT", "PATCH"):
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                if int(content_length) > settings.MAX_UPLOAD_BYTES:
                    return JSONResponse(
                        status_code=413,
                        content={"detail": f"Request body exceeds {settings.MAX_UPLOAD_BYTES} bytes"},
                    )
            except ValueError:
                pass

    if request.url.path.startswith("/api/scan/"):
        client = request.client.host if request.client else "unknown"
        now = time.time()
        with _rate_lock:
            bucket = _rate_buckets.setdefault(client, deque())
            while bucket and now - bucket[0] > 60:
                bucket.popleft()
            if len(bucket) >= settings.RATE_LIMIT_PER_MINUTE:
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Try again in a minute."},
                )
            bucket.append(now)

    return await call_next(request)


# Custom Security Headers Middleware
@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["X-Response-Time-Ms"] = f"{process_time * 1000:.2f}"
    return response

# Include API Routers under /api. Auth stays public; everything else is
# protected by get_current_user (which allows the seeded demo analyst only
# when REQUIRE_AUTH=false).
protected = [Depends(get_current_user)]
app.include_router(auth_router, prefix="/api")
app.include_router(scans_router, prefix="/api", dependencies=protected)
app.include_router(dashboard_router, prefix="/api", dependencies=protected)
app.include_router(agents_router, prefix="/api", dependencies=protected)
app.include_router(incidents_router, prefix="/api", dependencies=protected)
app.include_router(quarantine_router, prefix="/api", dependencies=protected)
app.include_router(reports_router, prefix="/api", dependencies=protected)
app.include_router(settings_router, prefix="/api", dependencies=protected)

@app.get("/api/health")
def health_check():
    return {
        "status": "HEALTHY",
        "system": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "groq_configured": bool(settings.GROQ_API_KEY.strip()),
        "engine": "Hybrid-Tri-Layer (Rules + Scikit-Learn RF + Groq)",
        "timestamp": time.time()
    }

# Safe Demonstration Seed Data for initial boot
def seed_demo_data():
    db = SessionLocal()
    try:
        # Check if analyst user exists
        user = db.query(User).filter(User.username == "analyst").first()
        if not user:
            user = User(
                username="analyst",
                email="analyst@cyberguard.local",
                password_hash=hash_password(settings.DEFAULT_ANALYST_PASSWORD),
                role="admin"
            )
            db.add(user)
            db.commit()

        # Seed sample scans if empty
        if db.query(Scan).count() == 0:
            # 1. Phishing email scan
            scan1 = Scan(
                scan_type="EMAIL",
                input_reference="Urgent: Your PayPal Account Has Been Suspended",
                risk_score=88.5,
                risk_level="CRITICAL",
                confidence=0.96,
                fraud_probability=0.94,
                summary="Critical phishing threat: Brand impersonation of PayPal, credential harvesting, and domain mismatch.",
                full_result={
                    "timeline": [
                        {"agent_name": "File Agent", "step_number": 1, "status": "SUCCESS", "execution_time_ms": 12.4, "summary": "Extracted MIME headers, suspicious sender address, and credential harvesting link."},
                        {"agent_name": "Risk Score Agent", "step_number": 2, "status": "SUCCESS", "execution_time_ms": 48.2, "summary": "Calculated score 88.5 (Critical). 4 threat indicators flagged."},
                        {"agent_name": "Policy Agent", "step_number": 3, "status": "SUCCESS", "execution_time_ms": 5.1, "summary": "Policy directive: BLOCK_QUARANTINE. Human approval required for restoration."},
                        {"agent_name": "Enforcer Agent", "step_number": 4, "status": "SUCCESS", "execution_time_ms": 18.7, "summary": "Enforced URL blocklist entry and neutralized hyperlinks."},
                        {"agent_name": "Vault Keeper", "step_number": 5, "status": "SUCCESS", "execution_time_ms": 15.3, "summary": "Formulated 3 recovery recommendations and logged incident."}
                    ]
                }
            )
            db.add(scan1)
            db.flush()

            db.add(ThreatIndicator(
                scan_id=scan1.id,
                indicator_type="SENDER_REPLY_TO_MISMATCH",
                title="Sender & Reply-To Domain Mismatch",
                severity="HIGH",
                description="From header claims @paypal.com but replies route to @paypal-update-desk.ru",
                evidence="paypal-update-desk.ru"
            ))
            db.add(ThreatIndicator(
                scan_id=scan1.id,
                indicator_type="CREDENTIAL_HARVESTING_INTENT",
                title="Credential Solicitation",
                severity="CRITICAL",
                description="Demands user password and credit card verification within 24 hours.",
                evidence="Enter your password to unlock account"
            ))

            inc1 = Incident(
                scan_id=scan1.id,
                title="PayPal Brand Impersonation Campaign",
                incident_type="EMAIL_FRAUD",
                severity="CRITICAL",
                status="OPEN",
                assigned_action="BLOCK_QUARANTINE",
                potential_impact="HIGH",
                resolution_notes="SOC notified. Blocked sender domain on internal perimeter."
            )
            db.add(inc1)

            # 2. Typosquatted website scan
            scan2 = Scan(
                scan_type="WEBSITE",
                input_reference="https://paypa1-security-login.xyz/account",
                risk_score=92.0,
                risk_level="CRITICAL",
                confidence=0.98,
                fraud_probability=0.97,
                summary="Typosquatted domain impersonating PayPal using homoglyph '1' on high-risk .xyz TLD.",
                full_result={"timeline": []}
            )
            db.add(scan2)
            db.flush()

            db.add(ThreatIndicator(
                scan_id=scan2.id,
                indicator_type="TYPOSQUATTING",
                title="Typosquatting of PayPal",
                severity="CRITICAL",
                description="Targeted domain paypa1-security-login.xyz mimics PayPal brand.",
                evidence="paypa1-security-login.xyz"
            ))

            # 3. Quarantined file entry
            demo_payload = b"DEMO_QUARANTINED_PAYLOAD_E3B0"
            qf = QuarantinedFile(
                scan_id=scan1.id,
                original_filename="account_verify_patch.exe",
                stored_filename="quarantine_demo_patch.exe",
                file_path=str(settings.QUARANTINE_DIR / "quarantine_demo_patch.exe"),
                file_size=len(demo_payload),
                file_hash=compute_sha256(demo_payload),
                quarantine_reason="Dangerous executable attachment in unverified phishing email",
                status="QUARANTINED"
            )
            # Create the demo file on disk
            with open(settings.QUARANTINE_DIR / "quarantine_demo_patch.exe", "wb") as f:
                f.write(demo_payload)
            db.add(qf)

            # Blocklist entry
            db.add(BlocklistEntry(
                entry_type="DOMAIN",
                value="paypa1-security-login.xyz",
                reason="Confirmed active phishing kit",
                severity="CRITICAL"
            ))

            db.commit()
    except Exception as e:
        db.rollback()
        print(f"Error seeding demo data: {e}")
    finally:
        db.close()

seed_demo_data()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend.app.main:app", host="0.0.0.0", port=8000, reload=True)
