import os
from pathlib import Path
from typing import List
from pydantic import BaseModel
from dotenv import load_dotenv

BASE_DIR = Path(__file__).resolve().parent.parent.parent
load_dotenv(BASE_DIR / ".env")

class Settings(BaseModel):
    PROJECT_NAME: str = "PhishSentinel"
    VERSION: str = "1.0.0"
    API_V1_STR: str = "/api"
    
    # Security & Auth
    ENVIRONMENT: str = os.getenv("ENVIRONMENT", "development")
    SECRET_KEY: str = os.getenv("SECRET_KEY", "cyber-guard-super-secret-key-32-chars-long-2026")
    ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    # When true, every protected route requires a real bearer token. Defaults
    # to false so the local demo keeps working out of the box.
    REQUIRE_AUTH: bool = os.getenv("REQUIRE_AUTH", "false").strip().lower() in ("1", "true", "yes", "on")
    DEFAULT_ANALYST_PASSWORD: str = os.getenv("DEFAULT_ANALYST_PASSWORD", "CyberGuard2026!")
    MAX_UPLOAD_BYTES: int = int(os.getenv("MAX_UPLOAD_BYTES", str(5 * 1024 * 1024)))
    RATE_LIMIT_PER_MINUTE: int = int(os.getenv("RATE_LIMIT_PER_MINUTE", "30"))
    
    # AI - Groq
    GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
    GROQ_MODEL: str = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
    
    # Database
    DATABASE_URL: str = os.getenv("DATABASE_URL", f"sqlite:///{BASE_DIR / 'cybersecurity_platform.db'}")
    
    # Storage Paths
    BASE_STORAGE_DIR: Path = BASE_DIR / "storage"
    UPLOAD_DIR: Path = BASE_STORAGE_DIR / "uploads"
    QUARANTINE_DIR: Path = BASE_STORAGE_DIR / "quarantine"
    RESTORE_DIR: Path = BASE_STORAGE_DIR / "restored"
    REPORT_DIR: Path = BASE_STORAGE_DIR / "reports"
    
    # Policy Thresholds (Configurable)
    THRESHOLD_LOW_MAX: int = int(os.getenv("THRESHOLD_LOW_MAX", "19"))
    THRESHOLD_MODERATE_MAX: int = int(os.getenv("THRESHOLD_MODERATE_MAX", "39"))
    THRESHOLD_HIGH_MAX: int = int(os.getenv("THRESHOLD_HIGH_MAX", "69"))
    THRESHOLD_CRITICAL_MIN: int = int(os.getenv("THRESHOLD_CRITICAL_MIN", "70"))
    
    # CORS
    CORS_ORIGINS: List[str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://localhost:8000"
    ]

settings = Settings()

if settings.ENVIRONMENT.lower() == "production":
    if settings.SECRET_KEY == "cyber-guard-super-secret-key-32-chars-long-2026":
        raise RuntimeError(
            "SECRET_KEY must be set to a unique value in production (backend/.env)."
        )

# Ensure directories exist
settings.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
settings.QUARANTINE_DIR.mkdir(parents=True, exist_ok=True)
settings.RESTORE_DIR.mkdir(parents=True, exist_ok=True)
settings.REPORT_DIR.mkdir(parents=True, exist_ok=True)
