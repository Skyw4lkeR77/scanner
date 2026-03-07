"""Application configuration loaded from environment variables."""
import os
from pathlib import Path
from pydantic_settings import BaseSettings
from dotenv import load_dotenv

# Load .env from project root
env_path = Path(__file__).resolve().parent.parent.parent / ".env"
load_dotenv(env_path)


class Settings(BaseSettings):
    # App
    APP_ENV: str = "development"
    SECRET_KEY: str = "change-me-in-production-use-random-64-chars"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000
    ALLOWED_HOSTS: str = "*"

    # Database (SQLite default, set DATABASE_URL for PostgreSQL)
    DATABASE_URL: str = "sqlite:///./scanner.db"

    # Redis
    REDIS_URL: str = "redis://localhost:6379/0"

    # Nuclei
    NUCLEI_BIN: str = "/usr/local/bin/nuclei"
    KATANA_BIN: str = "/usr/local/bin/katana"
    NUCLEI_TEMPLATES: str = "~/nuclei-templates"
    NUCLEI_RATE_LIMIT: int = 50
    NUCLEI_CONCURRENCY: int = 5

    # Scan limits
    MAX_CONCURRENT_SCANS_PER_USER: int = 5
    MAX_CONCURRENT_SCANS_GLOBAL: int = 20

    # Rate limiting (requests per minute for scan endpoint)
    RATE_LIMIT_SCAN: int = 5

    # Session
    SESSION_EXPIRY_HOURS: int = 8

    # Paths
    SCAN_OUTPUT_DIR: str = "/tmp/scanner-outputs"
    LOG_DIR: str = "./logs"

    # Retention
    RAW_OUTPUT_RETENTION_DAYS: int = 90

    class Config:
        env_file = ".env"
        case_sensitive = True


settings = Settings()

# Ensure directories exist
os.makedirs(settings.SCAN_OUTPUT_DIR, exist_ok=True)
os.makedirs(settings.LOG_DIR, exist_ok=True)
