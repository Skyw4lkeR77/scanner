"""Database models."""
import json
from datetime import datetime, timezone, timedelta
from sqlalchemy import (
    Column, Integer, String, Text, DateTime, Boolean,
    ForeignKey, Enum, JSON, Float
)
from sqlalchemy.orm import relationship
from app.database import Base
import enum


class UserRole(str, enum.Enum):
    ADMIN = "admin"
    USER = "user"


class JobStatus(str, enum.Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingStatus(str, enum.Enum):
    OPEN = "open"
    FALSE_POSITIVE = "false_positive"
    NEEDS_REVIEW = "needs_review"
    CONFIRMED = "confirmed"


# Timezone Asia/Jakarta (WIB - UTC+7)
JAKARTA_TZ = timezone(timedelta(hours=7))


def utcnow():
    """Return current time in UTC."""
    return datetime.now(timezone.utc)


def jakartanow():
    """Return current time in Asia/Jakarta timezone (WIB)."""
    return datetime.now(JAKARTA_TZ)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=jakartanow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    jobs = relationship("Job", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")


class Job(Base):
    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    scan_mode = Column(String(50), default="fast", nullable=False)  # 'fast', 'deep', 'comprehensive'
    status = Column(String(20), default=JobStatus.QUEUED, nullable=False, index=True)
    progress_pct = Column(Float, default=0.0)
    scan_note = Column(Text, nullable=True)
    scan_options = Column(Text, nullable=True)  # JSON string
    output_file = Column(String(512), nullable=True)
    nuclei_output_file = Column(String(512), nullable=True)  # Nuclei specific output
    xray_output_file = Column(String(512), nullable=True)  # Xray specific output
    katana_output_file = Column(String(512), nullable=True)  # Katana crawl output
    error_message = Column(Text, nullable=True)
    findings_count = Column(Integer, default=0)
    nuclei_findings_count = Column(Integer, default=0)
    xray_findings_count = Column(Integer, default=0)
    scan_duration_seconds = Column(Integer, nullable=True)  # Total scan duration
    endpoints_discovered = Column(Integer, default=0)  # Number of endpoints found by katana
    created_at = Column(DateTime, default=jakartanow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    pid = Column(Integer, nullable=True)  # nuclei process ID for stop capability
    xray_pid = Column(Integer, nullable=True)  # xray process ID for stop capability

    user = relationship("User", back_populates="jobs")
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False, index=True)
    
    # Source scanner
    source = Column(String(50), default="nuclei", nullable=False)  # 'nuclei', 'xray', 'manual'
    
    # Vulnerability identification
    rule_id = Column(String(255), nullable=True, index=True)
    name = Column(String(512), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    cwe = Column(String(50), nullable=True)
    owasp_category = Column(String(10), nullable=True, index=True)
    owasp_name = Column(String(255), nullable=True)
    
    # Detailed vulnerability information
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    
    # Endpoint details
    matched_url = Column(String(2048), nullable=True)
    endpoint_path = Column(String(2048), nullable=True)  # Parsed endpoint path
    http_method = Column(String(10), nullable=True)  # GET, POST, PUT, DELETE, etc.
    
    # Parameter details
    vulnerable_parameter = Column(String(512), nullable=True)  # Parameter name that is vulnerable
    parameter_location = Column(String(50), nullable=True)  # query, body, header, cookie, path
    
    # Request/Response details (stored as JSON)
    request_data = Column(Text, nullable=True)  # HTTP request that triggered vulnerability
    response_data = Column(Text, nullable=True)  # HTTP response showing vulnerability
    
    # Additional context
    remediation = Column(Text, nullable=True)
    references = Column(Text, nullable=True)  # JSON array of reference URLs
    
    # CVSS scoring
    cvss_score = Column(Float, nullable=True)
    cvss_vector = Column(String(100), nullable=True)
    
    # Status tracking
    status = Column(String(30), default=FindingStatus.OPEN, nullable=False)
    
    # Raw data
    raw_json = Column(Text, nullable=True)  # Full scanner JSON output
    
    created_at = Column(DateTime, default=jakartanow, nullable=False)

    job = relationship("Job", back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=jakartanow, nullable=False, index=True)

    user = relationship("User", back_populates="audit_logs")


class AppSetting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=jakartanow, onupdate=jakartanow)


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(128), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    csrf_token = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=jakartanow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
