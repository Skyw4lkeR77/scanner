"""Database models."""
import json
from datetime import datetime, timezone
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


def utcnow():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(80), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    password_hash = Column(String(255), nullable=False)
    role = Column(String(20), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    last_login = Column(DateTime, nullable=True)

    jobs = relationship("Job", back_populates="user", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="user", cascade="all, delete-orphan")


class Job(Base):
    __tablename__ = "jobs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    target_url = Column(String(2048), nullable=False)
    scan_mode = Column(String(50), default="fast", nullable=False)  # 'fast' or 'deep'
    status = Column(String(20), default=JobStatus.QUEUED, nullable=False, index=True)
    progress_pct = Column(Float, default=0.0)
    scan_note = Column(Text, nullable=True)
    scan_options = Column(Text, nullable=True)  # JSON string
    output_file = Column(String(512), nullable=True)
    error_message = Column(Text, nullable=True)
    findings_count = Column(Integer, default=0)
    created_at = Column(DateTime, default=utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    pid = Column(Integer, nullable=True)  # nuclei process ID for stop capability

    user = relationship("User", back_populates="jobs")
    findings = relationship("Finding", back_populates="job", cascade="all, delete-orphan")


class Finding(Base):
    __tablename__ = "findings"

    id = Column(Integer, primary_key=True, index=True)
    job_id = Column(Integer, ForeignKey("jobs.id"), nullable=False, index=True)
    rule_id = Column(String(255), nullable=True, index=True)
    name = Column(String(512), nullable=False)
    severity = Column(String(20), nullable=False, index=True)
    cwe = Column(String(50), nullable=True)
    owasp_category = Column(String(10), nullable=True, index=True)
    owasp_name = Column(String(255), nullable=True)
    description = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    matched_url = Column(String(2048), nullable=True)
    remediation = Column(Text, nullable=True)
    status = Column(String(30), default=FindingStatus.OPEN, nullable=False)
    raw_json = Column(Text, nullable=True)  # Full nuclei JSON line
    created_at = Column(DateTime, default=utcnow, nullable=False)

    job = relationship("Job", back_populates="findings")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True, index=True)
    action = Column(String(100), nullable=False, index=True)
    details = Column(Text, nullable=True)
    ip_address = Column(String(45), nullable=True)
    timestamp = Column(DateTime, default=utcnow, nullable=False, index=True)

    user = relationship("User", back_populates="audit_logs")


class AppSetting(Base):
    __tablename__ = "settings"

    id = Column(Integer, primary_key=True, index=True)
    key = Column(String(100), unique=True, nullable=False, index=True)
    value = Column(Text, nullable=True)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True)
    session_id = Column(String(128), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    csrf_token = Column(String(128), nullable=False)
    created_at = Column(DateTime, default=utcnow, nullable=False)
    expires_at = Column(DateTime, nullable=False)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(512), nullable=True)
