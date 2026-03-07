"""Pydantic schemas for request/response validation."""
from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field, field_validator, HttpUrl, ConfigDict
import re


# ─── Auth ────────────────────────────────────────────────────────────────────
class LoginRequest(BaseModel):
    username: str = Field(..., min_length=2, max_length=80)
    password: str = Field(..., min_length=6)


class LoginResponse(BaseModel):
    message: str
    user: "UserOut"
    csrf_token: str


# ─── Users ───────────────────────────────────────────────────────────────────
class UserCreate(BaseModel):
    username: str = Field(..., min_length=2, max_length=80)
    email: str = Field(..., max_length=255)
    password: str = Field(..., min_length=8)
    role: str = Field(default="user")

    @field_validator("username")
    @classmethod
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError("Username may only contain letters, numbers, dots, dashes, and underscores.")
        return v

    @field_validator("email")
    @classmethod
    def validate_email(cls, v):
        if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v):
            raise ValueError("Invalid email address.")
        return v

    @field_validator("role")
    @classmethod
    def validate_role(cls, v):
        if v not in ("admin", "user"):
            raise ValueError("Role must be 'admin' or 'user'.")
        return v


class UserUpdate(BaseModel):
    username: Optional[str] = Field(None, min_length=2, max_length=80)
    email: Optional[str] = Field(None, max_length=255)
    password: Optional[str] = Field(None, min_length=8)
    role: Optional[str] = None
    is_active: Optional[bool] = None


class UserOut(BaseModel):
    id: int
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None

    class Config:
        from_attributes = True


# ─── Scan / Jobs ────────────────────────────────────────────────────────────
class JobCreate(BaseModel):
    target_url: HttpUrl
    note: Optional[str] = None
    scan_mode: str = Field(default="fast", description="'fast', 'deep', or 'comprehensive'")


class JobOut(BaseModel):
    id: int
    user_id: int
    target_url: str
    status: str
    scan_mode: str = "fast"
    progress_pct: float
    scan_note: Optional[str] = None
    findings_count: int = 0
    nuclei_findings_count: int = 0
    xray_findings_count: int = 0
    endpoints_discovered: int = 0
    scan_duration_seconds: Optional[int] = None
    error_message: Optional[str] = None
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    class Config:
        from_attributes = True


class JobDetail(JobOut):
    output_file: Optional[str] = None
    nuclei_output_file: Optional[str] = None
    xray_output_file: Optional[str] = None
    katana_output_file: Optional[str] = None
    scan_options: Optional[str] = None


# ─── Findings ───────────────────────────────────────────────────────────────
class FindingOut(BaseModel):
    id: int
    job_id: int
    source: str = "nuclei"  # nuclei, xray, manual
    rule_id: Optional[str] = None
    name: str
    severity: str
    cwe: Optional[str] = None
    owasp_category: Optional[str] = None
    owasp_name: Optional[str] = None
    description: Optional[str] = None
    evidence: Optional[str] = None
    
    # Endpoint details
    matched_url: Optional[str] = None
    endpoint_path: Optional[str] = None
    http_method: Optional[str] = None
    
    # Parameter details
    vulnerable_parameter: Optional[str] = None
    parameter_location: Optional[str] = None
    
    # Request/Response
    request_data: Optional[str] = None
    response_data: Optional[str] = None
    
    # Remediation
    remediation: Optional[str] = None
    references: Optional[str] = None  # JSON string
    
    # CVSS
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    
    status: str
    created_at: datetime

    class Config:
        from_attributes = True


class FindingDetail(FindingOut):
    """Detailed finding with full raw JSON."""
    raw_json: Optional[str] = None


class MarkFindingRequest(BaseModel):
    status: str = Field(...)

    @field_validator("status")
    @classmethod
    def validate_status(cls, v):
        allowed = ("open", "false_positive", "needs_review", "confirmed")
        if v not in allowed:
            raise ValueError(f"Status must be one of: {', '.join(allowed)}")
        return v


# ─── Audit Logs ─────────────────────────────────────────────────────────────
class AuditLogOut(BaseModel):
    id: int
    user_id: Optional[int] = None
    action: str
    details: Optional[str] = None
    ip_address: Optional[str] = None
    timestamp: datetime
    username: Optional[str] = None

    class Config:
        from_attributes = True


# ─── Dashboard Stats ────────────────────────────────────────────────────────
class DashboardStats(BaseModel):
    total_users: int = 0
    total_jobs: int = 0
    total_findings: int = 0
    queued_jobs: int = 0
    running_jobs: int = 0
    severity_counts: dict = {}
    owasp_counts: dict = {}
    recent_scans: List[JobOut] = []


class ScannerStatus(BaseModel):
    """Scanner tools availability status."""
    nuclei_available: bool = False
    nuclei_version: Optional[str] = None
    katana_available: bool = False
    katana_version: Optional[str] = None
    xray_available: bool = False
    xray_version: Optional[str] = None


# ─── Pagination ─────────────────────────────────────────────────────────────
class PaginatedResponse(BaseModel):
    items: list
    total: int
    page: int
    per_page: int
    pages: int


# ─── Generic ────────────────────────────────────────────────────────────────
class MessageResponse(BaseModel):
    message: str


# ─── Scan Reports ───────────────────────────────────────────────────────────
class ScanReport(BaseModel):
    """Comprehensive scan report."""
    job_id: int
    target_url: str
    scan_mode: str
    scan_status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    endpoints_discovered: int = 0
    
    # Findings summary
    total_findings: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    
    # Scanner breakdown
    nuclei_findings: int = 0
    xray_findings: int = 0
    
    # OWASP breakdown
    owasp_breakdown: Dict[str, int] = {}
    
    # Findings list
    findings: List[FindingOut] = []
