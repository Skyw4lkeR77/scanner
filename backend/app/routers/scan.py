"""Scan router: submit, list, detail, stop, export."""
from math import ceil
from datetime import datetime, timezone, timedelta
from fastapi import APIRouter, Depends, HTTPException, Request, Query, Response, status
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import desc, func
from app.database import get_db
from app.models import User, Job, Finding, JobStatus, JAKARTA_TZ
from app.schemas import (
    JobCreate, JobOut, JobDetail, FindingOut, FindingDetail,
    PaginatedResponse, MessageResponse, ScannerStatus, ScanReport
)
from app.dependencies import get_current_user, get_client_ip
from app.services.audit import log_action
from app.utils.validators import validate_target_url
from app.utils.export import findings_to_json, findings_to_csv
from app.services.nuclei import stop_process
from app.services.xray import check_xray_binary, stop_xray_process
from app.config import settings
import shutil

router = APIRouter(prefix="/api/scan", tags=["scan"])


def jakartanow():
    """Return current time in Asia/Jakarta timezone."""
    return datetime.now(JAKARTA_TZ)


def get_scanner_versions():
    """Get version info for all scanner tools."""
    versions = {
        "nuclei": None,
        "katana": None,
        "xray": None,
    }
    
    # Check Nuclei
    nuclei_bin = settings.NUCLEI_BIN
    if not shutil.which(nuclei_bin) and not os.path.isfile(nuclei_bin):
        nuclei_path = shutil.which("nuclei")
        if nuclei_path:
            nuclei_bin = nuclei_path
    
    if nuclei_bin and (os.path.isfile(nuclei_bin) or shutil.which(nuclei_bin)):
        try:
            import subprocess
            result = subprocess.run([nuclei_bin, "-version"], capture_output=True, text=True, timeout=10)
            versions["nuclei"] = result.stdout.strip()[:50] if result.returncode == 0 else "installed"
        except:
            versions["nuclei"] = "installed"
    
    # Check Katana
    katana_bin = settings.KATANA_BIN
    if not shutil.which(katana_bin) and not os.path.isfile(katana_bin):
        katana_path = shutil.which("katana")
        if katana_path:
            katana_bin = katana_path
    
    if katana_bin and (os.path.isfile(katana_bin) or shutil.which(katana_bin)):
        try:
            import subprocess
            result = subprocess.run([katana_bin, "-version"], capture_output=True, text=True, timeout=10)
            versions["katana"] = result.stdout.strip()[:50] if result.returncode == 0 else "installed"
        except:
            versions["katana"] = "installed"
    
    # Check Xray
    xray_bin = check_xray_binary()
    if xray_bin:
        try:
            import subprocess
            result = subprocess.run([xray_bin, "version"], capture_output=True, text=True, timeout=10)
            versions["xray"] = result.stdout.strip()[:50] if result.returncode == 0 else "installed"
        except:
            versions["xray"] = "installed"
    
    return versions


@router.post("", response_model=JobOut, status_code=201)
def submit_scan(
    body: JobCreate,
    request: Request,
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Submit a new scan target."""
    ip = get_client_ip(request)

    # Validate target URL
    target_url_str = str(body.target_url)
    is_valid, error = validate_target_url(target_url_str)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)
    
    # Validate scan mode
    valid_modes = ["fast", "deep", "comprehensive"]
    scan_mode = body.scan_mode.lower() if body.scan_mode else "fast"
    if scan_mode not in valid_modes:
        raise HTTPException(
            status_code=400, 
            detail=f"Invalid scan mode. Must be one of: {', '.join(valid_modes)}"
        )

    # Check per-user concurrent scan limit
    user_running = db.query(func.count(Job.id)).filter(
        Job.user_id == user.id,
        Job.status.in_([JobStatus.QUEUED, JobStatus.RUNNING]),
    ).scalar()
    if user_running >= settings.MAX_CONCURRENT_SCANS_PER_USER:
        raise HTTPException(
            status_code=429,
            detail=f"Max {settings.MAX_CONCURRENT_SCANS_PER_USER} concurrent scans per user. Please wait for current scans to complete.",
        )

    # Check global concurrent scan limit
    global_running = db.query(func.count(Job.id)).filter(
        Job.status.in_([JobStatus.QUEUED, JobStatus.RUNNING]),
    ).scalar()
    if global_running >= settings.MAX_CONCURRENT_SCANS_GLOBAL:
        raise HTTPException(
            status_code=429,
            detail=f"Server is busy. Max {settings.MAX_CONCURRENT_SCANS_GLOBAL} concurrent scans allowed globally.",
        )

    # Create job
    job = Job(
        user_id=user.id,
        target_url=str(body.target_url).strip().rstrip('/'),  # HttpUrl to str
        scan_mode=scan_mode,
        status=JobStatus.QUEUED,
        scan_note=body.note,
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    # Enqueue to Redis/RQ
    try:
        from redis import Redis
        from rq import Queue
        redis_conn = Redis.from_url(settings.REDIS_URL)
        q = Queue(connection=redis_conn)
        
        # Set timeout based on scan mode
        timeout_map = {
            "fast": "30m",
            "deep": "2h",
            "comprehensive": "3h",
        }
        job_timeout = timeout_map.get(scan_mode, "1h")
        
        q.enqueue("app.services.scanner.run_scan_job", job.id, job_timeout=job_timeout)
    except Exception as e:
        # If Redis is not available, run inline (dev mode fallback)
        job.error_message = f"Queue unavailable ({str(e)[:100]}). Job created but not queued. Start worker to process."
        db.commit()

    log_action(db, "scan_submitted", user_id=user.id,
               details=f"Scan submitted for {body.target_url} (mode: {scan_mode})", ip_address=ip)

    return JobOut.model_validate(job)


@router.get("/status/scanners", response_model=ScannerStatus)
def get_scanner_status(
    user: User = Depends(get_current_user),
):
    """Get status of all scanner tools."""
    versions = get_scanner_versions()
    
    return ScannerStatus(
        nuclei_available=versions["nuclei"] is not None,
        nuclei_version=versions["nuclei"],
        katana_available=versions["katana"] is not None,
        katana_version=versions["katana"],
        xray_available=versions["xray"] is not None,
        xray_version=versions["xray"],
    )


@router.get("", response_model=PaginatedResponse)
def list_scans(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status_filter: str = Query("", alias="status", max_length=20),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List current user's scan jobs."""
    query = db.query(Job).filter(Job.user_id == user.id)
    if status_filter:
        query = query.filter(Job.status == status_filter)

    total = query.count()
    jobs = query.order_by(desc(Job.created_at)).offset((page - 1) * per_page).limit(per_page).all()

    return PaginatedResponse(
        items=[JobOut.model_validate(j).model_dump() for j in jobs],
        total=total,
        page=page,
        per_page=per_page,
        pages=ceil(total / per_page) if per_page else 1,
    )


@router.get("/{job_id}", response_model=JobDetail)
def get_scan(
    job_id: int,
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get scan job details."""
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Users can only see their own scans; admins can see all
    if job.user_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    return JobDetail.model_validate(job)


@router.get("/{job_id}/report", response_model=ScanReport)
def get_scan_report(
    job_id: int,
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get comprehensive scan report with findings."""
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    if job.user_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    # Get all findings
    findings = db.query(Finding).filter(Finding.job_id == job_id).all()
    
    # Count by severity
    severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        if f.severity in severity_counts:
            severity_counts[f.severity] += 1
    
    # Count by OWASP category
    owasp_breakdown = {}
    for f in findings:
        if f.owasp_category:
            owasp_breakdown[f.owasp_category] = owasp_breakdown.get(f.owasp_category, 0) + 1

    return ScanReport(
        job_id=job.id,
        target_url=job.target_url,
        scan_mode=job.scan_mode,
        scan_status=job.status,
        created_at=job.created_at,
        started_at=job.started_at,
        finished_at=job.finished_at,
        duration_seconds=job.scan_duration_seconds,
        endpoints_discovered=job.endpoints_discovered,
        total_findings=len(findings),
        critical_count=severity_counts["critical"],
        high_count=severity_counts["high"],
        medium_count=severity_counts["medium"],
        low_count=severity_counts["low"],
        info_count=severity_counts["info"],
        nuclei_findings=job.nuclei_findings_count,
        xray_findings=job.xray_findings_count,
        owasp_breakdown=owasp_breakdown,
        findings=[FindingOut.model_validate(f) for f in findings],
    )


@router.post("/{job_id}/stop", response_model=MessageResponse)
def stop_scan(
    job_id: int,
    request: Request,
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Stop a running scan."""
    import os
    
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    if job.user_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    if job.status not in (JobStatus.QUEUED, JobStatus.RUNNING):
        raise HTTPException(status_code=400, detail="Scan is not running or queued")

    # Kill the nuclei process if running
    if job.pid and job.status == JobStatus.RUNNING:
        stop_process(job.pid)
    
    # Kill the xray process if running
    if job.xray_pid and job.status == JobStatus.RUNNING:
        stop_xray_process(job.xray_pid)

    job.status = JobStatus.STOPPED
    job.finished_at = jakartanow()
    job.pid = None
    job.xray_pid = None
    db.commit()

    ip = get_client_ip(request)
    log_action(db, "scan_stopped", user_id=user.id,
               details=f"Scan stopped for {job.target_url} (job {job_id})", ip_address=ip)

    return MessageResponse(message="Scan stopped")


@router.get("/{job_id}/findings")
def get_findings(
    job_id: int,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    severity: str = Query("", max_length=20),
    owasp: str = Query("", max_length=10),
    source: str = Query("", max_length=50),  # Filter by scanner source
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """List findings for a scan job."""
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    if job.user_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    query = db.query(Finding).filter(Finding.job_id == job_id)
    if severity:
        query = query.filter(Finding.severity == severity.lower())
    if owasp:
        query = query.filter(Finding.owasp_category == owasp.upper())
    if source:
        query = query.filter(Finding.source == source.lower())

    total = query.count()
    
    # Custom ordering: Critical > High > Medium > Low > Info
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings = query.all()
    findings.sort(key=lambda f: (severity_order.get(f.severity, 5), f.id))
    
    # Paginate
    start = (page - 1) * per_page
    end = start + per_page
    paginated_findings = findings[start:end]

    return PaginatedResponse(
        items=[FindingOut.model_validate(f).model_dump() for f in paginated_findings],
        total=total,
        page=page,
        per_page=per_page,
        pages=ceil(total / per_page) if per_page else 1,
    )


@router.get("/{job_id}/findings/{finding_id}", response_model=FindingDetail)
def get_finding_detail(
    job_id: int,
    finding_id: int,
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get detailed information about a specific finding."""
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    if job.user_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    finding = db.query(Finding).filter(
        Finding.id == finding_id,
        Finding.job_id == job_id
    ).first()
    
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    return FindingDetail.model_validate(finding)


@router.get("/{job_id}/export")
def export_findings(
    job_id: int,
    format: str = Query("json", regex="^(json|csv)$"),
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Export findings as JSON or CSV."""
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    if job.user_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    findings = db.query(Finding).filter(Finding.job_id == job_id).all()

    if format == "csv":
        content = findings_to_csv(findings)
        media_type = "text/csv"
        filename = f"findings-{job_id}.csv"
    else:
        content = findings_to_json(findings)
        media_type = "application/json"
        filename = f"findings-{job_id}.json"

    return Response(
        content=content,
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )
