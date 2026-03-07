"""Scan router: submit, list, detail, stop, export."""
from math import ceil
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Query, Response, status
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import desc, func
from app.database import get_db
from app.models import User, Job, Finding, JobStatus
from app.schemas import JobCreate, JobOut, JobDetail, FindingOut, PaginatedResponse, MessageResponse
from app.dependencies import get_current_user, get_client_ip
from app.services.audit import log_action
from app.utils.validators import validate_target_url
from app.utils.export import findings_to_json, findings_to_csv
from app.services.nuclei import stop_process
from app.config import settings

router = APIRouter(prefix="/api/scan", tags=["scan"])


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
    is_valid, error = validate_target_url(body.target_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=error)

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
        scan_mode=body.scan_mode,
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
        q.enqueue("app.services.scanner.run_scan_job", job.id, job_timeout="1h")
    except Exception as e:
        # If Redis is not available, run inline (dev mode fallback)
        job.error_message = f"Queue unavailable ({str(e)[:100]}). Job created but not queued. Start worker to process."
        db.commit()

    log_action(db, "scan_submitted", user_id=user.id,
               details=f"Scan submitted for {body.target_url}", ip_address=ip)

    return JobOut.model_validate(job)


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


@router.post("/{job_id}/stop", response_model=MessageResponse)
def stop_scan(
    job_id: int,
    request: Request,
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Stop a running scan."""
    job = db.query(Job).filter(Job.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    if job.user_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    if job.status not in (JobStatus.QUEUED, JobStatus.RUNNING):
        raise HTTPException(status_code=400, detail="Scan is not running or queued")

    # Kill the process if running
    if job.pid and job.status == JobStatus.RUNNING:
        stop_process(job.pid)

    job.status = JobStatus.STOPPED
    job.finished_at = datetime.now(timezone.utc)
    job.pid = None
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

    total = query.count()
    findings = query.order_by(
        # Critical first
        Finding.severity.desc(),
        Finding.id,
    ).offset((page - 1) * per_page).limit(per_page).all()

    return PaginatedResponse(
        items=[FindingOut.model_validate(f).model_dump() for f in findings],
        total=total,
        page=page,
        per_page=per_page,
        pages=ceil(total / per_page) if per_page else 1,
    )


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
