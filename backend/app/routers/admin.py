"""Admin router: user CRUD, audit logs, all jobs."""
from math import ceil
from fastapi import APIRouter, Depends, HTTPException, Request, Query, status
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, desc
from app.database import get_db
from app.models import User, Job, Finding, AuditLog, JobStatus
from app.schemas import (
    UserCreate, UserUpdate, UserOut, MessageResponse,
    JobOut, AuditLogOut, PaginatedResponse,
)
from app.auth import hash_password, invalidate_all_user_sessions
from app.dependencies import require_admin, get_client_ip
from app.services.audit import log_action

router = APIRouter(prefix="/api/admin", tags=["admin"])


# ─── User CRUD ──────────────────────────────────────────────────────────────

@router.get("/users")
def list_users(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    search: str = Query("", max_length=100),
    db: DBSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """List all users (admin only)."""
    query = db.query(User)
    if search:
        query = query.filter(
            (User.username.ilike(f"%{search}%")) |
            (User.email.ilike(f"%{search}%"))
        )

    total = query.count()
    users = query.order_by(desc(User.created_at)).offset((page - 1) * per_page).limit(per_page).all()

    return PaginatedResponse(
        items=[UserOut.model_validate(u).model_dump() for u in users],
        total=total,
        page=page,
        per_page=per_page,
        pages=ceil(total / per_page) if per_page else 1,
    )


@router.post("/users", response_model=UserOut, status_code=201)
def create_user(
    body: UserCreate,
    request: Request,
    db: DBSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Create a new user (admin only)."""
    # Check uniqueness
    existing = db.query(User).filter(
        (User.username == body.username) | (User.email == body.email)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email already exists",
        )

    user = User(
        username=body.username,
        email=body.email,
        password_hash=hash_password(body.password),
        role=body.role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    ip = get_client_ip(request)
    log_action(db, "user_created", user_id=admin.id,
               details=f"Created user '{body.username}' (role: {body.role})", ip_address=ip)

    return UserOut.model_validate(user)


@router.put("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: int,
    body: UserUpdate,
    request: Request,
    db: DBSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Update a user (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    # Prevent admin from deactivating themselves
    if user.id == admin.id and body.is_active is False:
        raise HTTPException(status_code=400, detail="Cannot deactivate your own account")

    if body.username is not None:
        existing = db.query(User).filter(User.username == body.username, User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Username already taken")
        user.username = body.username

    if body.email is not None:
        existing = db.query(User).filter(User.email == body.email, User.id != user_id).first()
        if existing:
            raise HTTPException(status_code=400, detail="Email already taken")
        user.email = body.email

    if body.password is not None:
        user.password_hash = hash_password(body.password)
        invalidate_all_user_sessions(db, user.id)

    if body.role is not None:
        user.role = body.role

    if body.is_active is not None:
        user.is_active = body.is_active
        if not body.is_active:
            invalidate_all_user_sessions(db, user.id)

    db.commit()
    db.refresh(user)

    ip = get_client_ip(request)
    log_action(db, "user_updated", user_id=admin.id,
               details=f"Updated user '{user.username}' (id: {user_id})", ip_address=ip)

    return UserOut.model_validate(user)


@router.delete("/users/{user_id}", response_model=MessageResponse)
def delete_user(
    user_id: int,
    request: Request,
    db: DBSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Delete a user (admin only)."""
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    if user.id == admin.id:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")

    username = user.username
    invalidate_all_user_sessions(db, user.id)
    db.delete(user)
    db.commit()

    ip = get_client_ip(request)
    log_action(db, "user_deleted", user_id=admin.id,
               details=f"Deleted user '{username}' (id: {user_id})", ip_address=ip)

    return MessageResponse(message=f"User '{username}' deleted successfully")


# ─── Audit Logs ─────────────────────────────────────────────────────────────

@router.get("/logs")
def list_logs(
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=200),
    action: str = Query("", max_length=100),
    db: DBSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """List audit logs (admin only)."""
    query = db.query(AuditLog)
    if action:
        query = query.filter(AuditLog.action.ilike(f"%{action}%"))

    total = query.count()
    logs = query.order_by(desc(AuditLog.timestamp)).offset((page - 1) * per_page).limit(per_page).all()

    # Enrich with usernames
    items = []
    for log in logs:
        data = AuditLogOut.model_validate(log).model_dump()
        if log.user:
            data["username"] = log.user.username
        items.append(data)

    return PaginatedResponse(
        items=items,
        total=total,
        page=page,
        per_page=per_page,
        pages=ceil(total / per_page) if per_page else 1,
    )


# ─── All Jobs ───────────────────────────────────────────────────────────────

@router.get("/jobs")
def list_all_jobs(
    page: int = Query(1, ge=1),
    per_page: int = Query(20, ge=1, le=100),
    status_filter: str = Query("", alias="status", max_length=20),
    db: DBSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """List all scan jobs across all users (admin only)."""
    query = db.query(Job)
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


# ─── Dashboard Stats ───────────────────────────────────────────────────────

@router.get("/dashboard")
def admin_dashboard(
    db: DBSession = Depends(get_db),
    admin: User = Depends(require_admin),
):
    """Get admin dashboard statistics."""
    total_users = db.query(func.count(User.id)).scalar()
    total_jobs = db.query(func.count(Job.id)).scalar()
    total_findings = db.query(func.count(Finding.id)).scalar()
    queued = db.query(func.count(Job.id)).filter(Job.status == JobStatus.QUEUED).scalar()
    running = db.query(func.count(Job.id)).filter(Job.status == JobStatus.RUNNING).scalar()

    # Severity distribution
    severity_rows = db.query(
        Finding.severity, func.count(Finding.id)
    ).group_by(Finding.severity).all()
    severity_counts = {row[0]: row[1] for row in severity_rows}

    # OWASP distribution
    owasp_rows = db.query(
        Finding.owasp_category, func.count(Finding.id)
    ).filter(Finding.owasp_category.isnot(None)).group_by(Finding.owasp_category).all()
    owasp_counts = {row[0]: row[1] for row in owasp_rows}

    # Recent scans
    recent = db.query(Job).order_by(desc(Job.created_at)).limit(10).all()

    return {
        "total_users": total_users,
        "total_jobs": total_jobs,
        "total_findings": total_findings,
        "queued_jobs": queued,
        "running_jobs": running,
        "severity_counts": severity_counts,
        "owasp_counts": owasp_counts,
        "recent_scans": [JobOut.model_validate(j).model_dump() for j in recent],
    }
