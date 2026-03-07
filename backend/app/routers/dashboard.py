"""Dashboard router: user-specific stats."""
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session as DBSession
from sqlalchemy import func, desc
from app.database import get_db
from app.models import User, Job, Finding, JobStatus
from app.schemas import JobOut
from app.dependencies import get_current_user

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])


@router.get("")
def user_dashboard(
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Get dashboard stats for current user."""
    # User's job counts
    total_jobs = db.query(func.count(Job.id)).filter(Job.user_id == user.id).scalar()
    queued = db.query(func.count(Job.id)).filter(
        Job.user_id == user.id, Job.status == JobStatus.QUEUED
    ).scalar()
    running = db.query(func.count(Job.id)).filter(
        Job.user_id == user.id, Job.status == JobStatus.RUNNING
    ).scalar()
    completed = db.query(func.count(Job.id)).filter(
        Job.user_id == user.id, Job.status == JobStatus.COMPLETED
    ).scalar()

    # User's findings via join
    user_job_ids = db.query(Job.id).filter(Job.user_id == user.id).subquery()
    total_findings = db.query(func.count(Finding.id)).filter(
        Finding.job_id.in_(user_job_ids)
    ).scalar()

    # Severity distribution
    severity_rows = db.query(
        Finding.severity, func.count(Finding.id)
    ).filter(Finding.job_id.in_(user_job_ids)).group_by(Finding.severity).all()
    severity_counts = {row[0]: row[1] for row in severity_rows}

    # OWASP distribution
    owasp_rows = db.query(
        Finding.owasp_category, func.count(Finding.id)
    ).filter(
        Finding.job_id.in_(user_job_ids),
        Finding.owasp_category.isnot(None),
    ).group_by(Finding.owasp_category).all()
    owasp_counts = {row[0]: row[1] for row in owasp_rows}

    # Recent scans
    recent = db.query(Job).filter(
        Job.user_id == user.id
    ).order_by(desc(Job.created_at)).limit(5).all()

    return {
        "total_jobs": total_jobs,
        "queued_jobs": queued,
        "running_jobs": running,
        "completed_jobs": completed,
        "total_findings": total_findings,
        "severity_counts": severity_counts,
        "owasp_counts": owasp_counts,
        "recent_scans": [JobOut.model_validate(j).model_dump() for j in recent],
    }
