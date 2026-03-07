"""Findings router: mark status."""
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DBSession
from app.database import get_db
from app.models import User, Finding, Job
from app.schemas import MarkFindingRequest, FindingOut, MessageResponse
from app.dependencies import get_current_user, get_client_ip
from app.services.audit import log_action

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.post("/{finding_id}/mark", response_model=FindingOut)
def mark_finding(
    finding_id: int,
    body: MarkFindingRequest,
    request: Request,
    db: DBSession = Depends(get_db),
    user: User = Depends(get_current_user),
):
    """Mark a finding as False Positive / Needs Review / Confirmed / Open."""
    finding = db.query(Finding).filter(Finding.id == finding_id).first()
    if not finding:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Check access
    job = db.query(Job).filter(Job.id == finding.job_id).first()
    if job.user_id != user.id and user.role != "admin":
        raise HTTPException(status_code=403, detail="Access denied")

    old_status = finding.status
    finding.status = body.status
    db.commit()
    db.refresh(finding)

    ip = get_client_ip(request)
    log_action(db, "finding_marked", user_id=user.id,
               details=f"Finding {finding_id} marked from '{old_status}' to '{body.status}'",
               ip_address=ip)

    return FindingOut.model_validate(finding)
