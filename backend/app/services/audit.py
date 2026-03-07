"""Audit logging service."""
from datetime import datetime, timezone
from sqlalchemy.orm import Session as DBSession
from app.models import AuditLog


def log_action(
    db: DBSession,
    action: str,
    user_id: int = None,
    details: str = None,
    ip_address: str = None,
):
    """Record an audit log entry."""
    entry = AuditLog(
        user_id=user_id,
        action=action,
        details=details,
        ip_address=ip_address,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.commit()
    return entry
