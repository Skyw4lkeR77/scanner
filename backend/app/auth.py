"""Authentication utilities: password hashing, session management."""
import secrets
from datetime import datetime, timezone, timedelta
from sqlalchemy.orm import Session as DBSession
from app.models import User, Session as SessionModel
from app.config import settings
import bcrypt


def hash_password(password: str) -> str:
    """Hash a password using bcrypt."""
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    """Verify a password against its hash."""
    return bcrypt.checkpw(password.encode("utf-8"), password_hash.encode("utf-8"))


def create_session(db: DBSession, user: User, ip: str = None, user_agent: str = None) -> SessionModel:
    """Create a new session for a user."""
    session_id = secrets.token_urlsafe(64)
    csrf_token = secrets.token_urlsafe(32)
    expires_at = datetime.now(timezone.utc) + timedelta(hours=settings.SESSION_EXPIRY_HOURS)

    session = SessionModel(
        session_id=session_id,
        user_id=user.id,
        csrf_token=csrf_token,
        expires_at=expires_at,
        ip_address=ip,
        user_agent=user_agent,
    )
    db.add(session)
    db.commit()
    db.refresh(session)
    return session


def validate_session(db: DBSession, session_id: str) -> SessionModel | None:
    """Validate a session ID and return the session if valid."""
    if not session_id:
        return None
    session = db.query(SessionModel).filter(
        SessionModel.session_id == session_id
    ).first()
    if not session:
        return None
    if session.expires_at.replace(tzinfo=timezone.utc) < datetime.now(timezone.utc):
        # Expired — delete it
        db.delete(session)
        db.commit()
        return None
    return session


def invalidate_session(db: DBSession, session_id: str) -> bool:
    """Delete a session."""
    session = db.query(SessionModel).filter(
        SessionModel.session_id == session_id
    ).first()
    if session:
        db.delete(session)
        db.commit()
        return True
    return False


def invalidate_all_user_sessions(db: DBSession, user_id: int):
    """Delete all sessions for a user."""
    db.query(SessionModel).filter(SessionModel.user_id == user_id).delete()
    db.commit()
