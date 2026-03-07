"""FastAPI dependencies for auth and database."""
from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.orm import Session as DBSession
from app.database import get_db
from app.auth import validate_session
from app.models import User, Session as SessionModel


def get_current_session(request: Request, db: DBSession = Depends(get_db)) -> SessionModel:
    """Get the current valid session or raise 401."""
    session_id = request.cookies.get("session_id")
    if not session_id:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    session = validate_session(db, session_id)
    if not session:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

    return session


def get_current_user(
    request: Request,
    db: DBSession = Depends(get_db),
    session: SessionModel = Depends(get_current_session),
) -> User:
    """Get the current authenticated user."""
    user = db.query(User).filter(User.id == session.user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


def require_admin(user: User = Depends(get_current_user)) -> User:
    """Require the current user to be an admin."""
    if user.role != "admin":
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin access required")
    return user


def get_client_ip(request: Request) -> str:
    """Get client IP, respecting X-Forwarded-For."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"
