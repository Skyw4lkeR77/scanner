"""Auth router: login, logout, current user."""
from datetime import datetime, timezone
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session as DBSession
from app.database import get_db
from app.models import User
from app.schemas import LoginRequest, LoginResponse, UserOut, MessageResponse
from app.auth import verify_password, create_session, invalidate_session
from app.dependencies import get_current_user, get_current_session, get_client_ip
from app.services.audit import log_action
from app.config import settings

router = APIRouter(prefix="/api/auth", tags=["auth"])


@router.post("/login", response_model=LoginResponse)
def login(
    body: LoginRequest,
    request: Request,
    response: Response,
    db: DBSession = Depends(get_db),
):
    """Authenticate user and create session."""
    ip = get_client_ip(request)

    user = db.query(User).filter(
        User.username == body.username,
        User.is_active == True,
    ).first()

    if not user or not verify_password(body.password, user.password_hash):
        log_action(db, "login_failed", details=f"Failed login for '{body.username}'", ip_address=ip)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Create session
    user_agent = request.headers.get("User-Agent", "")[:512]
    session = create_session(db, user, ip=ip, user_agent=user_agent)

    # Update last_login
    user.last_login = datetime.now(timezone.utc)
    db.commit()

    # Set session cookie
    is_secure = settings.APP_ENV == "production"
    response.set_cookie(
        key="session_id",
        value=session.session_id,
        httponly=True,
        samesite="strict",
        secure=is_secure,
        max_age=settings.SESSION_EXPIRY_HOURS * 3600,
        path="/",
    )

    log_action(db, "login", user_id=user.id, details=f"User logged in", ip_address=ip)

    return LoginResponse(
        message="Login successful",
        user=UserOut.model_validate(user),
        csrf_token=session.csrf_token,
    )


@router.post("/logout", response_model=MessageResponse)
def logout(
    request: Request,
    response: Response,
    db: DBSession = Depends(get_db),
):
    """Logout current session."""
    session_id = request.cookies.get("session_id")
    ip = get_client_ip(request)

    if session_id:
        # Get user_id before invalidating
        from app.auth import validate_session
        session = validate_session(db, session_id)
        user_id = session.user_id if session else None

        invalidate_session(db, session_id)

        if user_id:
            log_action(db, "logout", user_id=user_id, details="User logged out", ip_address=ip)

    response.delete_cookie("session_id", path="/")
    return MessageResponse(message="Logged out successfully")


@router.get("/me", response_model=UserOut)
def get_me(user: User = Depends(get_current_user)):
    """Get current authenticated user info."""
    return UserOut.model_validate(user)
