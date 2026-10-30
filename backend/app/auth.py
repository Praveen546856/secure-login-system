"""Session handling and the dependencies that protect routes."""
from dataclasses import dataclass
from datetime import timedelta

from fastapi import Depends, HTTPException, Request, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import security
from .config import Settings
from .models import User, UserSession, utcnow

COOKIE_NAME = "session"
LAST_SEEN_UPDATE_SECONDS = 60


def get_db(request: Request):
    db = request.app.state.session_factory()
    try:
        yield db
    finally:
        db.close()


def settings_of(request: Request) -> Settings:
    return request.app.state.settings


def create_session(db: Session, user: User, settings: Settings) -> str:
    """Create a server-side session and return the RAW token (only the hash is stored)."""
    token = security.new_token()
    now = utcnow()
    db.add(UserSession(
        user_id=user.id,
        token_hash=security.hash_token(token),
        created_at=now,
        last_seen_at=now,
        expires_at=now + timedelta(minutes=settings.session_lifetime_minutes),
    ))
    db.commit()
    return token


def set_session_cookie(response: Response, token: str, settings: Settings) -> None:
    response.set_cookie(
        COOKIE_NAME, token,
        max_age=settings.session_lifetime_minutes * 60,
        httponly=True,                  # JavaScript cannot read it (blocks theft via XSS)
        secure=settings.cookie_secure,  # HTTPS only when enabled (required in production)
        samesite=settings.cookie_samesite,
        path="/",
    )


def clear_session_cookie(response: Response, settings: Settings) -> None:
    response.delete_cookie(
        COOKIE_NAME, path="/", httponly=True, secure=settings.cookie_secure, samesite=settings.cookie_samesite
    )


def revoke_session(db: Session, token: str) -> None:
    row = db.scalar(select(UserSession).where(UserSession.token_hash == security.hash_token(token)))
    if row:
        db.delete(row)
        db.commit()


@dataclass
class SessionContext:
    user: User
    token: str
    csrf_token: str


def current_session(
    request: Request,
    db: Session = Depends(get_db),
    settings: Settings = Depends(settings_of),
) -> SessionContext:
    """Dependency: returns the logged-in user or raises 401."""
    unauthorized = HTTPException(status_code=401, detail="Not authenticated.")
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise unauthorized

    row = db.scalar(select(UserSession).where(UserSession.token_hash == security.hash_token(token)))
    if row is None:
        raise unauthorized

    now = utcnow()
    idle_limit = row.last_seen_at + timedelta(minutes=settings.session_idle_minutes)
    if now >= row.expires_at or now >= idle_limit:  # absolute expiry OR idle timeout
        db.delete(row)
        db.commit()
        raise unauthorized

    user = row.user
    if not user.is_active:
        raise unauthorized

    if (now - row.last_seen_at).total_seconds() > LAST_SEEN_UPDATE_SECONDS:
        row.last_seen_at = now
        db.commit()

    return SessionContext(user=user, token=token, csrf_token=security.csrf_token_for(token, settings.secret_key))


def require_csrf(request: Request, ctx: SessionContext = Depends(current_session)) -> SessionContext:
    """Dependency for state-changing routes: the X-CSRF-Token header must match the session."""
    sent = request.headers.get("x-csrf-token", "")
    if not sent or not security.tokens_equal(sent, ctx.csrf_token):
        raise HTTPException(status_code=403, detail="Invalid or missing CSRF token.")
    return ctx
