"""Protected routes (need a valid session)."""
from datetime import timedelta

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..auth import SessionContext, current_session, get_db
from ..models import RecoveryCode, UserSession, utcnow
from ..schemas import UserPublic

router = APIRouter(prefix="/api", tags=["users"])


@router.get("/users/me", response_model=UserPublic)
def profile(ctx: SessionContext = Depends(current_session)):
    return ctx.user


@router.get("/dashboard")
def dashboard(ctx: SessionContext = Depends(current_session), db: Session = Depends(get_db)):
    """Real numbers read from the database for the logged-in user only."""
    user = ctx.user
    now = utcnow()
    active_sessions = db.scalar(
        select(func.count()).select_from(UserSession).where(UserSession.user_id == user.id, UserSession.expires_at > now)
    )
    remaining_codes = db.scalar(
        select(func.count()).select_from(RecoveryCode).where(RecoveryCode.user_id == user.id, RecoveryCode.used.is_(False))
    )
    return {
        "username": user.username,
        "account_age_days": (now - user.created_at).days,
        "last_login_at": user.last_login_at,
        "active_sessions": active_sessions,
        "two_factor_enabled": user.totp_enabled,
        "recovery_codes_remaining": remaining_codes if user.totp_enabled else None,
    }
