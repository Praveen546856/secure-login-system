"""Authentication routes: register, login (+2FA), logout, password change, 2FA management."""
import base64
import hashlib
import io
import logging

import qrcode
import qrcode.image.svg
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer
from sqlalchemy import delete, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import security
from ..auth import (
    COOKIE_NAME, SessionContext, clear_session_cookie, create_session, current_session,
    get_db, require_csrf, revoke_session, set_session_cookie, settings_of,
)
from ..config import Settings
from ..models import RecoveryCode, User, UserSession, utcnow
from ..schemas import (
    AuthResponse, ChangePasswordRequest, LoginRequest, MessageResponse, RecoveryCodesResponse,
    RegisterRequest, TwoFactorDisableRequest, TwoFactorEnableRequest, TwoFactorLoginRequest,
    TwoFactorRequiredResponse, TwoFactorSetupRequest, TwoFactorSetupResponse, UserPublic,
)

router = APIRouter(prefix="/api/auth", tags=["auth"])
logger = logging.getLogger("securelogin")  # we never log passwords, codes, tokens or emails

CHALLENGE_MAX_AGE_SECONDS = 300
GENERIC_LOGIN_ERROR = "Invalid email or password."


# ------------------------------------------------------------------ helpers
def client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def _too_many(wait: int) -> HTTPException:
    return HTTPException(
        status_code=429,
        detail="Too many attempts. Please try again later.",
        headers={"Retry-After": str(wait)},
    )


def _short_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()[:32]


def check_ip_limit(request: Request, settings: Settings) -> None:
    limiter = request.app.state.ip_limiter
    key = f"ip:{client_ip(request)}"
    wait = limiter.retry_after(key, settings.ip_max_attempts_per_minute, 60)
    if wait:
        raise _too_many(wait)
    limiter.record(key, 60)


def check_failure_limit(request: Request, settings: Settings, key: str) -> None:
    wait = request.app.state.id_limiter.retry_after(key, settings.login_max_failures, settings.login_failure_window_seconds)
    if wait:
        raise _too_many(wait)


def record_failure(request: Request, settings: Settings, key: str) -> None:
    request.app.state.id_limiter.record(key, settings.login_failure_window_seconds)


def clear_failures(request: Request, key: str) -> None:
    request.app.state.id_limiter.clear(key)


def challenge_serializer(settings: Settings) -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(settings.secret_key, salt="login-2fa-challenge")


def finish_login(request: Request, response: Response, db: Session, user: User, settings: Settings) -> AuthResponse:
    """Issue a brand-new session (prevents session fixation) and set the cookie."""
    old_token = request.cookies.get(COOKIE_NAME)
    if old_token:
        revoke_session(db, old_token)
    user.last_login_at = utcnow()
    db.commit()
    token = create_session(db, user, settings)
    set_session_cookie(response, token, settings)
    logger.info("login ok user_id=%s", user.id)
    return AuthResponse(
        user=UserPublic.model_validate(user),
        csrf_token=security.csrf_token_for(token, settings.secret_key),
    )


def verify_second_factor(db: Session, user: User, code: str, settings: Settings) -> bool:
    """Accept a TOTP code (with replay protection) or a one-time recovery code."""
    if security.CODE_RE.match(code):
        if not user.totp_secret_encrypted:
            return False
        secret = security.decrypt_secret(user.totp_secret_encrypted, settings.totp_encryption_key)
        step = security.verify_totp(secret, code, user.totp_last_step)
        if step is None:
            return False
        user.totp_last_step = step
        db.commit()
        return True

    code_hash = security.hash_recovery_code(code, settings.secret_key)
    row = db.scalar(select(RecoveryCode).where(
        RecoveryCode.user_id == user.id, RecoveryCode.code_hash == code_hash, RecoveryCode.used.is_(False)
    ))
    if row is None:
        return False
    row.used = True
    db.commit()
    return True


def require_password(request: Request, db: Session, user: User, password: str, settings: Settings) -> None:
    """Re-check the current password before sensitive changes (rate limited)."""
    key = f"pw:{user.id}"
    check_failure_limit(request, settings, key)
    if not security.verify_password(user.password_hash, password):
        record_failure(request, settings, key)
        raise HTTPException(status_code=403, detail="Current password is incorrect.")
    clear_failures(request, key)


# ------------------------------------------------------------------- routes
@router.post("/register", response_model=UserPublic, status_code=201)
def register(
    payload: RegisterRequest, request: Request,
    db: Session = Depends(get_db), settings: Settings = Depends(settings_of),
):
    check_ip_limit(request, settings)

    # NOTE: telling the user "already registered" lets an attacker test whether an email exists.
    # That trade-off is inherent to simple registration forms; see the README.
    if db.scalar(select(User.id).where(User.email == payload.email)):
        raise HTTPException(status_code=409, detail="An account with this email already exists.")
    if db.scalar(select(User.id).where(User.username_lower == payload.username.lower())):
        raise HTTPException(status_code=409, detail="This username is already taken.")

    user = User(
        username=payload.username,
        username_lower=payload.username.lower(),
        email=payload.email,
        password_hash=security.hash_password(payload.password),
    )
    db.add(user)
    try:
        db.commit()  # unique constraints are the final guard against races
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Username or email already registered.")
    db.refresh(user)
    logger.info("registered user_id=%s", user.id)
    return user


@router.post("/login", response_model=AuthResponse | TwoFactorRequiredResponse)
def login(
    payload: LoginRequest, request: Request, response: Response,
    db: Session = Depends(get_db), settings: Settings = Depends(settings_of),
):
    check_ip_limit(request, settings)
    key = "login:" + _short_hash(payload.email)
    check_failure_limit(request, settings, key)

    # Parameterised ORM query: the email is bound as data, never pasted into SQL.
    user = db.scalar(select(User).where(User.email == payload.email))

    if user is not None and user.is_active:
        valid = security.verify_password(user.password_hash, payload.password)
    else:
        security.burn_time_like_a_login(payload.password)  # same timing for unknown emails
        valid = False

    if not valid:
        record_failure(request, settings, key)
        logger.info("login failed ip=%s", client_ip(request))
        raise HTTPException(status_code=401, detail=GENERIC_LOGIN_ERROR)

    clear_failures(request, key)
    if security.needs_rehash(user.password_hash):  # upgrade old hashes when settings get stronger
        user.password_hash = security.hash_password(payload.password)
        db.commit()

    if user.totp_enabled:
        challenge = challenge_serializer(settings).dumps({"uid": user.id})
        return TwoFactorRequiredResponse(challenge=challenge)
    return finish_login(request, response, db, user, settings)


@router.post("/login/2fa", response_model=AuthResponse)
def login_two_factor(
    payload: TwoFactorLoginRequest, request: Request, response: Response,
    db: Session = Depends(get_db), settings: Settings = Depends(settings_of),
):
    check_ip_limit(request, settings)
    try:
        data = challenge_serializer(settings).loads(payload.challenge, max_age=CHALLENGE_MAX_AGE_SECONDS)
    except (BadSignature, SignatureExpired):
        raise HTTPException(status_code=401, detail="Login session expired. Please log in again.")

    user = db.get(User, data.get("uid"))
    if user is None or not user.is_active or not user.totp_enabled:
        raise HTTPException(status_code=401, detail="Login session expired. Please log in again.")

    key = f"2fa:{user.id}"
    check_failure_limit(request, settings, key)
    if not verify_second_factor(db, user, payload.code, settings):
        record_failure(request, settings, key)
        raise HTTPException(status_code=401, detail="Invalid code.")
    clear_failures(request, key)
    return finish_login(request, response, db, user, settings)


@router.post("/logout", response_model=MessageResponse)
def logout(
    response: Response, ctx: SessionContext = Depends(require_csrf),
    db: Session = Depends(get_db), settings: Settings = Depends(settings_of),
):
    revoke_session(db, ctx.token)  # the session row is deleted, so the cookie is useless afterwards
    clear_session_cookie(response, settings)
    return MessageResponse(message="Logged out.")


@router.get("/me", response_model=AuthResponse)
def me(ctx: SessionContext = Depends(current_session)):
    return AuthResponse(user=UserPublic.model_validate(ctx.user), csrf_token=ctx.csrf_token)


@router.post("/change-password", response_model=MessageResponse)
def change_password(
    payload: ChangePasswordRequest, request: Request,
    ctx: SessionContext = Depends(require_csrf),
    db: Session = Depends(get_db), settings: Settings = Depends(settings_of),
):
    user = ctx.user
    require_password(request, db, user, payload.current_password, settings)
    problems = security.password_problems(payload.new_password, user.username, user.email)
    if payload.new_password == payload.current_password:
        problems.append("New password must be different from the current password.")
    if problems:
        raise HTTPException(status_code=422, detail=" ".join(problems))

    user.password_hash = security.hash_password(payload.new_password)
    # Log out every OTHER device: a stolen session must not survive a password change.
    current_hash = security.hash_token(ctx.token)
    db.execute(delete(UserSession).where(UserSession.user_id == user.id, UserSession.token_hash != current_hash))
    db.commit()
    return MessageResponse(message="Password changed. Other sessions were logged out.")


def _qr_data_uri(text: str) -> str:
    image = qrcode.make(text, image_factory=qrcode.image.svg.SvgPathImage)
    buffer = io.BytesIO()
    image.save(buffer)
    return "data:image/svg+xml;base64," + base64.b64encode(buffer.getvalue()).decode()


@router.post("/2fa/setup", response_model=TwoFactorSetupResponse)
def two_factor_setup(
    payload: TwoFactorSetupRequest, request: Request,
    ctx: SessionContext = Depends(require_csrf),
    db: Session = Depends(get_db), settings: Settings = Depends(settings_of),
):
    user = ctx.user
    require_password(request, db, user, payload.password, settings)
    if user.totp_enabled:
        raise HTTPException(status_code=409, detail="Two-factor authentication is already enabled.")

    secret = security.new_totp_secret()
    user.totp_secret_encrypted = security.encrypt_secret(secret, settings.totp_encryption_key)  # encrypted at rest
    user.totp_last_step = -1
    db.commit()
    uri = security.provisioning_uri(secret, user.email, settings.totp_issuer)
    return TwoFactorSetupResponse(otpauth_uri=uri, secret=secret, qr_svg_data_uri=_qr_data_uri(uri))


@router.post("/2fa/enable", response_model=RecoveryCodesResponse)
def two_factor_enable(
    payload: TwoFactorEnableRequest, request: Request,
    ctx: SessionContext = Depends(require_csrf),
    db: Session = Depends(get_db), settings: Settings = Depends(settings_of),
):
    user = ctx.user
    if user.totp_enabled or not user.totp_secret_encrypted:
        raise HTTPException(status_code=409, detail="Start 2FA setup first.")

    key = f"2fa-enable:{user.id}"
    check_failure_limit(request, settings, key)
    secret = security.decrypt_secret(user.totp_secret_encrypted, settings.totp_encryption_key)
    step = security.verify_totp(secret, payload.code, user.totp_last_step)
    if step is None:
        record_failure(request, settings, key)
        raise HTTPException(status_code=400, detail="Invalid code. Check your authenticator app and try again.")
    clear_failures(request, key)

    user.totp_enabled = True
    user.totp_last_step = step
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    codes = security.make_recovery_codes()
    for code in codes:
        db.add(RecoveryCode(user_id=user.id, code_hash=security.hash_recovery_code(code, settings.secret_key)))
    db.commit()
    return RecoveryCodesResponse(recovery_codes=codes)  # shown ONCE; only hashes are stored


@router.post("/2fa/disable", response_model=MessageResponse)
def two_factor_disable(
    payload: TwoFactorDisableRequest, request: Request,
    ctx: SessionContext = Depends(require_csrf),
    db: Session = Depends(get_db), settings: Settings = Depends(settings_of),
):
    user = ctx.user
    if not user.totp_enabled:
        raise HTTPException(status_code=409, detail="Two-factor authentication is not enabled.")
    require_password(request, db, user, payload.password, settings)

    key = f"2fa:{user.id}"
    check_failure_limit(request, settings, key)
    if not verify_second_factor(db, user, payload.code, settings):
        record_failure(request, settings, key)
        raise HTTPException(status_code=400, detail="Invalid code.")
    clear_failures(request, key)

    user.totp_enabled = False
    user.totp_secret_encrypted = None
    user.totp_last_step = -1
    db.execute(delete(RecoveryCode).where(RecoveryCode.user_id == user.id))
    db.commit()
    return MessageResponse(message="Two-factor authentication disabled.")
