"""Settings come ONLY from environment variables (or a local .env file).

There are no default secrets: if SECRET_KEY or TOTP_ENCRYPTION_KEY is missing
the app refuses to start, so a secret can never be accidentally hard-coded.
"""
import os
from dataclasses import dataclass
from functools import lru_cache

from cryptography.fernet import Fernet
from dotenv import load_dotenv


class SettingsError(Exception):
    """Raised at startup when the configuration is missing or unsafe."""


def _bool(value: str | None, default: bool) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in ("1", "true", "yes", "on")


@dataclass(frozen=True)
class Settings:
    environment: str
    secret_key: str
    totp_encryption_key: str
    database_url: str
    frontend_origins: tuple[str, ...]
    cookie_secure: bool
    cookie_samesite: str
    session_lifetime_minutes: int
    session_idle_minutes: int
    login_max_failures: int
    login_failure_window_seconds: int
    ip_max_attempts_per_minute: int
    totp_issuer: str

    @property
    def is_production(self) -> bool:
        return self.environment == "production"


def load_settings() -> Settings:
    load_dotenv()  # reads backend/.env if it exists; real environment variables win
    env = os.environ

    secret_key = env.get("SECRET_KEY", "")
    totp_key = env.get("TOTP_ENCRYPTION_KEY", "")
    if len(secret_key) < 32:
        raise SettingsError("SECRET_KEY is missing or too short (need 32+ characters). See .env.example.")
    try:
        Fernet(totp_key.encode())
    except Exception:
        raise SettingsError("TOTP_ENCRYPTION_KEY is missing or invalid. See .env.example.")

    environment = env.get("ENVIRONMENT", "development").strip().lower()
    if environment not in ("development", "production"):
        raise SettingsError("ENVIRONMENT must be 'development' or 'production'.")

    origins = tuple(o.strip().rstrip("/") for o in env.get("FRONTEND_ORIGINS", "http://localhost:5174").split(",") if o.strip())
    samesite = env.get("COOKIE_SAMESITE", "strict").strip().lower()
    if samesite not in ("strict", "lax"):
        raise SettingsError("COOKIE_SAMESITE must be 'strict' or 'lax'.")
    cookie_secure = _bool(env.get("COOKIE_SECURE"), False)

    if environment == "production":
        if not cookie_secure:
            raise SettingsError("In production COOKIE_SECURE must be true (HTTPS only).")
        if any(not o.startswith("https://") for o in origins):
            raise SettingsError("In production FRONTEND_ORIGINS must all use https://.")

    return Settings(
        environment=environment,
        secret_key=secret_key,
        totp_encryption_key=totp_key,
        database_url=env.get("DATABASE_URL", "sqlite:///./secure_login.db"),
        frontend_origins=origins,
        cookie_secure=cookie_secure,
        cookie_samesite=samesite,
        session_lifetime_minutes=int(env.get("SESSION_LIFETIME_MINUTES", "480")),
        session_idle_minutes=int(env.get("SESSION_IDLE_MINUTES", "30")),
        login_max_failures=int(env.get("LOGIN_MAX_FAILURES", "5")),
        login_failure_window_seconds=int(env.get("LOGIN_FAILURE_WINDOW_SECONDS", "900")),
        ip_max_attempts_per_minute=int(env.get("IP_MAX_ATTEMPTS_PER_MINUTE", "20")),
        totp_issuer=env.get("TOTP_ISSUER", "SecureLoginSystem"),
    )


@lru_cache
def get_settings() -> Settings:
    return load_settings()
