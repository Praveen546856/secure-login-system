"""Database tables."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def utcnow() -> datetime:
    """Current UTC time as a naive datetime (SQLite does not store time zones)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(30))
    username_lower: Mapped[str] = mapped_column(String(30), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(254), unique=True, index=True)  # stored lowercase
    password_hash: Mapped[str] = mapped_column(String(255))  # Argon2id hash, never the password
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    # Two-factor authentication (TOTP)
    totp_secret_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)  # Fernet-encrypted
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    totp_last_step: Mapped[int] = mapped_column(Integer, default=-1)  # blocks code replay

    @property
    def two_factor_enabled(self) -> bool:
        return bool(self.totp_enabled)

    sessions: Mapped[list["UserSession"]] = relationship(back_populates="user", cascade="all, delete-orphan")
    recovery_codes: Mapped[list["RecoveryCode"]] = relationship(back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    """Server-side session. The browser only holds a random token; we store its SHA-256 hash."""
    __tablename__ = "sessions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    expires_at: Mapped[datetime] = mapped_column(DateTime)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    user: Mapped[User] = relationship(back_populates="sessions")


class RecoveryCode(Base):
    """One-time 2FA recovery codes (stored only as keyed hashes)."""
    __tablename__ = "recovery_codes"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("users.id", ondelete="CASCADE"), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    used: Mapped[bool] = mapped_column(Boolean, default=False)

    user: Mapped[User] = relationship(back_populates="recovery_codes")
