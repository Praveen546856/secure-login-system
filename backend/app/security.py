"""All security primitives in one place (easy to review and to explain in a viva).

* Password hashing: Argon2id (argon2-cffi) with a per-password random salt.
* Session tokens: 256-bit random values; only their SHA-256 hash is stored.
* CSRF tokens: HMAC of the session token with SECRET_KEY.
* TOTP: pyotp, secrets encrypted at rest with Fernet, replay protection.
"""
import hashlib
import hmac
import re
import secrets
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from cryptography.fernet import Fernet

from .common_passwords import COMMON_PASSWORDS

# ---------------------------------------------------------------- passwords
# PasswordHasher() defaults to Argon2id (the recommended variant) with sensible cost settings.
_hasher = PasswordHasher()
# Hash of a random value, used so "unknown user" logins take about as long as "wrong password".
_DUMMY_HASH = _hasher.hash(secrets.token_urlsafe(24))

MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 128


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str, password: str) -> bool:
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def burn_time_like_a_login(password: str) -> None:
    """Run a hash check against a dummy hash (hides whether an email exists)."""
    verify_password(_DUMMY_HASH, password)


def needs_rehash(password_hash: str) -> bool:
    return _hasher.check_needs_rehash(password_hash)


def password_problems(password: str, username: str = "", email: str = "") -> list[str]:
    """Return a list of reasons the password is not acceptable (empty list = OK)."""
    problems = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters long.")
    if len(password) > MAX_PASSWORD_LENGTH:
        problems.append(f"Password must be at most {MAX_PASSWORD_LENGTH} characters long.")
    lowered = password.lower()
    if lowered in COMMON_PASSWORDS:
        problems.append("This password is too common.")
    if password and len(set(password)) == 1:
        problems.append("Password cannot be one repeated character.")
    if password.isdigit():
        problems.append("Password cannot be only digits.")
    if len(username) >= 3 and username.lower() in lowered:
        problems.append("Password must not contain your username.")
    local = email.split("@")[0].lower() if email else ""
    if len(local) >= 3 and local in lowered:
        problems.append("Password must not contain part of your email address.")
    return problems


# ----------------------------------------------------------------- sessions
def new_token() -> str:
    return secrets.token_urlsafe(32)  # 256 bits of randomness


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def csrf_token_for(session_token: str, secret_key: str) -> str:
    return hmac.new(secret_key.encode(), b"csrf:" + session_token.encode(), hashlib.sha256).hexdigest()


def tokens_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


# --------------------------------------------------------------------- TOTP
TOTP_PERIOD = 30
CODE_RE = re.compile(r"^\d{6}$")


def new_totp_secret() -> str:
    return pyotp.random_base32()


def encrypt_secret(secret: str, key: str) -> str:
    return Fernet(key.encode()).encrypt(secret.encode()).decode()


def decrypt_secret(token: str, key: str) -> str:
    return Fernet(key.encode()).decrypt(token.encode()).decode()


def provisioning_uri(secret: str, email: str, issuer: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, code: str, last_step: int, now: float | None = None) -> int | None:
    """Return the matching time-step if the code is valid and NOT already used, else None.

    Accepts the previous, current and next 30-second step (clock drift). Any step that is
    <= last_step is rejected, so a code cannot be replayed.
    """
    if not CODE_RE.match(code):
        return None
    totp = pyotp.TOTP(secret)
    base = int((time.time() if now is None else now) // TOTP_PERIOD)
    for offset in (0, -1, 1):
        step = base + offset
        if step <= last_step:
            continue
        if hmac.compare_digest(totp.at(step * TOTP_PERIOD), code):
            return step
    return None


def make_recovery_codes(count: int = 8) -> list[str]:
    """Human-friendly 80-bit codes like 'a1b2c-d3e4f-0a1b2-c3d4e'."""
    codes = []
    for _ in range(count):
        raw = secrets.token_hex(10)
        codes.append("-".join(raw[i:i + 5] for i in range(0, 20, 5)))
    return codes


def hash_recovery_code(code: str, secret_key: str) -> str:
    normalized = code.strip().lower().replace("-", "").replace(" ", "")
    return hmac.new(secret_key.encode(), b"recovery:" + normalized.encode(), hashlib.sha256).hexdigest()
