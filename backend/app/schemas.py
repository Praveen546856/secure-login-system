"""Request/response models. Pydantic validates every incoming field before our code runs."""
import re
from datetime import datetime

from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator

from .security import MAX_PASSWORD_LENGTH, password_problems

USERNAME_RE = re.compile(r"^[A-Za-z0-9_]{3,30}$")


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")  # unknown fields are rejected


class RegisterRequest(StrictModel):
    username: str = Field(min_length=3, max_length=30)
    email: EmailStr = Field(max_length=254)
    password: str = Field(max_length=MAX_PASSWORD_LENGTH)

    @field_validator("username")
    @classmethod
    def check_username(cls, value: str) -> str:
        if not USERNAME_RE.match(value):
            raise ValueError("Username must be 3-30 characters: letters, numbers and underscore only.")
        return value

    @field_validator("email")
    @classmethod
    def lower_email(cls, value: str) -> str:
        return value.strip().lower()

    @field_validator("password")
    @classmethod
    def check_password(cls, value: str, info) -> str:
        problems = password_problems(value, info.data.get("username", ""), info.data.get("email", ""))
        if problems:
            raise ValueError(" ".join(problems))
        return value


class LoginRequest(StrictModel):
    email: EmailStr = Field(max_length=254)
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)

    @field_validator("email")
    @classmethod
    def lower_email(cls, value: str) -> str:
        return value.strip().lower()


class TwoFactorLoginRequest(StrictModel):
    challenge: str = Field(min_length=10, max_length=500)
    code: str = Field(min_length=6, max_length=40)  # 6-digit app code or a recovery code


class ChangePasswordRequest(StrictModel):
    current_password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    new_password: str = Field(max_length=MAX_PASSWORD_LENGTH)


class TwoFactorSetupRequest(StrictModel):
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)


class TwoFactorEnableRequest(StrictModel):
    code: str = Field(pattern=r"^\d{6}$")


class TwoFactorDisableRequest(StrictModel):
    password: str = Field(min_length=1, max_length=MAX_PASSWORD_LENGTH)
    code: str = Field(min_length=6, max_length=40)


class UserPublic(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    created_at: datetime
    last_login_at: datetime | None
    two_factor_enabled: bool


class AuthResponse(BaseModel):
    user: UserPublic
    csrf_token: str


class TwoFactorRequiredResponse(BaseModel):
    two_factor_required: bool = True
    challenge: str


class TwoFactorSetupResponse(BaseModel):
    otpauth_uri: str
    secret: str
    qr_svg_data_uri: str


class RecoveryCodesResponse(BaseModel):
    recovery_codes: list[str]


class MessageResponse(BaseModel):
    message: str
