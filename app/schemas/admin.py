"""
app.schemas.admin
===================
Platform admin account management (distinct from app.schemas.auth's
LoginRequest, which is unauthenticated-by-definition). `allowed_source_ips`
reuses app.security.parse_allowed_source_ips for validation, so the
format accepted here and the format actually enforced at login can
never silently drift apart from each other.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..security import parse_allowed_source_ips


class AdminUserBase(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    is_active: bool = True
    is_superadmin: bool = False
    allowed_source_ips: str | None = Field(default=None, max_length=2000)

    @field_validator("allowed_source_ips")
    @classmethod
    def validate_allowed_source_ips(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        parse_allowed_source_ips(v)  # raises ValueError on the first bad entry
        return v


class AdminUserCreate(AdminUserBase):
    password: str = Field(min_length=8, max_length=256)


class AdminUserUpdate(AdminUserBase):
    # Leave password unset (None) to keep the existing password -- same
    # write-only pattern as every other secret field in this project.
    password: str | None = Field(default=None, min_length=8, max_length=256)


class AdminUserOut(AdminUserBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    created_at: str
    last_login_at: str | None
    is_self: bool = False  # true when this row is the requesting admin's own account
