"""
app.schemas.admin_role
========================
`permissions` is validated against app.services.permissions.PERMISSION_KEYS
at save time -- an unknown permission string is rejected with a clear
error rather than silently stored and never matching anything.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, field_validator

from ..services.permissions import PERMISSION_KEYS


class AdminRoleBase(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=2000)
    permissions: list[str] = Field(default_factory=list)

    @field_validator("permissions")
    @classmethod
    def validate_permissions(cls, v: list[str]) -> list[str]:
        unknown = [p for p in v if p not in PERMISSION_KEYS]
        if unknown:
            raise ValueError(f"Unknown permission key(s): {', '.join(unknown)}")
        return v


class AdminRoleCreate(AdminRoleBase):
    pass


class AdminRoleUpdate(AdminRoleBase):
    pass


class AdminRoleOut(AdminRoleBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    is_template: bool
    admin_count: int = 0
