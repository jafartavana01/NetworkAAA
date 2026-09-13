"""
app.schemas.device_access_grant
==================================
Exactly one of `device_id` / `device_group_id` must be set -- a
grant targets one device OR a whole device group, never both and
never neither. Enforced here with a model-level validator rather than
relying on the database (a single CHECK constraint expressing that
shape across two nullable FKs is awkward in portable SQL), matching
the "clear 400 instead of a raw constraint violation" convention
already used throughout this project's other cross-field validation.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field, model_validator


class DeviceAccessGrantCreate(BaseModel):
    device_id: str | None = None
    device_group_id: str | None = None
    user_group_id: str = Field(min_length=1)

    @model_validator(mode="after")
    def validate_exactly_one_target(self) -> "DeviceAccessGrantCreate":
        if bool(self.device_id) == bool(self.device_group_id):
            raise ValueError("Specify exactly one of device or device group -- not both, not neither.")
        return self


class DeviceAccessGrantOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    device_id: str | None = None
    device_group_id: str | None = None
    user_group_id: str
    device_name: str | None = None
    device_group_name: str | None = None
    user_group_name: str | None = None
    created_by: str | None = None
    created_at: str
