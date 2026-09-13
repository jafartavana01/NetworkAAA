"""
app.schemas.device_group
==========================
Unlike TacacsGroup, this name does NOT become part of the generated
tac_plus-ng config (see app/models/device_group.py) -- but it's kept
to the same conservative identifier charset anyway, for consistency
and to keep the door open if a future phase finds a real config use
for it rather than relaxing validation later.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")


class DeviceGroupBase(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=2000)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not _NAME_PATTERN.match(v):
            raise ValueError(
                "Group name must start with a letter or digit and contain only "
                "letters, digits, hyphens, and underscores (max 64 chars)."
            )
        return v


class DeviceGroupCreate(DeviceGroupBase):
    pass


class DeviceGroupUpdate(DeviceGroupBase):
    pass


class DeviceGroupOut(DeviceGroupBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    member_count: int = 0
