"""
app.schemas.user
==================
`username` becomes a bare identifier inside a generated tac_plus-ng
`user {}` block, so it's restricted to the same conservative safe
charset as NetworkDevice.name (app.schemas.device) and for the same
reason: no confirmed quoting mechanism exists for that grammar
position, so restriction at input time is the only safe option.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")


class TacacsUserBase(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    full_name: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    group_id: str | None = None
    enabled: bool = True

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not _USERNAME_PATTERN.match(v):
            raise ValueError(
                "Username must start with a letter or digit and contain only "
                "letters, digits, hyphens, and underscores (max 64 chars) -- it is "
                "used as a raw identifier in the generated tac_plus-ng configuration."
            )
        return v


class TacacsUserCreate(TacacsUserBase):
    password: str = Field(min_length=1, max_length=256)


class TacacsUserUpdate(TacacsUserBase):
    # Leave password unset (None) to keep the existing password -- the
    # GUI never round-trips the hash or plaintext back to the client.
    password: str | None = Field(default=None, min_length=1, max_length=256)


class TacacsUserOut(TacacsUserBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    group_name: str | None = None
