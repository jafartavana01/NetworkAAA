"""
app.schemas.user
==================
`username` becomes a bare identifier inside a generated tac_plus-ng
`user {}` block, so it's restricted to the same conservative safe
charset as NetworkDevice.name (app.schemas.device) and for the same
reason: no confirmed quoting mechanism exists for that grammar
position, so restriction at input time is the only safe option.

`allowed_source_ips` reuses app.security.parse_allowed_source_ips for
validation -- same format, same helper AdminUser's version uses (see
app.schemas.admin) -- but is NOT YET ENFORCED anywhere in the
generated tac_plus-ng config; see app.models.user's docstring for
exactly why (per-user, not per-group, source-IP restriction has no
directly confirmed tac_plus-ng syntax for this project's current
one-group-per-user data model). Stored and validated now so the
GUI/API/Simulator can exist ahead of that compiler work.

`auth_source` ("local" | "ad") governs which other fields are
required: a "local" user needs a password (on create); an "ad" user
needs `ad_identity` instead and has no local password at all --
tac_plus-ng's MAVIS backend authenticates them against Active
Directory directly (see app.models.user's docstring).
"""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from ..security import parse_allowed_source_ips

_USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")
_VALID_AUTH_SOURCES = ("local", "ad")


class TacacsUserBase(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    full_name: str | None = Field(default=None, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    group_id: str | None = None
    enabled: bool = True
    allowed_source_ips: str | None = Field(default=None, max_length=2000)
    auth_source: str = Field(default="local")
    ad_identity: str | None = Field(default=None, max_length=255)

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

    @field_validator("allowed_source_ips")
    @classmethod
    def validate_allowed_source_ips(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        parse_allowed_source_ips(v)  # raises ValueError on the first bad entry
        return v

    @field_validator("auth_source")
    @classmethod
    def validate_auth_source(cls, v: str) -> str:
        if v not in _VALID_AUTH_SOURCES:
            raise ValueError(f"auth_source must be one of {_VALID_AUTH_SOURCES}.")
        return v

    @model_validator(mode="after")
    def validate_ad_identity_required(self) -> "TacacsUserBase":
        if self.auth_source == "ad" and not (self.ad_identity or "").strip():
            raise ValueError("An AD-linked user needs an AD identity (username or UPN).")
        return self


class TacacsUserCreate(TacacsUserBase):
    # Required only for a "local" user -- validated below, not via
    # Field(...), since whether it's required depends on auth_source.
    password: str | None = Field(default=None, min_length=1, max_length=256)

    @model_validator(mode="after")
    def validate_password_required_for_local(self) -> "TacacsUserCreate":
        if self.auth_source == "local" and not self.password:
            raise ValueError("A password is required for a local user.")
        return self


class TacacsUserUpdate(TacacsUserBase):
    # Leave password unset (None) to keep the existing password -- the
    # GUI never round-trips the hash or plaintext back to the client.
    # Not required even for a "local" user here (unlike create) --
    # omitting it just means "don't change the password."
    password: str | None = Field(default=None, min_length=1, max_length=256)


class TacacsUserOut(TacacsUserBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    group_name: str | None = None

