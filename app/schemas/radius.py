"""
app.schemas.radius
=====================
Request/response schemas for platform-level RADIUS settings.

Only `protocol = UDP` is offered. Upstream documents TCP, DTLS and TLS
as supported, but their `listen` syntax was not present in the sample
configuration this implementation was built against, so it is not
offered rather than guessed -- the same rule this project already
applies to IPv6 host addresses.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class RadiusSettingsOut(BaseModel):
    enabled: bool
    auth_port: int
    acct_port: int
    protocol: str
    include_dictionaries: bool
    updated_by: str | None
    updated_at: datetime | None
    #: How many devices currently have RADIUS turned on -- shown so an
    #: admin can see that enabling the listeners will actually serve
    #: something, rather than opening ports nothing uses.
    devices_with_radius: int


class RadiusSettingsUpdate(BaseModel):
    enabled: bool
    # 1812/1813 are the IANA-registered ports and what the upstream
    # sample uses. Anything above 1024 is allowed for non-standard
    # deployments; below that would require the daemon to hold
    # privileges it should not need.
    auth_port: int = Field(default=1812, ge=1025, le=65535)
    acct_port: int = Field(default=1813, ge=1025, le=65535)
    include_dictionaries: bool = True
