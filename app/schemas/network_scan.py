from __future__ import annotations

from pydantic import BaseModel, Field


class ScanRequest(BaseModel):
    cidr: str = Field(min_length=1, max_length=64)
    ssh_username: str = Field(min_length=1, max_length=128)
    ssh_password: str = Field(min_length=1, max_length=256)


class ScanResultOut(BaseModel):
    ip_address: str
    already_exists: str | None = None  # existing device id, if any
    hostname: str | None = None


class PreviewCommandsRequest(BaseModel):
    platform_ip: str = Field(min_length=1, max_length=64)


class ApplyAaaRequest(BaseModel):
    ip_address: str
    ssh_username: str = Field(min_length=1, max_length=128)
    ssh_password: str = Field(min_length=1, max_length=256)
    platform_ip: str = Field(min_length=1, max_length=64)
    device_group_id: str | None = None
    device_name: str | None = Field(default=None, max_length=64)
    commands: list[str] | None = None  # admin-edited override; auto-generated when omitted
    # See app.schemas.device.DeviceAaaApplyRequest's own docstring for
    # why these exist -- same per-apply-override, falls back to the
    # admin's stored default, then ssh_provision's own built-in one.
    connect_timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    command_timeout_seconds: int | None = Field(default=None, ge=1, le=300)


class ApplyAaaAllRequest(BaseModel):
    ip_addresses: list[str] = Field(min_length=1)
    ssh_username: str = Field(min_length=1, max_length=128)
    ssh_password: str = Field(min_length=1, max_length=256)
    platform_ip: str = Field(min_length=1, max_length=64)
    device_group_id: str | None = None
    commands: list[str] | None = None
    connect_timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    command_timeout_seconds: int | None = Field(default=None, ge=1, le=300)


class ApplyAaaResultOut(BaseModel):
    ip_address: str
    success: bool
    message: str
    command_log: list[str] = Field(default_factory=list)
    device_id: str | None = None
