from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class CommandTemplateCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    vendor: str = Field(default="cisco_ios", max_length=64)
    platform: str | None = Field(default=None, max_length=64)
    device_role: str | None = Field(default=None, max_length=64)
    commands: list[str] = Field(min_length=1)
    command_timeout_seconds: int = Field(default=30, ge=1, le=600)


class CommandTemplateOut(BaseModel):
    id: str
    name: str
    description: str | None
    vendor: str
    platform: str | None
    device_role: str | None
    commands: list[str]
    command_timeout_seconds: int
    created_at: datetime
    updated_at: datetime


class TargetSelection(BaseModel):
    device_ids: list[str] = Field(default_factory=list)
    device_group_ids: list[str] = Field(default_factory=list)


class ResolvedTargetOut(BaseModel):
    device_id: str
    device_name: str
    device_ip_address: str
    resolved_from: str


class CommandJobCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    targets: TargetSelection
    commands: list[str] | None = None  # raw command box (spec section 5)
    template_id: str | None = None  # OR run from a saved template -- one of the two must be given
    ssh_username: str = Field(min_length=1, max_length=128)
    ssh_password: str = Field(min_length=1, max_length=256)
    execution_mode: str = Field(default="sequential", pattern="^(sequential|parallel)$")
    concurrency: int = Field(default=1, ge=1, le=50)
    command_timeout_seconds: int = Field(default=30, ge=1, le=600)
    connection_timeout_seconds: int = Field(default=10, ge=1, le=120)


class CommandJobOut(BaseModel):
    id: str
    name: str
    description: str | None
    commands: list[str]
    source_template_name: str | None
    execution_mode: str
    concurrency: int
    status: str
    created_by_admin_username: str | None
    created_at: datetime
    started_at: datetime | None
    completed_at: datetime | None
    target_count: int = 0


class CommandExecutionOut(BaseModel):
    id: str
    command: str
    command_order: int
    command_classification: str
    status: str
    raw_output: str | None
    error_message: str | None
    duration_ms: int | None


class CommandJobTargetOut(BaseModel):
    id: str
    device_id: str | None
    device_name: str
    device_ip_address: str
    resolved_from: str | None
    status: str
    error_message: str | None
    executions: list[CommandExecutionOut] = Field(default_factory=list)


class CommandJobDetailOut(CommandJobOut):
    targets: list[CommandJobTargetOut] = Field(default_factory=list)
