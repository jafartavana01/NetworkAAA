from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class CheckOut(BaseModel):
    id: str
    check_key: str
    name: str
    description: str
    category: str
    default_severity: str
    required_commands: list[str]
    enabled: bool


class CheckResultOut(BaseModel):
    id: str
    check_key: str
    check_name: str
    device_name: str
    status: str
    severity: str
    title: str
    description: str
    evidence: list[str]
    actual_value: str | None
    expected_value: str | None
    recommendation: str | None
    created_at: datetime


class RunChecksRequest(BaseModel):
    check_keys: list[str] | None = None  # None = run every enabled check
