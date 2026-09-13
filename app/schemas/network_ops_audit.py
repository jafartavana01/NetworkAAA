from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from .network_ops_checks import CheckResultOut


class AuditCreate(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = None
    check_keys: list[str] = Field(min_length=1)


class AuditOut(BaseModel):
    id: str
    name: str
    description: str | None
    check_keys: list[str]
    created_at: datetime
    updated_at: datetime


class ScoreBreakdownOut(BaseModel):
    score: int
    total_checks: int
    passed: int
    failed: int
    not_applicable: int
    other: int
    findings_by_severity: dict
    deductions_by_severity: dict


class AuditRunOut(BaseModel):
    id: str
    audit_name: str
    job_name: str
    created_by_admin_username: str | None
    created_at: datetime
    score: ScoreBreakdownOut


class AuditRunDetailOut(AuditRunOut):
    results: list[CheckResultOut]
