"""
app.schemas.security_audit
=============================
Request/response schemas for the Security Center API
(app.api.routes_security). Mirrors this project's established schema
conventions (see app.schemas.network_ops_audit for the closest
existing precedent) -- flat, explicit fields rather than passing
dataclasses straight through, so the API's response shape is decoupled
from app.security_center.engine's internal dataclasses and can evolve
independently.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class AuditUploadRequest(BaseModel):
    raw_config: str = Field(min_length=1, description="Full 'show running-config' text to audit.")
    device_id: str | None = Field(default=None, description="Attach this audit run to an existing NetworkAAA device, if any.")
    device_name: str | None = Field(default=None, max_length=64, description="Display name when device_id is omitted.")


class AuditLiveRequest(BaseModel):
    ssh_username: str = Field(min_length=1, max_length=128)
    ssh_password: str = Field(min_length=1, max_length=256)
    connect_timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    command_timeout_seconds: int | None = Field(default=None, ge=1, le=300)


class FindingOut(BaseModel):
    check_id: str
    domain: str
    title: str
    status: str
    severity: str
    interface_name: str | None
    evidence: list[str]
    evidence_label: str
    recommendation: str
    detail: str
    fix_command: str
    why: str
    risk: str
    attack: str
    best: str
    performance: str
    operational: str
    compatibility: str
    references: list[str]
    correlation_id: str | None


class DomainScoreOut(BaseModel):
    domain: str
    score: float
    fail_count: int
    manual_count: int
    pass_count: int
    warn_count: int


class AuditRunSummaryOut(BaseModel):
    id: str
    device_id: str | None
    device_name: str
    source: str
    status: str
    overall_score: float | None
    compliance_score: float | None
    started_at: datetime
    completed_at: datetime | None


class AuditRunDetailOut(AuditRunSummaryOut):
    risk_level: str | None
    findings: list[FindingOut]
    correlation_findings: list[FindingOut]
    domain_scores: list[DomainScoreOut]
    compliance_summary: dict[str, dict]  # framework_key -> {"total": n, "fail": n, "controls": {...}}


class AuditCompareOut(BaseModel):
    from_run_id: str
    to_run_id: str
    score_delta: float
    new_findings: list[FindingOut]
    resolved_findings: list[FindingOut]
    persistent_findings: list[FindingOut]


class SecurityOverviewOut(BaseModel):
    devices_audited: int
    average_score: float | None
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    manual_review_findings: int
    recent_audits: list[AuditRunSummaryOut]


class SecurityDeviceOut(BaseModel):
    id: str
    name: str
    ip_address: str
    device_group_name: str | None
    latest_score: float | None
    latest_risk_level: str | None
    latest_audited_at: datetime | None
    latest_audit_run_id: str | None


class FleetFindingOut(BaseModel):
    """
    A single finding plus the device context a fleet-wide view needs
    that a per-audit FindingOut doesn't carry on its own -- which
    device it came from and when. Only ever built from each device's
    OWN latest completed audit (see list_fleet_findings's own
    docstring), never from older superseded runs.
    """
    device_id: str
    device_name: str
    audit_run_id: str
    audited_at: datetime
    check_id: str
    domain: str
    title: str
    status: str
    severity: str
    interface_name: str | None
    recommendation: str
    fix_command: str
    correlation_id: str | None


class AuditScheduleOut(BaseModel):
    enabled: bool
    ssh_username: str
    has_password: bool
    daily_run_time: str
    management_ip_note: str | None
    last_run_at: datetime | None
    last_run_status: str | None
    last_run_summary: str | None


class AuditScheduleUpdateRequest(BaseModel):
    enabled: bool
    ssh_username: str = Field(min_length=1, max_length=128)
    ssh_password: str | None = Field(default=None, max_length=256, description="Leave blank to keep the current password.")
    daily_run_time: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$", description="24-hour HH:MM, server-local time.")
    management_ip_note: str | None = Field(default=None, max_length=255)
