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
    # Added for the Finding Detail Drawer -- the drawer shows evidence,
    # "why this matters" and compliance mappings, and fetching those in
    # a second per-row request would be an N+1 against a table the user
    # is clicking through quickly. They come from the same already-
    # loaded AuditFinding row, so this costs one wider response instead
    # of one request per opened finding.
    detail: str
    why: str
    risk: str
    evidence: list
    evidence_label: str
    compliance_refs: dict


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


class BatchDeviceRowOut(BaseModel):
    device_id: str | None
    device_name: str
    ip_address: str | None
    high: int
    medium: int
    low: int
    score: float | None
    risk_level: str | None
    status: str
    last_scan_at: datetime


class BatchCategoryCountOut(BaseModel):
    domain: str
    fail_count: int


class BatchTopFindingOut(BaseModel):
    check_id: str
    title: str
    severity: str
    device_count: int


class AuditBatchSummaryOut(BaseModel):
    id: str
    display_number: int
    status: str
    source: str
    target_description: str
    started_by_admin_username: str | None
    started_at: datetime
    completed_at: datetime | None
    duration_seconds: int | None

    total_devices: int
    devices_succeeded: int
    devices_failed: int
    total_checks: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    average_score: float | None

    category_breakdown: list[BatchCategoryCountOut]
    top_findings: list[BatchTopFindingOut]
    devices: list[BatchDeviceRowOut]


class AuditBatchSummaryListItemOut(BaseModel):
    id: str
    display_number: int
    status: str
    started_at: datetime
    total_devices: int


class DashboardDomainScoreOut(BaseModel):
    """Fleet-wide average score for one security domain, across every
    device's own most recent completed audit."""
    domain: str
    score: float
    fail_count: int
    manual_count: int


class DashboardSeverityCountOut(BaseModel):
    severity: str
    count: int


class DashboardTrendPointOut(BaseModel):
    """One real historical data point -- never synthesized. Points come
    only from audit runs that actually exist and completed."""
    label: str
    score: float
    audit_run_id: str


class DashboardComplianceOut(BaseModel):
    framework: str
    passed: int
    failed: int
    manual_review: int
    percentage: float


class DashboardRiskyDeviceOut(BaseModel):
    device_id: str | None
    device_name: str
    score: float | None
    risk_level: str | None
    critical: int
    high: int
    medium: int


class DashboardTopRiskOut(BaseModel):
    check_id: str
    title: str
    severity: str
    domain: str
    device_name: str
    device_id: str | None
    risk: str | None
    audit_run_id: str


class DashboardHeatmapCellOut(BaseModel):
    device_name: str
    device_id: str | None
    domain: str
    score: float
    fail_count: int
    manual_count: int


class SecurityDashboardOut(BaseModel):
    """
    Everything the redesigned Security Center Overview needs, in ONE
    request -- per this feature's own performance requirement that the
    Overview must not fire a dozen independent queries. Every field
    here is derived from real stored audit rows; sections with no data
    come back empty so the GUI can show a real empty state rather than
    a fabricated chart.
    """
    devices_audited: int
    average_score: float | None
    previous_average_score: float | None
    compliance_score: float | None

    severity_counts: list[DashboardSeverityCountOut]
    total_findings: int
    manual_review_findings: int
    failed_checks: int

    domain_scores: list[DashboardDomainScoreOut]
    score_trend: list[DashboardTrendPointOut]
    compliance: list[DashboardComplianceOut]
    risky_devices: list[DashboardRiskyDeviceOut]
    top_risks: list[DashboardTopRiskOut]
    heatmap: list[DashboardHeatmapCellOut]
    heatmap_domains: list[str]
