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


class ScoreContributionOut(BaseModel):
    """One domain's contribution to the gap between a perfect score and
    the actual one.

    `points_lost` is the domain's shortfall (100 - its own score)
    weighted by its share of all domains, so the values sum to the
    fleet-wide gap. This is derived from the domain scores the engine
    itself produced -- it is NOT a second scoring algorithm, and it
    cannot be, because `applicable_weight` (the engine's real
    denominator) is not persisted per domain. The API labels this an
    approximate attribution for exactly that reason.
    """
    domain: str
    score: float
    points_lost: float
    fail_count: int
    manual_count: int


class ScoreExplanationOut(BaseModel):
    base_score: float
    final_score: float | None
    total_deduction: float
    contributions: list[ScoreContributionOut]
    is_approximate: bool


class ManualReviewCategoryOut(BaseModel):
    domain: str
    count: int


class ManualReviewOut(BaseModel):
    total: int
    categories: list[ManualReviewCategoryOut]


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
    score_explanation: ScoreExplanationOut | None
    manual_review: ManualReviewOut


class ComplianceControlOut(BaseModel):
    """One control within a framework, aggregated across the fleet.

    `devices_failing` / `devices_passing` count DEVICES, not findings:
    a control failing on three devices is one control needing
    attention on three devices, which is the number an auditor
    actually asks about.
    """
    control_id: str
    devices_passing: int
    devices_failing: int
    devices_manual: int
    status: str  # fail | manual_review | pass -- worst status wins


class ComplianceFrameworkOut(BaseModel):
    framework_key: str
    framework_name: str
    total_controls: int
    passing_controls: int
    failing_controls: int
    manual_controls: int
    percentage: float
    controls: list[ComplianceControlOut]


class ComplianceOverviewOut(BaseModel):
    devices_audited: int
    frameworks: list[ComplianceFrameworkOut]


class ActivityEventOut(BaseModel):
    """One real audit run, shaped for the activity timeline.

    Every event corresponds to a stored AuditRun -- the timeline never
    synthesizes entries like "3 findings resolved" unless a real row
    supports it. `score_delta` is populated only when that device has
    an earlier completed run to compare against; otherwise it stays
    null and the GUI shows no trend arrow rather than implying one.
    """
    audit_run_id: str
    device_id: str | None
    device_name: str
    source: str
    status: str
    overall_score: float | None
    score_delta: float | None
    started_at: datetime


class BulkAuditRequest(BaseModel):
    """Audit a chosen set of devices as one job.

    Empty `device_ids` is rejected rather than silently treated as
    "everything" -- an accidental empty selection auditing the entire
    fleet would be a genuinely surprising and expensive outcome.
    """
    device_ids: list[str] = Field(min_length=1)


class BulkAuditResultOut(BaseModel):
    batch_display_number: int
    total_devices: int
    succeeded: int
    failed: int
    status: str
    summary: str




class ComplianceFindingOut(BaseModel):
    """One real audit finding contributing to a control's status.

    Everything here comes from the stored AuditFinding row and the
    framework's own mapping file -- the title, the recommendation and
    the fix are what the audit engine itself produced for that check,
    not remediation text written for the compliance view.
    """
    check_id: str
    title: str
    domain: str
    status: str
    severity: str
    device_name: str
    device_id: str | None
    recommendation: str
    fix_command: str
    why: str
    relationship: str  # "direct" | "supporting" -- from the mapping file


class ComplianceControlDetailOut(BaseModel):
    control_id: str
    control_title: str
    framework_key: str
    framework_name: str
    status: str
    devices_passing: int
    devices_failing: int
    devices_manual: int
    findings: list[ComplianceFindingOut]
