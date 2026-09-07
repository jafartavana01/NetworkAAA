"""
app.schemas.ncm
==================
Request/response schemas for the NCM API (app.api.routes_ncm).

Follows this project's existing schema conventions (see
app.schemas.security_audit): flat explicit fields rather than passing
ORM objects through, so the API shape is decoupled from the models and
can evolve independently.

Note what is deliberately ABSENT: no schema here carries a password,
credential, or any device secret. Configuration content is exposed
only through the explicit detail/download endpoints, never bundled
into list responses -- a fleet-wide archive list must not ship
hundreds of full device configurations to the browser.
"""
from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field


class NcmConfigurationSummaryOut(BaseModel):
    """Archive/history row. Deliberately WITHOUT configuration_content."""
    id: str
    device_id: str
    device_name: str
    version_number: int
    configuration_type: str
    sha256: str
    size_bytes: int
    source: str
    created_by: str | None
    created_at: datetime


class NcmConfigurationDetailOut(NcmConfigurationSummaryOut):
    configuration_content: str


class NcmBackupRequest(BaseModel):
    """
    Targets may be devices, device groups, or both -- they are
    de-duplicated server-side. At least one target is required rather
    than defaulting to the whole fleet: an accidental empty selection
    SSHing into every device would be a genuinely expensive surprise.
    """
    device_ids: list[str] = Field(default_factory=list)
    device_group_ids: list[str] = Field(default_factory=list)
    configuration_types: list[str] = Field(default_factory=lambda: ["running"])


class NcmBackupResultOut(BaseModel):
    job_display_number: int
    total_devices: int
    succeeded: int
    failed: int
    changed: int
    status: str
    failures: list[str]


class NcmDiffRequest(BaseModel):
    from_configuration_id: str
    to_configuration_id: str


class NcmDiffLineOut(BaseModel):
    type: str  # add | remove | context | meta
    text: str


class NcmDiffOut(BaseModel):
    from_version: int
    to_version: int
    from_created_at: datetime
    to_created_at: datetime
    device_name: str
    configuration_type: str
    added: int
    removed: int
    unchanged: int
    identical: bool
    lines: list[NcmDiffLineOut]


class NcmJobTargetOut(BaseModel):
    device_id: str | None
    device_name: str
    configuration_type: str
    status: str
    configuration_changed: bool
    connection_ok: bool
    retrieval_ok: bool
    error_message: str | None
    configuration_id: str | None


class NcmJobSummaryOut(BaseModel):
    id: str
    display_number: int
    source: str
    status: str
    schedule_name: str | None
    started_by: str | None
    total_devices: int
    succeeded: int
    failed: int
    changed: int
    started_at: datetime
    completed_at: datetime | None


class NcmJobDetailOut(NcmJobSummaryOut):
    targets: list[NcmJobTargetOut]


class NcmScheduleOut(BaseModel):
    id: str
    name: str
    description: str | None
    enabled: bool
    device_ids: list[str]
    device_group_ids: list[str]
    configuration_types: list[str]
    daily_run_time: str
    retention_days: int
    created_by: str | None
    updated_by: str | None
    last_run_at: datetime | None
    created_at: datetime
    updated_at: datetime


class NcmScheduleRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool = True
    device_ids: list[str] = Field(default_factory=list)
    device_group_ids: list[str] = Field(default_factory=list)
    configuration_types: list[str] = Field(default_factory=lambda: ["running"])
    daily_run_time: str = Field(pattern=r"^([01]\d|2[0-3]):[0-5]\d$", description="24-hour HH:MM, server-local time.")
    retention_days: int = Field(default=90, ge=1, le=3650)


class NcmDeviceStatusOut(BaseModel):
    """Per-device NCM state, backing both the device-page panel and the
    overview's device roll-up."""
    device_id: str
    device_name: str
    ip_address: str
    device_group_name: str | None
    latest_version: int | None
    latest_configuration_id: str | None
    latest_backup_at: datetime | None
    latest_source: str | None
    total_versions: int
    last_backup_status: str | None   # success | failed | None (never attempted)
    last_backup_error: str | None


class NcmRecentChangeOut(BaseModel):
    device_id: str
    device_name: str
    configuration_id: str
    version_number: int
    configuration_type: str
    source: str
    created_at: datetime


class NcmOverviewOut(BaseModel):
    total_devices: int
    devices_with_recent_backup: int
    devices_with_failed_backup: int
    devices_never_backed_up: int
    total_configurations: int
    configurations_changed_recently: int
    last_successful_backup_at: datetime | None
    active_jobs: int
    recent_changes: list[NcmRecentChangeOut]
    recent_jobs: list[NcmJobSummaryOut]


class CompareRequest(BaseModel):
    """At least two devices, since one device cannot be compared with
    anything. Capped so a mis-click on "select all" against a large
    fleet cannot ask the server to diff hundreds of configurations in
    one request."""
    device_ids: list[str] = Field(min_length=2, max_length=50)
    configuration_type: str = "running"


class CompareDeviceOut(BaseModel):
    device_id: str
    device_name: str
    ip_address: str | None
    configuration_id: str | None
    version_number: int | None
    created_at: datetime | None
    has_snapshot: bool


class CompareCellOut(BaseModel):
    device_id: str
    present: bool
    matches_majority: bool
    line_count: int


class CompareCategoryOut(BaseModel):
    category: str
    cells: list[CompareCellOut]
    matching_devices: int
    total_devices: int
    match_percent: float


class CompareResultOut(BaseModel):
    devices: list[CompareDeviceOut]
    categories: list[CompareCategoryOut]
    comparable_devices: int
    devices_without_snapshot: list[str]
    identical_devices: int
    differing_devices: int
    consistency_percent: float
    outlier_device_id: str | None
    outlier_difference_count: int
    baseline_device_id: str | None


class DeviceDriftOut(BaseModel):
    device_id: str
    device_name: str
    configuration_type: str
    #: in_sync | drifted | no_baseline | no_snapshot | baseline_gone
    status: str
    baseline_version: int | None
    latest_version: int | None
    baseline_configuration_id: str | None
    latest_configuration_id: str | None
    lines_added: int
    lines_removed: int
    last_backup_at: datetime | None
    baseline_set_at: datetime | None


class DriftOverviewOut(BaseModel):
    configuration_type: str
    total: int
    in_sync: int
    drifted: int
    no_baseline: int
    no_snapshot: int
    baseline_gone: int
    #: no_baseline + no_snapshot + baseline_gone. Reported separately so
    #: a fleet with no baselines set never reads as healthy.
    coverage_gaps: int
    devices: list[DeviceDriftOut]


class SetBaselineRequest(BaseModel):
    configuration_id: str
    notes: str | None = Field(default=None, max_length=2000)


class BaselineOut(BaseModel):
    id: str
    device_id: str
    device_name: str
    configuration_type: str
    configuration_id: str | None
    version_number: int | None
    sha256: str | None
    notes: str | None
    set_by: str | None
    set_at: datetime


class CandidateCreateRequest(BaseModel):
    device_id: str
    title: str = Field(min_length=1, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    configuration_lines: str = Field(min_length=1, max_length=100000)


class CandidateReviewRequest(BaseModel):
    #: approve | reject
    decision: str
    note: str | None = Field(default=None, max_length=2000)


class CandidateOut(BaseModel):
    id: str
    display_number: int
    device_id: str
    device_name: str
    title: str
    description: str | None
    configuration_lines: str
    status: str
    created_by: str | None
    created_at: datetime
    approved_by: str | None
    approved_at: datetime | None
    review_note: str | None
    #: Names of commands the deployer would refuse. Surfaced at read
    #: time so a reviewer sees the problem before approving, not at
    #: deployment when it is too late to be useful.
    blocked_commands: list[str]


class DeploymentOut(BaseModel):
    id: str
    display_number: int
    candidate_id: str | None
    device_id: str | None
    device_name: str
    status: str
    verified_changed: bool
    pre_configuration_id: str | None
    post_configuration_id: str | None
    transcript: str | None
    error_message: str | None
    started_by: str | None
    started_at: datetime
    completed_at: datetime | None


class DeployResultOut(BaseModel):
    ok: bool
    status: str
    deployment_number: int
    verified_changed: bool
    message: str
    blocked_commands: list[str]
