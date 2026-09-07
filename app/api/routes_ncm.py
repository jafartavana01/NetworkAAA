"""
app.api.routes_ncm
=====================
NCM API -- configuration archive, diff, backups, jobs and schedules.

Follows this project's existing API conventions: `require_permission`
dependencies on every endpoint, `verify_csrf` on every mutating one,
Pydantic response models, and HTTPException with safe messages.

Credential handling is entirely absent from this module by design:
backups read the platform's existing encrypted service account through
the backup service, and no endpoint accepts, returns, or logs a
password.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..models.audit_schedule_settings import AuditScheduleSettings
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..models.ncm import (
    NcmBackupJob, NcmBackupJobTarget, NcmBackupSchedule, NcmBaseline, NcmCandidate,
    NcmConfiguration, NcmDeployment,
)
from ..schemas.ncm import (
    BaselineOut, CandidateCreateRequest, CandidateOut, CandidateReviewRequest,
    CompareCategoryOut, CompareCellOut, CompareDeviceOut, CompareRequest,
    CompareResultOut, DeployResultOut, DeploymentOut, DeviceDriftOut, DriftOverviewOut,
    SetBaselineRequest,
    NcmBackupRequest, NcmBackupResultOut, NcmConfigurationDetailOut, NcmConfigurationSummaryOut,
    NcmDeviceStatusOut, NcmDiffLineOut, NcmDiffOut, NcmDiffRequest, NcmJobDetailOut, NcmJobSummaryOut,
    NcmJobTargetOut, NcmOverviewOut, NcmRecentChangeOut, NcmScheduleOut, NcmScheduleRequest,
)
from ..services import ncm_archive, ncm_backup, ncm_compare, ncm_deploy, ncm_drift
from .deps import require_permission, verify_csrf

router = APIRouter(prefix="/api/ncm", tags=["ncm"])

#: A device is "recently backed up" within this window. Chosen to be
#: comfortably longer than a daily schedule so one missed night does
#: not immediately paint the fleet red.
RECENT_BACKUP_HOURS = 48


def _parse_uuids(values: list[str], field_name: str) -> list[uuid.UUID]:
    try:
        return [uuid.UUID(v) for v in values]
    except (ValueError, AttributeError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"One or more {field_name} were malformed.")


def _config_summary(c: NcmConfiguration) -> NcmConfigurationSummaryOut:
    return NcmConfigurationSummaryOut(
        id=str(c.id), device_id=str(c.device_id), device_name=c.device_name,
        version_number=c.version_number, configuration_type=c.configuration_type,
        sha256=c.sha256, size_bytes=c.size_bytes, source=c.source,
        created_by=c.created_by, created_at=c.created_at,
    )


def _job_summary(j: NcmBackupJob) -> NcmJobSummaryOut:
    return NcmJobSummaryOut(
        id=str(j.id), display_number=j.display_number, source=j.source, status=j.status,
        schedule_name=j.schedule_name, started_by=j.started_by, total_devices=j.total_devices,
        succeeded=j.succeeded, failed=j.failed, changed=j.changed,
        started_at=j.started_at, completed_at=j.completed_at,
    )


def _split(raw: str) -> list[str]:
    return [x.strip() for x in (raw or "").split(",") if x.strip()]


def _schedule_out(s: NcmBackupSchedule) -> NcmScheduleOut:
    return NcmScheduleOut(
        id=str(s.id), name=s.name, description=s.description, enabled=s.enabled,
        device_ids=_split(s.device_ids), device_group_ids=_split(s.device_group_ids),
        configuration_types=_split(s.configuration_types), daily_run_time=s.daily_run_time,
        retention_days=s.retention_days, created_by=s.created_by, updated_by=s.updated_by,
        last_run_at=s.last_run_at, created_at=s.created_at, updated_at=s.updated_at,
    )


# ---------------------------------------------------------------- overview

@router.get("/overview", response_model=NcmOverviewOut)
def get_overview(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    """
    Every figure here is derived from stored rows. Sections with no
    data return zero or an empty list rather than a placeholder --
    "never backed up" is a real, useful number, not a gap to fill.
    """
    devices = db.query(NetworkDevice).filter(NetworkDevice.enabled.is_(True)).all()
    total_devices = len(devices)
    device_ids = [d.id for d in devices]

    cutoff = datetime.now(timezone.utc) - timedelta(hours=RECENT_BACKUP_HOURS)

    latest_success_by_device: dict = {}
    latest_status_by_device: dict = {}
    if device_ids:
        targets = (
            db.query(NcmBackupJobTarget)
            .filter(NcmBackupJobTarget.device_id.in_(device_ids))
            .order_by(NcmBackupJobTarget.created_at.desc())
            .all()
        )
        for t in targets:
            # First row per device wins -- the list is newest-first.
            latest_status_by_device.setdefault(t.device_id, t)
            if t.status == "success":
                latest_success_by_device.setdefault(t.device_id, t)

    recent = sum(
        1 for d in device_ids
        if (t := latest_success_by_device.get(d)) is not None and t.created_at >= cutoff
    )
    failed = sum(1 for d in device_ids if (t := latest_status_by_device.get(d)) is not None and t.status == "failed")
    never = sum(1 for d in device_ids if d not in latest_status_by_device)

    total_configs = db.query(func.count(NcmConfiguration.id)).scalar() or 0
    changed_recently = (
        db.query(func.count(NcmConfiguration.id)).filter(NcmConfiguration.created_at >= cutoff).scalar() or 0
    )

    last_success = max(
        (t.created_at for t in latest_success_by_device.values()), default=None
    )

    active_jobs = db.query(func.count(NcmBackupJob.id)).filter(NcmBackupJob.status == "running").scalar() or 0

    recent_changes = (
        db.query(NcmConfiguration).order_by(NcmConfiguration.created_at.desc()).limit(10).all()
    )
    recent_jobs = db.query(NcmBackupJob).order_by(NcmBackupJob.started_at.desc()).limit(5).all()

    return NcmOverviewOut(
        total_devices=total_devices, devices_with_recent_backup=recent,
        devices_with_failed_backup=failed, devices_never_backed_up=never,
        total_configurations=total_configs, configurations_changed_recently=changed_recently,
        last_successful_backup_at=last_success, active_jobs=active_jobs,
        recent_changes=[
            NcmRecentChangeOut(
                device_id=str(c.device_id), device_name=c.device_name, configuration_id=str(c.id),
                version_number=c.version_number, configuration_type=c.configuration_type,
                source=c.source, created_at=c.created_at,
            )
            for c in recent_changes
        ],
        recent_jobs=[_job_summary(j) for j in recent_jobs],
    )


@router.get("/devices", response_model=list[NcmDeviceStatusOut])
def list_device_status(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    """Every managed device with its NCM state -- backs the archive's
    device list and the per-device panel."""
    devices = db.query(NetworkDevice).order_by(NetworkDevice.name.asc()).all()
    groups = {g.id: g.name for g in db.query(DeviceGroup).all()}
    device_ids = [d.id for d in devices]

    latest_config: dict = {}
    counts: dict = {}
    latest_target: dict = {}
    if device_ids:
        for c in (
            db.query(NcmConfiguration)
            .filter(NcmConfiguration.device_id.in_(device_ids))
            .order_by(NcmConfiguration.created_at.desc())
            .all()
        ):
            latest_config.setdefault(c.device_id, c)
            counts[c.device_id] = counts.get(c.device_id, 0) + 1
        for t in (
            db.query(NcmBackupJobTarget)
            .filter(NcmBackupJobTarget.device_id.in_(device_ids))
            .order_by(NcmBackupJobTarget.created_at.desc())
            .all()
        ):
            latest_target.setdefault(t.device_id, t)

    out = []
    for d in devices:
        c = latest_config.get(d.id)
        t = latest_target.get(d.id)
        out.append(NcmDeviceStatusOut(
            device_id=str(d.id), device_name=d.name, ip_address=d.ip_address,
            device_group_name=groups.get(d.device_group_id),
            latest_version=c.version_number if c else None,
            latest_configuration_id=str(c.id) if c else None,
            latest_backup_at=c.created_at if c else None,
            latest_source=c.source if c else None,
            total_versions=counts.get(d.id, 0),
            last_backup_status=t.status if t else None,
            last_backup_error=t.error_message if t else None,
        ))
    return out


# ------------------------------------------------------- configurations

@router.get("/configurations", response_model=list[NcmConfigurationSummaryOut])
def list_configurations(
    device_id: str | None = None,
    configuration_type: str | None = None,
    limit: int = 200,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    """
    Archive listing. Never includes configuration_content -- shipping
    hundreds of full device configurations to the browser to render a
    table would be both slow and needless; content is fetched per
    snapshot on demand.
    """
    limit = max(1, min(limit, 1000))
    q = db.query(NcmConfiguration)
    if device_id:
        q = q.filter(NcmConfiguration.device_id == _parse_uuids([device_id], "device ids")[0])
    if configuration_type:
        q = q.filter(NcmConfiguration.configuration_type == configuration_type)
    rows = q.order_by(NcmConfiguration.created_at.desc()).limit(limit).all()
    return [_config_summary(c) for c in rows]


@router.get("/configurations/{configuration_id}", response_model=NcmConfigurationDetailOut)
def get_configuration(
    configuration_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    c = db.query(NcmConfiguration).filter(
        NcmConfiguration.id == _parse_uuids([configuration_id], "configuration ids")[0]
    ).first()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Configuration not found.")
    base = _config_summary(c)
    return NcmConfigurationDetailOut(**base.model_dump(), configuration_content=c.configuration_content)


@router.get("/configurations/{configuration_id}/download")
def download_configuration(
    configuration_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:download")),
):
    """Separate permission from viewing: taking a full device
    configuration off the platform as a file is a higher-trust action
    than reading it in the UI."""
    c = db.query(NcmConfiguration).filter(
        NcmConfiguration.id == _parse_uuids([configuration_id], "configuration ids")[0]
    ).first()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Configuration not found.")

    # Filename is built from the device name with anything non-trivial
    # stripped -- a device name is admin-supplied, and it must not be
    # able to inject header content or path separators.
    safe_name = "".join(ch for ch in c.device_name if ch.isalnum() or ch in "-_") or "device"
    filename = f"{safe_name}_{c.configuration_type}_v{c.version_number}.cfg"
    return Response(
        content=c.configuration_content,
        media_type="text/plain; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@router.delete("/configurations/{configuration_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(verify_csrf)])
def delete_configuration(
    configuration_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:delete")),
):
    c = db.query(NcmConfiguration).filter(
        NcmConfiguration.id == _parse_uuids([configuration_id], "configuration ids")[0]
    ).first()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Configuration not found.")
    db.delete(c)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/devices/{device_id}/history", response_model=list[NcmConfigurationSummaryOut])
def device_history(
    device_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    rows = (
        db.query(NcmConfiguration)
        .filter(NcmConfiguration.device_id == _parse_uuids([device_id], "device ids")[0])
        .order_by(NcmConfiguration.created_at.desc())
        .all()
    )
    return [_config_summary(c) for c in rows]


# --------------------------------------------------------------- backup

@router.post("/backup", response_model=NcmBackupResultOut, dependencies=[Depends(verify_csrf)])
def run_backup(
    payload: NcmBackupRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("ncm:backup")),
):
    """
    Manual backup of selected devices and/or device groups, de-duplicated
    server-side. Uses the platform's existing encrypted service account;
    if none is configured this says so plainly rather than reporting an
    opaque failure per device.
    """
    if not payload.device_ids and not payload.device_group_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Select at least one device or device group.")

    types = [t.strip() for t in payload.configuration_types if t.strip()] or ["running"]

    settings = db.query(AuditScheduleSettings).first()
    if not settings or not settings.ssh_username or not settings.ssh_password_encrypted:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="No backup service account is configured. Set one up under Security Center → Scheduled Audits first.",
        )

    devices = ncm_backup.resolve_target_devices(
        db,
        _parse_uuids(payload.device_ids, "device ids"),
        _parse_uuids(payload.device_group_ids, "device group ids"),
    )
    if not devices:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="No enabled devices matched that selection.")

    outcome = ncm_backup.run_backup(
        db, devices=devices, configuration_types=types,
        ssh_username=settings.ssh_username,
        ssh_password=security.decrypt_secret(settings.ssh_password_encrypted),
        source="manual", started_by=admin.username,
    )
    return NcmBackupResultOut(
        job_display_number=outcome.job_display_number, total_devices=outcome.total,
        succeeded=outcome.succeeded, failed=outcome.failed, changed=outcome.changed,
        status=outcome.status, failures=outcome.failures,
    )


# ----------------------------------------------------------------- diff

@router.post("/diff", response_model=NcmDiffOut, dependencies=[Depends(verify_csrf)])
def diff_configurations(
    payload: NcmDiffRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:diff")),
):
    ids = _parse_uuids([payload.from_configuration_id, payload.to_configuration_id], "configuration ids")
    rows = db.query(NcmConfiguration).filter(NcmConfiguration.id.in_(ids)).all()
    by_id = {c.id: c for c in rows}
    # ids[0] and ids[1] may be the SAME id (comparing a version with
    # itself); a dict lookup handles that correctly where indexing the
    # query result by position would not, since the query returns one
    # row for a repeated id.
    a = by_id.get(ids[0])
    b = by_id.get(ids[1])
    if not a or not b:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="One or both configurations were not found.")
    if a.device_id != b.device_id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Both versions must belong to the same device.")

    result = ncm_archive.diff_configurations(
        a.configuration_content, b.configuration_content,
        from_label=f"v{a.version_number}", to_label=f"v{b.version_number}",
    )
    return NcmDiffOut(
        from_version=a.version_number, to_version=b.version_number,
        from_created_at=a.created_at, to_created_at=b.created_at,
        device_name=a.device_name, configuration_type=a.configuration_type,
        added=result.added, removed=result.removed, unchanged=result.unchanged,
        identical=result.identical,
        lines=[NcmDiffLineOut(type=l["type"], text=l["text"]) for l in result.lines],
    )


# ----------------------------------------------------------------- jobs

@router.get("/jobs", response_model=list[NcmJobSummaryOut])
def list_jobs(
    limit: int = 50,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    limit = max(1, min(limit, 200))
    rows = db.query(NcmBackupJob).order_by(NcmBackupJob.started_at.desc()).limit(limit).all()
    return [_job_summary(j) for j in rows]


@router.get("/jobs/{job_id}", response_model=NcmJobDetailOut)
def get_job(
    job_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    j = db.query(NcmBackupJob).filter(NcmBackupJob.id == _parse_uuids([job_id], "job ids")[0]).first()
    if not j:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Backup job not found.")
    targets = (
        db.query(NcmBackupJobTarget)
        .filter(NcmBackupJobTarget.job_id == j.id)
        .order_by(NcmBackupJobTarget.device_name.asc())
        .all()
    )
    return NcmJobDetailOut(
        **_job_summary(j).model_dump(),
        targets=[
            NcmJobTargetOut(
                device_id=str(t.device_id) if t.device_id else None, device_name=t.device_name,
                configuration_type=t.configuration_type, status=t.status,
                configuration_changed=t.configuration_changed, connection_ok=t.connection_ok,
                retrieval_ok=t.retrieval_ok, error_message=t.error_message,
                configuration_id=str(t.configuration_id) if t.configuration_id else None,
            )
            for t in targets
        ],
    )


# ------------------------------------------------------------ schedules

@router.get("/schedules", response_model=list[NcmScheduleOut])
def list_schedules(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    rows = db.query(NcmBackupSchedule).order_by(NcmBackupSchedule.name.asc()).all()
    return [_schedule_out(s) for s in rows]


@router.post("/schedules", response_model=NcmScheduleOut, dependencies=[Depends(verify_csrf)])
def create_schedule(
    payload: NcmScheduleRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("ncm:schedule")),
):
    if not payload.device_ids and not payload.device_group_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Select at least one device or device group.")
    if db.query(NcmBackupSchedule).filter(NcmBackupSchedule.name == payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A schedule with that name already exists.")

    # Validate the ids parse before storing them -- catching a malformed
    # id here beats discovering it at 02:00 when the schedule runs.
    _parse_uuids(payload.device_ids, "device ids")
    _parse_uuids(payload.device_group_ids, "device group ids")

    s = NcmBackupSchedule(
        name=payload.name, description=payload.description, enabled=payload.enabled,
        device_ids=",".join(payload.device_ids), device_group_ids=",".join(payload.device_group_ids),
        configuration_types=",".join(payload.configuration_types or ["running"]),
        daily_run_time=payload.daily_run_time, retention_days=payload.retention_days,
        created_by=admin.username, updated_by=admin.username,
    )
    db.add(s)
    db.commit()
    db.refresh(s)
    return _schedule_out(s)


@router.put("/schedules/{schedule_id}", response_model=NcmScheduleOut, dependencies=[Depends(verify_csrf)])
def update_schedule(
    schedule_id: str,
    payload: NcmScheduleRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("ncm:schedule")),
):
    s = db.query(NcmBackupSchedule).filter(
        NcmBackupSchedule.id == _parse_uuids([schedule_id], "schedule ids")[0]
    ).first()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Schedule not found.")
    if not payload.device_ids and not payload.device_group_ids:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Select at least one device or device group.")

    clash = db.query(NcmBackupSchedule).filter(
        NcmBackupSchedule.name == payload.name, NcmBackupSchedule.id != s.id
    ).first()
    if clash:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A schedule with that name already exists.")

    _parse_uuids(payload.device_ids, "device ids")
    _parse_uuids(payload.device_group_ids, "device group ids")

    s.name = payload.name
    s.description = payload.description
    s.enabled = payload.enabled
    s.device_ids = ",".join(payload.device_ids)
    s.device_group_ids = ",".join(payload.device_group_ids)
    s.configuration_types = ",".join(payload.configuration_types or ["running"])
    s.daily_run_time = payload.daily_run_time
    s.retention_days = payload.retention_days
    s.updated_by = admin.username
    db.commit()
    db.refresh(s)
    return _schedule_out(s)


@router.delete("/schedules/{schedule_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(verify_csrf)])
def delete_schedule(
    schedule_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:schedule")),
):
    s = db.query(NcmBackupSchedule).filter(
        NcmBackupSchedule.id == _parse_uuids([schedule_id], "schedule ids")[0]
    ).first()
    if not s:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Schedule not found.")
    db.delete(s)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/compare", response_model=CompareResultOut, dependencies=[Depends(verify_csrf)])
def compare_configurations(
    payload: CompareRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:diff")),
):
    """
    Compares the LATEST stored snapshot of each selected device.

    Gated on `ncm:diff` -- the same permission the two-version diff
    uses, since this is the same capability applied across devices.

    Devices with no snapshot are returned in `devices_without_snapshot`
    rather than dropped: "we have never backed this device up" is a
    finding an operator needs to see, not an absence to hide. Nothing
    is retrieved from a device here -- this compares what is already
    archived, so an unreachable device simply has no newer snapshot
    rather than failing the comparison.
    """
    device_uuids = _parse_uuids(payload.device_ids, "device ids")

    devices = db.query(NetworkDevice).filter(NetworkDevice.id.in_(device_uuids)).all()
    if not devices:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="None of those devices were found.")

    # Latest snapshot per device, of the requested type, in one query
    # rather than one per device.
    rows = (
        db.query(NcmConfiguration)
        .filter(
            NcmConfiguration.device_id.in_(device_uuids),
            NcmConfiguration.configuration_type == payload.configuration_type,
        )
        .order_by(NcmConfiguration.created_at.desc())
        .all()
    )
    latest: dict = {}
    for c in rows:
        latest.setdefault(c.device_id, c)

    by_id = {d.id: d for d in devices}
    inputs = []
    for device_uuid in device_uuids:
        d = by_id.get(device_uuid)
        if not d:
            continue
        c = latest.get(device_uuid)
        inputs.append(ncm_compare.DeviceConfigInput(
            device_id=str(d.id), device_name=d.name, ip_address=d.ip_address,
            configuration_id=str(c.id) if c else None,
            version_number=c.version_number if c else None,
            created_at=c.created_at if c else None,
            content=c.configuration_content if c else None,
        ))

    result = ncm_compare.compare_devices(inputs)

    return CompareResultOut(
        devices=[CompareDeviceOut(**d) for d in result.devices],
        categories=[
            CompareCategoryOut(
                category=r.category,
                cells=[CompareCellOut(
                    device_id=c.device_id, present=c.present,
                    matches_majority=c.matches_majority, line_count=c.line_count,
                ) for c in r.cells],
                matching_devices=r.matching_devices, total_devices=r.total_devices,
                match_percent=r.match_percent,
            )
            for r in result.categories
        ],
        comparable_devices=result.comparable_devices,
        devices_without_snapshot=result.devices_without_snapshot,
        identical_devices=result.identical_devices,
        differing_devices=result.differing_devices,
        consistency_percent=result.consistency_percent,
        outlier_device_id=result.outlier_device_id,
        outlier_difference_count=result.outlier_difference_count,
        baseline_device_id=result.baseline_device_id,
    )


# --------------------------------------------------- baselines / drift

@router.get("/drift", response_model=DriftOverviewOut)
def get_drift(
    configuration_type: str = "running",
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    """
    Fleet drift: every enabled device's latest snapshot against its
    designated baseline.

    Nothing is retrieved from a device here -- drift describes what has
    been ARCHIVED. A device that changed but has not been backed up
    since shows as its real coverage state rather than as "in sync",
    which would be a false all-clear.
    """
    drifts = ncm_drift.compute_fleet_drift(db, configuration_type)
    counts = ncm_drift.summarize(drifts)
    return DriftOverviewOut(
        configuration_type=configuration_type,
        total=counts["total"], in_sync=counts[ncm_drift.STATUS_IN_SYNC],
        drifted=counts[ncm_drift.STATUS_DRIFTED],
        no_baseline=counts[ncm_drift.STATUS_NO_BASELINE],
        no_snapshot=counts[ncm_drift.STATUS_NO_SNAPSHOT],
        baseline_gone=counts[ncm_drift.STATUS_BASELINE_GONE],
        coverage_gaps=counts["coverage_gaps"],
        devices=[
            DeviceDriftOut(
                device_id=d.device_id, device_name=d.device_name,
                configuration_type=d.configuration_type, status=d.status,
                baseline_version=d.baseline_version, latest_version=d.latest_version,
                baseline_configuration_id=d.baseline_configuration_id,
                latest_configuration_id=d.latest_configuration_id,
                lines_added=d.lines_added, lines_removed=d.lines_removed,
                last_backup_at=d.last_backup_at, baseline_set_at=d.baseline_set_at,
            )
            for d in drifts
        ],
    )


@router.get("/baselines", response_model=list[BaselineOut])
def list_baselines(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    rows = db.query(NcmBaseline).order_by(NcmBaseline.device_name.asc()).all()
    return [
        BaselineOut(
            id=str(b.id), device_id=str(b.device_id), device_name=b.device_name,
            configuration_type=b.configuration_type,
            configuration_id=str(b.configuration_id) if b.configuration_id else None,
            version_number=b.version_number, sha256=b.sha256, notes=b.notes,
            set_by=b.set_by, set_at=b.set_at,
        )
        for b in rows
    ]


@router.put("/devices/{device_id}/baseline", response_model=BaselineOut,
            dependencies=[Depends(verify_csrf)])
def set_baseline(
    device_id: str,
    payload: SetBaselineRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("ncm:schedule")),
):
    """
    Designates an archived snapshot as this device's baseline.

    Gated on `ncm:schedule` rather than `ncm:view`: declaring what
    "correct" means for a device is a configuration-management
    decision, not a read.

    The snapshot must belong to THIS device -- designating another
    device's configuration as the baseline would make every future
    drift comparison meaningless, so it is rejected rather than
    trusted.
    """
    device_uuid = _parse_uuids([device_id], "device ids")[0]
    config_uuid = _parse_uuids([payload.configuration_id], "configuration ids")[0]

    device = db.query(NetworkDevice).filter(NetworkDevice.id == device_uuid).first()
    if not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")

    config = db.query(NcmConfiguration).filter(NcmConfiguration.id == config_uuid).first()
    if not config:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Configuration not found.")
    if config.device_id != device_uuid:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="That configuration belongs to a different device.",
        )

    baseline = (
        db.query(NcmBaseline)
        .filter(
            NcmBaseline.device_id == device_uuid,
            NcmBaseline.configuration_type == config.configuration_type,
        )
        .first()
    )
    if baseline is None:
        baseline = NcmBaseline(device_id=device_uuid, configuration_type=config.configuration_type)
        db.add(baseline)

    baseline.device_name = device.name
    baseline.configuration_id = config.id
    baseline.version_number = config.version_number
    baseline.sha256 = config.sha256
    baseline.notes = payload.notes
    baseline.set_by = admin.username
    db.commit()
    db.refresh(baseline)

    return BaselineOut(
        id=str(baseline.id), device_id=str(baseline.device_id), device_name=baseline.device_name,
        configuration_type=baseline.configuration_type,
        configuration_id=str(baseline.configuration_id) if baseline.configuration_id else None,
        version_number=baseline.version_number, sha256=baseline.sha256,
        notes=baseline.notes, set_by=baseline.set_by, set_at=baseline.set_at,
    )


@router.delete("/devices/{device_id}/baseline", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(verify_csrf)])
def clear_baseline(
    device_id: str,
    configuration_type: str = "running",
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:schedule")),
):
    """Removes the baseline designation only. The archived snapshot it
    pointed at is untouched -- clearing what counts as 'correct' must
    never delete configuration history."""
    device_uuid = _parse_uuids([device_id], "device ids")[0]
    baseline = (
        db.query(NcmBaseline)
        .filter(
            NcmBaseline.device_id == device_uuid,
            NcmBaseline.configuration_type == configuration_type,
        )
        .first()
    )
    if baseline is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="No baseline set for that device.")
    db.delete(baseline)
    db.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ------------------------------------------- candidates / deployments

def _candidate_out(c: NcmCandidate) -> CandidateOut:
    return CandidateOut(
        id=str(c.id), display_number=c.display_number, device_id=str(c.device_id),
        device_name=c.device_name, title=c.title, description=c.description,
        configuration_lines=c.configuration_lines, status=c.status,
        created_by=c.created_by, created_at=c.created_at,
        approved_by=c.approved_by, approved_at=c.approved_at, review_note=c.review_note,
        blocked_commands=ncm_deploy.check_dangerous_commands(
            ncm_deploy.parse_configuration_lines(c.configuration_lines)
        ),
    )


def _deployment_out(d: NcmDeployment) -> DeploymentOut:
    return DeploymentOut(
        id=str(d.id), display_number=d.display_number,
        candidate_id=str(d.candidate_id) if d.candidate_id else None,
        device_id=str(d.device_id) if d.device_id else None,
        device_name=d.device_name, status=d.status, verified_changed=d.verified_changed,
        pre_configuration_id=str(d.pre_configuration_id) if d.pre_configuration_id else None,
        post_configuration_id=str(d.post_configuration_id) if d.post_configuration_id else None,
        transcript=d.transcript, error_message=d.error_message,
        started_by=d.started_by, started_at=d.started_at, completed_at=d.completed_at,
    )


@router.get("/candidates", response_model=list[CandidateOut])
def list_candidates(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    rows = db.query(NcmCandidate).order_by(NcmCandidate.created_at.desc()).limit(200).all()
    return [_candidate_out(c) for c in rows]


@router.post("/candidates", response_model=CandidateOut, dependencies=[Depends(verify_csrf)])
def create_candidate(
    payload: CandidateCreateRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("ncm:propose")),
):
    device_uuid = _parse_uuids([payload.device_id], "device ids")[0]
    device = db.query(NetworkDevice).filter(NetworkDevice.id == device_uuid).first()
    if not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")

    if not ncm_deploy.parse_configuration_lines(payload.configuration_lines):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="The change contains no commands (only blank or comment lines).",
        )

    from sqlalchemy import func as _func
    number = (db.query(_func.max(NcmCandidate.display_number)).scalar() or 0) + 1

    candidate = NcmCandidate(
        display_number=number, device_id=device.id, device_name=device.name,
        title=payload.title, description=payload.description,
        configuration_lines=payload.configuration_lines,
        status=ncm_deploy.STATUS_DRAFT, created_by=admin.username,
    )
    db.add(candidate)
    db.commit()
    db.refresh(candidate)
    return _candidate_out(candidate)


@router.post("/candidates/{candidate_id}/submit", response_model=CandidateOut,
             dependencies=[Depends(verify_csrf)])
def submit_candidate(
    candidate_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:propose")),
):
    c = db.query(NcmCandidate).filter(
        NcmCandidate.id == _parse_uuids([candidate_id], "candidate ids")[0]
    ).first()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Candidate not found.")
    if not ncm_deploy.can_transition(c.status, ncm_deploy.STATUS_PENDING):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"A candidate in '{c.status}' cannot be submitted for approval.",
        )
    c.status = ncm_deploy.STATUS_PENDING
    db.commit()
    db.refresh(c)
    return _candidate_out(c)


@router.post("/candidates/{candidate_id}/review", response_model=CandidateOut,
             dependencies=[Depends(verify_csrf)])
def review_candidate(
    candidate_id: str,
    payload: CandidateReviewRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("ncm:approve")),
):
    """
    Approve or reject a submitted candidate.

    **Self-approval is refused.** The whole point of a separate
    `ncm:approve` permission is that a change gets a second pair of
    eyes; letting the author sign off their own work would make the
    approval step a formality that records a name without adding any
    review. A superadmin is not exempted -- an exemption is exactly the
    path a rushed change would take.
    """
    c = db.query(NcmCandidate).filter(
        NcmCandidate.id == _parse_uuids([candidate_id], "candidate ids")[0]
    ).first()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Candidate not found.")

    decision = (payload.decision or "").strip().lower()
    if decision not in ("approve", "reject"):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Decision must be 'approve' or 'reject'.")

    target = ncm_deploy.STATUS_APPROVED if decision == "approve" else ncm_deploy.STATUS_REJECTED
    if not ncm_deploy.can_transition(c.status, target):
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"A candidate in '{c.status}' cannot be {decision}d.",
        )

    if decision == "approve" and c.created_by and c.created_by == admin.username:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail="You cannot approve a change you created. Ask another administrator to review it.",
        )

    c.status = target
    c.review_note = payload.note
    if decision == "approve":
        c.approved_by = admin.username
        c.approved_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(c)
    return _candidate_out(c)


@router.post("/candidates/{candidate_id}/deploy", response_model=DeployResultOut,
             dependencies=[Depends(verify_csrf)])
def deploy_candidate_endpoint(
    candidate_id: str,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("ncm:deploy")),
):
    c = db.query(NcmCandidate).filter(
        NcmCandidate.id == _parse_uuids([candidate_id], "candidate ids")[0]
    ).first()
    if not c:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Candidate not found.")

    outcome = ncm_deploy.deploy_candidate(db, c, actor=admin.username)
    return DeployResultOut(
        ok=outcome.ok, status=outcome.status, deployment_number=outcome.deployment_number,
        verified_changed=outcome.verified_changed, message=outcome.message,
        blocked_commands=outcome.blocked_commands,
    )


@router.get("/deployments", response_model=list[DeploymentOut])
def list_deployments(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("ncm:view")),
):
    rows = db.query(NcmDeployment).order_by(NcmDeployment.started_at.desc()).limit(100).all()
    return [_deployment_out(d) for d in rows]


@router.post("/deployments/{deployment_id}/rollback", response_model=DeployResultOut,
             dependencies=[Depends(verify_csrf)])
def rollback_deployment_endpoint(
    deployment_id: str,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("ncm:deploy")),
):
    d = db.query(NcmDeployment).filter(
        NcmDeployment.id == _parse_uuids([deployment_id], "deployment ids")[0]
    ).first()
    if not d:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Deployment not found.")

    outcome = ncm_deploy.rollback_deployment(db, d, actor=admin.username)
    return DeployResultOut(
        ok=outcome.ok, status=outcome.status, deployment_number=outcome.deployment_number,
        verified_changed=outcome.verified_changed, message=outcome.message,
        blocked_commands=outcome.blocked_commands,
    )
