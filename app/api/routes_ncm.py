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
from ..models.ncm import NcmBackupJob, NcmBackupJobTarget, NcmBackupSchedule, NcmConfiguration
from ..schemas.ncm import (
    CompareCategoryOut, CompareCellOut, CompareDeviceOut, CompareRequest, CompareResultOut,
    NcmBackupRequest, NcmBackupResultOut, NcmConfigurationDetailOut, NcmConfigurationSummaryOut,
    NcmDeviceStatusOut, NcmDiffLineOut, NcmDiffOut, NcmDiffRequest, NcmJobDetailOut, NcmJobSummaryOut,
    NcmJobTargetOut, NcmOverviewOut, NcmRecentChangeOut, NcmScheduleOut, NcmScheduleRequest,
)
from ..services import ncm_archive, ncm_backup, ncm_compare
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
