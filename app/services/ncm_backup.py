"""
app.services.ncm_backup
==========================
The NCM backup engine: resolves targets, retrieves configuration
through the shared driver/SSH layer, archives it, and records
per-device results.

Infrastructure reused rather than reimplemented:
  * SSH/prompt/paging/timeout handling -- via
    app.services.ncm_drivers, which wraps
    app.services.network_ops_execution.run_commands_on_device.
  * Bounded concurrency -- ThreadPoolExecutor, the same approach
    app.services.network_ops_execution.run_job already uses, rather
    than one unbounded thread per device.
  * Credentials -- the existing encrypted platform service account
    (app.models.audit_schedule_settings), decrypted through
    app.security. NCM stands up no second credential vault and never
    writes a credential to a job record, log line or error message.
  * Device groups -- resolved through NetworkDevice.device_group_id,
    the existing relationship, not a new NCM-specific grouping.
"""
from __future__ import annotations

import logging
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_sessionmaker
from ..models.device import NetworkDevice
from ..models.ncm import NcmBackupJob, NcmBackupJobTarget
from . import ncm_archive, ncm_drivers

logger = logging.getLogger(__name__)

DEFAULT_CONCURRENCY = 10


def _safe_error(exc: Exception | str) -> str:
    """
    Error text safe to persist and show. Credentials are never
    interpolated into messages anywhere in this module, but this also
    truncates: a stack-trace-length string in a job record helps
    nobody and risks carrying context that was never meant to be
    stored.
    """
    text = str(exc).strip() or exc.__class__.__name__ if isinstance(exc, Exception) else str(exc).strip()
    return text[:500]


def resolve_target_devices(db: Session, device_ids: list, device_group_ids: list) -> list[NetworkDevice]:
    """
    Resolves an explicit device list plus any device groups into ONE
    de-duplicated, name-ordered list of enabled devices.

    A device selected directly AND via a group appears exactly once --
    the spec's deduplication requirement -- because both paths collapse
    into a single id set before the query runs. Group membership uses
    the existing NetworkDevice.device_group_id relationship rather
    than an NCM-specific grouping table.
    """
    wanted: set = set(device_ids or [])

    if device_group_ids:
        rows = (
            db.query(NetworkDevice.id)
            .filter(NetworkDevice.device_group_id.in_(device_group_ids))
            .all()
        )
        wanted.update(r[0] for r in rows)

    if not wanted:
        return []

    return (
        db.query(NetworkDevice)
        .filter(NetworkDevice.id.in_(wanted), NetworkDevice.enabled.is_(True))
        .order_by(NetworkDevice.name.asc())
        .all()
    )


@dataclass
class BackupOutcome:
    total: int = 0
    succeeded: int = 0
    failed: int = 0
    changed: int = 0
    job_display_number: int = 0
    failures: list = field(default_factory=list)

    @property
    def status(self) -> str:
        if self.total == 0:
            return "completed"
        if self.failed == 0:
            return "completed"
        if self.succeeded == 0:
            return "failed"
        return "partial_success"


def _next_job_number(db: Session) -> int:
    current_max = db.query(func.max(NcmBackupJob.display_number)).scalar()
    return (current_max or 0) + 1


@dataclass
class _DeviceWork:
    device_id: uuid.UUID
    device_name: str
    host: str
    vendor: str | None


def _retrieve_one(work: _DeviceWork, configuration_type: str, username: str, password: str) -> dict:
    """
    Runs entirely inside a worker thread and touches NO database
    session -- SQLAlchemy sessions are not thread-safe, so every
    thread returns a plain dict and the caller writes results on the
    main thread. Any exception is caught here so one device can never
    fail the whole fleet job.
    """
    driver = ncm_drivers.get_driver(work.vendor)
    try:
        result = driver.get_configuration(work.host, username, password, configuration_type)
        return {
            "device_id": work.device_id, "device_name": work.device_name,
            "ok": result.ok, "content": result.content,
            "connection_ok": result.connection_ok, "retrieval_ok": result.retrieval_ok,
            "error": result.error,
        }
    except Exception as exc:  # noqa: BLE001 -- deliberately broad; see docstring
        logger.exception("NCM backup failed for %s", work.device_name)
        return {
            "device_id": work.device_id, "device_name": work.device_name,
            "ok": False, "content": "", "connection_ok": False, "retrieval_ok": False,
            "error": _safe_error(exc),
        }


def run_backup(
    db: Session, *, devices: list[NetworkDevice], configuration_types: list[str],
    ssh_username: str, ssh_password: str, source: str, started_by: str | None = None,
    schedule_id=None, schedule_name: str | None = None, concurrency: int = DEFAULT_CONCURRENCY,
) -> BackupOutcome:
    """
    Backs up every device for every requested configuration type,
    archiving only what actually changed, and writing one
    NcmBackupJobTarget row per device+type regardless of outcome.

    `ssh_password` is a parameter, never read from or written to any
    NCM table, and never placed in a target row, log line or error
    message.
    """
    job = NcmBackupJob(
        display_number=_next_job_number(db), source=source, status="running",
        started_by=started_by, schedule_id=schedule_id, schedule_name=schedule_name,
        total_devices=len(devices),
    )
    db.add(job)
    db.commit()
    db.refresh(job)

    outcome = BackupOutcome(total=len(devices), job_display_number=job.display_number)

    work_items = [
        _DeviceWork(
            device_id=d.id, device_name=d.name,
            host=d.ip_address.split("/")[0].strip(), vendor=getattr(d, "vendor", None),
        )
        for d in devices
    ]

    device_had_failure: set = set()
    device_had_success: set = set()

    for configuration_type in configuration_types:
        results: list[dict] = []
        if work_items:
            workers = max(1, min(concurrency, len(work_items)))
            with ThreadPoolExecutor(max_workers=workers) as pool:
                results = list(pool.map(
                    lambda w: _retrieve_one(w, configuration_type, ssh_username, ssh_password),
                    work_items,
                ))

        # Database writes happen here, on the main thread, one session.
        for res in results:
            target = NcmBackupJobTarget(
                job_id=job.id, device_id=res["device_id"], device_name=res["device_name"],
                configuration_type=configuration_type,
                connection_ok=res["connection_ok"], retrieval_ok=res["retrieval_ok"],
            )
            if res["ok"]:
                archived = ncm_archive.archive_configuration(
                    db, device_id=res["device_id"], device_name=res["device_name"],
                    configuration_type=configuration_type, content=res["content"],
                    source=source, created_by=started_by, job_id=job.id,
                )
                target.status = "success"
                target.configuration_changed = archived.changed
                target.configuration_id = archived.configuration.id if archived.configuration else None
                if archived.changed:
                    outcome.changed += 1
                device_had_success.add(res["device_id"])
            else:
                target.status = "failed"
                target.error_message = _safe_error(res["error"] or "Backup failed.")
                device_had_failure.add(res["device_id"])
                outcome.failures.append(f"{res['device_name']} ({configuration_type}): {target.error_message}")
            db.add(target)
        db.commit()

    # A device counts as failed if ANY requested configuration type
    # failed for it -- reporting a device as successful when its
    # startup-config could not be retrieved would overstate coverage.
    outcome.failed = len(device_had_failure)
    outcome.succeeded = len(device_had_success - device_had_failure)

    job.succeeded = outcome.succeeded
    job.failed = outcome.failed
    job.changed = outcome.changed
    job.status = outcome.status
    job.completed_at = datetime.now(timezone.utc)
    db.commit()

    return outcome
