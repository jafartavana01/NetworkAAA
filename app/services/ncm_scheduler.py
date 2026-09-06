"""
app.services.ncm_scheduler
=============================
Executes NCM backup schedules (Phase 3).

Reuses the scheduling approach this project already established for
scheduled security audits (app.services.scheduled_audit): a plain
asyncio background task started from app.main's startup event, polling
on an interval. No Celery, Redis, RabbitMQ or container runtime is
introduced -- the platform targets a native Ubuntu install and stays
operationally simple, and a single "wake up, check, maybe run" loop
covers a daily schedule without a job-queue dependency.

Schedules live in PostgreSQL (app.models.ncm.NcmBackupSchedule), never
in browser memory, so they survive application restarts. `last_run_at`
is persisted, which is what stops a restart mid-day from re-running a
schedule that already completed.
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .. import security
from ..database import get_sessionmaker
from ..models.audit_schedule_settings import AuditScheduleSettings
from ..models.ncm import NcmBackupSchedule
from . import ncm_backup

logger = logging.getLogger(__name__)

_POLL_INTERVAL_SECONDS = 300  # 5 minutes -- same cadence as the audit
# scheduler: close enough to honour a daily time within a few minutes,
# far cheaper than the backup run it guards.


def _split_ids(raw: str) -> list:
    """Parses a stored comma-separated UUID list, skipping anything
    malformed rather than failing the whole schedule -- a single bad
    id should not stop every other target from being backed up."""
    import uuid as _uuid

    out = []
    for chunk in (raw or "").split(","):
        chunk = chunk.strip()
        if not chunk:
            continue
        try:
            out.append(_uuid.UUID(chunk))
        except ValueError:
            logger.warning("Skipping malformed target id in NCM schedule.")
    return out


def should_run_now(daily_run_time: str, last_run_at: datetime | None, now: datetime) -> bool:
    """
    True when the configured time has passed today and this schedule
    has not already run today. Compared by DATE, not exact time,
    because this is polled on an interval rather than fired at the
    precise minute. Pure function so it is testable without a
    database, a clock, or a device.
    """
    try:
        run_hour, run_minute = (int(part) for part in daily_run_time.split(":"))
    except (ValueError, AttributeError):
        logger.warning("NCM schedule has an unparseable run time; skipping it.")
        return False

    scheduled_today = now.replace(hour=run_hour, minute=run_minute, second=0, microsecond=0)
    if now < scheduled_today:
        return False
    if last_run_at is not None and last_run_at.date() == now.date():
        return False
    return True


def run_due_schedule(db: Session, schedule: NcmBackupSchedule, *, ssh_username: str, ssh_password: str) -> None:
    """Runs one schedule now. Marks `last_run_at` even on failure, so a
    persistently broken schedule retries tomorrow rather than looping
    every poll interval for the rest of the day."""
    devices = ncm_backup.resolve_target_devices(
        db, _split_ids(schedule.device_ids), _split_ids(schedule.device_group_ids)
    )
    types = [t.strip() for t in (schedule.configuration_types or "running").split(",") if t.strip()]

    try:
        outcome = ncm_backup.run_backup(
            db, devices=devices, configuration_types=types,
            ssh_username=ssh_username, ssh_password=ssh_password,
            source="scheduled", started_by="(scheduled)",
            schedule_id=schedule.id, schedule_name=schedule.name,
        )
        logger.info(
            "NCM schedule '%s' finished: %s/%s devices, %s changed.",
            schedule.name, outcome.succeeded, outcome.total, outcome.changed,
        )
    finally:
        schedule.last_run_at = datetime.now(timezone.utc)
        db.commit()


async def scheduler_loop() -> None:
    """
    Runs for the process lifetime, started once from app.main. The
    backup itself always runs via asyncio.to_thread -- it is blocking
    SSH work across potentially many devices, and running it directly
    in this coroutine would stall the web server for the duration of a
    fleet backup.
    """
    session_local = get_sessionmaker()
    while True:
        try:
            db: Session = session_local()
            try:
                settings = db.query(AuditScheduleSettings).first()
                have_credentials = bool(settings and settings.ssh_username and settings.ssh_password_encrypted)

                schedules = db.query(NcmBackupSchedule).filter(NcmBackupSchedule.enabled.is_(True)).all()
                now = datetime.now(timezone.utc)
                due = [s for s in schedules if should_run_now(s.daily_run_time, s.last_run_at, now)]

                if due and not have_credentials:
                    # Never silently skip: an admin who configured a
                    # schedule but no service account needs to know why
                    # nothing is being backed up.
                    logger.warning(
                        "%s NCM schedule(s) are due but no backup service account is configured; skipping.", len(due)
                    )
                elif due:
                    password = security.decrypt_secret(settings.ssh_password_encrypted)
                    for schedule in due:
                        await asyncio.to_thread(
                            run_due_schedule, db, schedule,
                            ssh_username=settings.ssh_username, ssh_password=password,
                        )
            finally:
                db.close()
        except Exception:
            # A failure in the loop's own bookkeeping must never kill
            # it -- a scheduler that silently stops after one bad poll
            # is worse than one that logs and retries.
            logger.exception("NCM schedule poll failed; will retry next cycle.")
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)
