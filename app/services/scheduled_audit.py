"""
app.services.scheduled_audit
===============================
Runs a live-SSH Security Center audit against every NetworkAAA device
using the platform's own stored service account
(app.models.audit_schedule_settings.AuditScheduleSettings), rather
than a human supplying credentials per device per run. Reuses the
exact same SSH-execution and audit-persistence path
app.api.routes_security's own live-audit endpoint already uses
(app.services.network_ops_execution.run_commands_on_device,
app.security_center.engine.orchestrator.run_device_audit,
app.services.security_audit_persistence.persist_audit_result) --
this is the SAME pipeline, driven by a scheduler instead of a request,
not a second implementation of it.

One unreachable or misconfigured device must never abort the whole
run -- see run_scheduled_audit's own docstring for why every device
is wrapped in its own try/except.

`start_scheduler_loop()` is the actual "runs every day, unattended"
piece -- a plain asyncio background task, not a new dependency
(no APScheduler/Celery): this project has no existing scheduling
infrastructure at all, and a single "wake up, check, maybe run" loop
covers the one real requirement (a daily fleet audit) without taking
on a general-purpose job-scheduling library for it.
"""
from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from .. import security
from ..database import get_sessionmaker
from ..models.audit_run import AuditRun
from ..models.audit_schedule_settings import AuditScheduleSettings
from ..models.device import NetworkDevice
from ..security_center.engine.orchestrator import run_device_audit
from . import network_ops_execution
from .security_audit_persistence import hash_config_text, persist_audit_result

logger = logging.getLogger(__name__)

_POLL_INTERVAL_SECONDS = 300  # 5 minutes -- frequent enough that the
# configured daily_run_time is honored within a few minutes, without
# polling so often it's meaningfully more database load than the
# actual daily audit run itself.


@dataclass
class ScheduledAuditResult:
    total_devices: int
    succeeded: int = 0
    failed: int = 0
    failures: list[str] = field(default_factory=list)  # "<device name>: <reason>"

    @property
    def status(self) -> str:
        if self.total_devices == 0 or self.succeeded == self.total_devices:
            return "completed"
        if self.succeeded == 0:
            return "failed"
        return "partial"

    @property
    def summary(self) -> str:
        if self.total_devices == 0:
            return "No devices to audit."
        lines = [f"{self.succeeded}/{self.total_devices} devices audited successfully."]
        lines.extend(f"  - {f}" for f in self.failures)
        return "\n".join(lines)


def _bare_ip(device: NetworkDevice) -> str:
    return device.ip_address.split("/")[0].strip()


def run_scheduled_audit(db: Session, *, ssh_username: str, ssh_password_encrypted: str) -> ScheduledAuditResult:
    """
    Audits every device in sequence (not in parallel -- a fleet-wide
    unattended job has no one watching it fail loudly, so a single
    device's SSH connection hanging near its own timeout is a real
    risk; running sequentially bounds the total run time predictably
    as device_count * per-device timeout, where a naive parallel
    version could exhaust connections or overwhelm devices with
    simultaneous management-plane sessions instead). Every device is
    wrapped in its own try/except specifically so one unreachable or
    misconfigured device doesn't abort auditing every device after it
    -- the whole point of an unattended job is that it keeps going
    without a human there to restart it.
    """
    ssh_password = security.decrypt_secret(ssh_password_encrypted)
    devices = db.query(NetworkDevice).filter(NetworkDevice.enabled.is_(True)).order_by(NetworkDevice.name.asc()).all()

    result = ScheduledAuditResult(total_devices=len(devices))

    for device in devices:
        run = AuditRun(
            device_id=device.id, device_name=device.name, source="scheduled", status="running",
            started_by_admin_username="(scheduled)",
        )
        db.add(run)
        db.commit()
        db.refresh(run)

        try:
            exec_result = network_ops_execution.run_commands_on_device(
                _bare_ip(device), ssh_username, ssh_password, ["terminal length 0", "show running-config"],
            )
            if not exec_result.success or not exec_result.command_results:
                raise RuntimeError(exec_result.message)

            raw_config = exec_result.command_results[-1].output
            run.raw_config = raw_config
            run.config_snapshot_hash = hash_config_text(raw_config)

            audit_result = run_device_audit(raw_config)
            persist_audit_result(db, audit_run=run, result=audit_result)
            db.commit()
            result.succeeded += 1
        except Exception as exc:
            run.status = "failed"
            run.error_message = str(exc)
            db.commit()
            result.failed += 1
            result.failures.append(f"{device.name}: {exc}")

    return result


def should_run_now(daily_run_time: str, last_run_at: datetime | None, now: datetime) -> bool:
    """
    True exactly when it's time to kick off today's scheduled run: the
    current time is at or past the configured daily_run_time, AND a
    run hasn't already happened today (compared by DATE, not exact
    time, since this is called repeatedly on a polling interval --
    see _POLL_INTERVAL_SECONDS -- not only at the precise scheduled
    minute). Pulled out as its own pure function specifically so this
    decision could be verified with real test cases independent of
    the database/SSH/asyncio machinery around it.
    """
    run_hour, run_minute = map(int, daily_run_time.split(":"))
    scheduled_today = now.replace(hour=run_hour, minute=run_minute, second=0, microsecond=0)
    if now < scheduled_today:
        return False
    if last_run_at is not None and last_run_at.date() == now.date():
        return False
    return True


async def scheduler_loop() -> None:
    """
    Runs for the lifetime of the process (started once, from
    app.main's own startup event -- see that module for why this is a
    SEPARATE startup handler, not folded into the existing sync one).
    Sleeps between checks; the actual audit (blocking network I/O,
    potentially one device at a time across a whole fleet) always runs
    via asyncio.to_thread, never directly in this coroutine, so a slow
    or hanging device can never block the web server itself from
    handling ordinary requests while a scheduled run is in progress.
    """
    session_local = get_sessionmaker()
    while True:
        try:
            db: Session = session_local()
            try:
                settings = db.query(AuditScheduleSettings).first()
                if settings and settings.enabled and settings.ssh_username and settings.ssh_password_encrypted:
                    now = datetime.now(timezone.utc)
                    if should_run_now(settings.daily_run_time, settings.last_run_at, now):
                        logger.info("Scheduled Security Center audit starting for all enabled devices.")
                        result = await asyncio.to_thread(
                            run_scheduled_audit, db,
                            ssh_username=settings.ssh_username,
                            ssh_password_encrypted=settings.ssh_password_encrypted,
                        )
                        settings.last_run_at = datetime.now(timezone.utc)
                        settings.last_run_status = result.status
                        settings.last_run_summary = result.summary
                        db.commit()
                        logger.info("Scheduled Security Center audit finished: %s", result.summary)
            finally:
                db.close()
        except Exception:
            # A failure in the scheduler's OWN bookkeeping (e.g. a
            # transient database hiccup) must never kill the loop --
            # an unattended daily job that silently stops running
            # after one bad poll is worse than one that logs an error
            # and tries again next cycle.
            logger.exception("Scheduled audit poll failed; will retry next cycle.")
        await asyncio.sleep(_POLL_INTERVAL_SECONDS)
