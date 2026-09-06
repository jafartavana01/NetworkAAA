"""
app.models.ncm
=================
Network Configuration Management (NCM) data model -- Phases 1-3:
configuration archive, diff, and scheduled backups.

Deliberately additive: nothing here modifies or replaces an existing
table. Devices, device groups and admin users are referenced by
foreign key rather than duplicated, and device SSH credentials are NOT
stored here at all -- NCM reuses the platform's existing encrypted
service account (app.models.audit_schedule_settings) rather than
standing up a second credential vault.

Separation from AAA is intentional and structural: none of these
tables feed tac_plus-ng config compilation, Command Sets, or
authorization policy. "How is this device's configuration backed up
and versioned" is a different domain from "which commands may this
TACACS user run", and the schema keeps them apart.

Future NCM phases (drift, golden config, candidate config, deployment,
approval, rollback) attach to `NcmConfiguration` by foreign key
without altering it: a snapshot is an immutable, hashed artifact, which
is exactly what those phases need to point at. `configuration_type` is
a free string rather than an enum precisely so `candidate`,
`committed`, `rollback` and `operational` can be added later without a
schema migration.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class NcmConfiguration(Base):
    """
    One immutable configuration snapshot. Never updated in place and
    never overwritten -- a changed configuration always becomes a new
    row, which is what makes version history and diff trustworthy.

    Deduplication is by `sha256` against the device's own most recent
    snapshot OF THE SAME `configuration_type`: an unchanged
    running-config must not spawn an identical row every night, but
    the fact that a backup ran is still recorded (on
    NcmBackupJobTarget, which always gets a row). Backup history and
    configuration history are deliberately separate concepts here --
    losing "we checked and it was unchanged" would be losing real
    operational information.
    """

    __tablename__ = "ncm_configurations"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    # Denormalised so history survives a device rename and stays
    # readable if the device row is later removed.
    device_name: Mapped[str] = mapped_column(String(64), nullable=False)

    # Per-device, per-type incrementing version number ("#184"), the
    # way an operator refers to a snapshot. Assigned in application
    # code as MAX+1 within its device+type scope, matching this
    # project's existing ConfigVersion convention.
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, index=True)

    configuration_type: Mapped[str] = mapped_column(String(32), nullable=False, index=True)  # running | startup | ...
    configuration_content: Mapped[str] = mapped_column(Text, nullable=False)
    sha256: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    size_bytes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    source: Mapped[str] = mapped_column(String(16), nullable=False)  # manual | scheduled
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)  # admin username, not a hard FK

    job_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ncm_backup_jobs.id", ondelete="SET NULL"), nullable=True, index=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)


class NcmBackupSchedule(Base):
    """
    A recurring backup. Targets are stored as comma-separated UUID
    lists rather than join tables: Phase 3 needs "which devices and
    groups did the admin pick", not queryable-by-target reporting, and
    a join table would be schema this phase can't yet justify. If a
    later phase needs to query "which schedules target device X", that
    becomes a real join table then -- with data to migrate, which is
    cheaper than carrying unused structure now.

    Persisted in the database, never browser memory, so schedules
    survive restarts (spec requirement).
    """

    __tablename__ = "ncm_backup_schedules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    name: Mapped[str] = mapped_column(String(128), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    device_ids: Mapped[str] = mapped_column(Text, nullable=False, default="")
    device_group_ids: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Comma-separated: "running" or "running,startup".
    configuration_types: Mapped[str] = mapped_column(String(128), nullable=False, default="running")

    # 24-hour "HH:MM" in the server's own local time. A single daily
    # time, not a cron expression -- the same reasoning as the existing
    # scheduled-audit settings: a field an admin can read at a glance
    # is more honest about what this actually offers than cron syntax
    # inviting sub-daily schedules the executor was never built to
    # guarantee against a large fleet.
    daily_run_time: Mapped[str] = mapped_column(String(5), nullable=False, default="02:00")

    retention_days: Mapped[int] = mapped_column(Integer, nullable=False, default=90)

    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)

    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)


class NcmBackupJob(Base):
    """One execution -- manual or scheduled -- across one or more devices."""

    __tablename__ = "ncm_backup_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Short human-readable number ("Backup Job #9281"), assigned MAX+1
    # like the audit batches already in this project.
    display_number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)

    schedule_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ncm_backup_schedules.id", ondelete="SET NULL"), nullable=True, index=True
    )
    schedule_name: Mapped[str | None] = mapped_column(String(128), nullable=True)

    source: Mapped[str] = mapped_column(String(16), nullable=False)  # manual | scheduled
    # running | completed | partial_success | failed
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="running", index=True)

    started_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    total_devices: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    succeeded: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    changed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class NcmBackupJobTarget(Base):
    """
    Per-device outcome within a job. Always written, even when the
    configuration was unchanged and no new snapshot was created --
    this row IS the "backup executed" record that keeps backup history
    independent of configuration history.

    `configuration_changed` distinguishes the two outcomes the spec
    calls out explicitly: a snapshot was archived, versus the device
    was reached and its config was byte-identical to the last one.

    Storing per-target rows (rather than a summary blob) is also what
    lets a future "retry failed devices" phase exist without a schema
    change.
    """

    __tablename__ = "ncm_backup_job_targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    job_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ncm_backup_jobs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    device_name: Mapped[str] = mapped_column(String(64), nullable=False)

    configuration_type: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)  # success | failed
    configuration_changed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    configuration_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ncm_configurations.id", ondelete="SET NULL"), nullable=True
    )

    # Connection vs retrieval are recorded separately so a failure can
    # be diagnosed without re-running it: "could not reach the device"
    # and "connected but the config came back empty" are different
    # problems with different fixes.
    connection_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    retrieval_ok: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    # Sanitised before storage -- see app.services.ncm_backup._safe_error.
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
