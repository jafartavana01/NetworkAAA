"""
app.models.command_job
=========================
Network Operations & Assurance Engine, Phase 1: the execution
infrastructure. Three tables, deliberately kept separate rather than
folded together (same "don't collapse distinct objects" discipline as
CommandTemplate vs CommandSet):

- CommandJob: one admin-initiated request to run a set of commands
  against a set of targets. Holds the job-level settings and status.
- CommandJobTarget: the RESOLVED, DEDUPLICATED, SNAPSHOTTED list of
  devices this specific job actually ran against -- captured at
  execution time, not recomputed from current group membership later.
  This is what makes "Access-Switches was 142 devices when this job
  ran" a permanently true historical fact even after the group's
  membership changes (spec section 39) -- resolving group membership
  live every time a job's history is viewed would silently rewrite
  history.
- CommandExecution: one row per (target, command) pair -- the actual
  evidence. Raw output is always preserved (spec section 9); nothing
  here is a "parsed-only" representation that discards the original.

STATE MACHINES (spec section 7), stored as plain strings (not
PostgreSQL ENUM types) so adding a new state later is a data value,
not a migration -- consistent with how `vendor`/`device_role` above
and CommandCategory.vendor already avoid DB-level enums for the same
reason:

  CommandJob.status:      PENDING, RUNNING, COMPLETED, PARTIAL, FAILED, CANCELLED
  CommandJobTarget.status: PENDING, CONNECTING, CONNECTED, RUNNING, COMPLETED, FAILED, TIMEOUT, SKIPPED, CANCELLED
  CommandExecution.status: PENDING, RUNNING, COMPLETED, FAILED, TIMEOUT, SKIPPED

CREDENTIALS ARE NEVER STORED HERE. The SSH username/password used to
run a job exists only for the duration of the execution request, the
same discipline app.services.ssh_provision already established for
Network Scan & Provision -- there is deliberately no column for them
anywhere in this file.

Command classification (READ_ONLY / CONFIGURATION / DESTRUCTIVE /
UNKNOWN -- spec section 49) is computed at execution time by
app.services.network_ops_execution's classifier, not stored on the
template itself, since the same literal command string could appear
in different templates and its classification never depends on which
template it's in -- storing it per-execution (CommandExecution.command_classification)
keeps a durable record of what was actually judged for THIS run, without
implying the classifier's own logic is versioned or historical.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CommandJob(Base):
    __tablename__ = "command_jobs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # The commands actually run for THIS job -- a plain JSONB snapshot,
    # whether they came from a CommandTemplate (copied at creation time,
    # not a live foreign-key read) or were typed directly into the raw
    # command box (spec section 5's "keep the raw text box"). Snapshotting
    # here means editing a CommandTemplate later never changes what an
    # already-run job's history says it executed -- the same snapshot
    # principle CommandJobTarget applies to device membership.
    commands: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    source_template_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("command_templates.id", ondelete="SET NULL"), nullable=True
    )
    source_template_name: Mapped[str | None] = mapped_column(String(128), nullable=True)  # snapshotted alongside commands, for the same reason

    execution_mode: Mapped[str] = mapped_column(String(16), nullable=False, default="sequential")  # "sequential" | "parallel"
    concurrency: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    command_timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)
    connection_timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=10)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")

    created_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("admin_users.id", ondelete="SET NULL"), nullable=True
    )
    created_by_admin_username: Mapped[str | None] = mapped_column(String(64), nullable=True)  # snapshotted -- survives the admin account being deleted later

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CommandJobTarget(Base):
    __tablename__ = "command_job_targets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("command_jobs.id", ondelete="CASCADE"), nullable=False, index=True)

    # The resolved device -- snapshotted name/IP alongside the FK so a
    # job's history still reads correctly even if the device is later
    # renamed or deleted (ondelete=SET NULL, not CASCADE: deleting a
    # device must never silently erase job history that references it).
    device_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True)
    device_name: Mapped[str] = mapped_column(String(64), nullable=False)
    device_ip_address: Mapped[str] = mapped_column(String(64), nullable=False)

    # Which selection this device came from, for display/audit only
    # ("resolved from device group Access-Switches", "individually
    # selected") -- never used to re-resolve anything later.
    resolved_from: Mapped[str | None] = mapped_column(String(128), nullable=True)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class CommandExecution(Base):
    __tablename__ = "command_executions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    job_target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("command_job_targets.id", ondelete="CASCADE"), nullable=False, index=True)

    command: Mapped[str] = mapped_column(Text, nullable=False)
    command_order: Mapped[int] = mapped_column(Integer, nullable=False)
    command_classification: Mapped[str] = mapped_column(String(16), nullable=False, default="UNKNOWN")  # READ_ONLY | CONFIGURATION | DESTRUCTIVE | UNKNOWN

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="PENDING")
    raw_output: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
