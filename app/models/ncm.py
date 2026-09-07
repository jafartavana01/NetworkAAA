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


class NcmBaseline(Base):
    """
    A device's designated "golden" configuration -- Phase 4.

    A baseline is a POINTER to an existing NcmConfiguration snapshot,
    not a copy of its text. That matters: the snapshot is already
    immutable and SHA-256 hashed, so pointing at it means a baseline
    can never silently disagree with the archive, and drift is a
    comparison between two real archived artifacts rather than between
    a device and a hand-maintained document.

    One baseline per device per configuration_type. Re-designating
    updates the existing row rather than accumulating history: "which
    config is golden right now" is the question this answers, and
    every previous baseline is still in the archive by version number
    if it is needed.
    """

    __tablename__ = "ncm_baselines"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_name: Mapped[str] = mapped_column(String(64), nullable=False)
    configuration_type: Mapped[str] = mapped_column(String(32), nullable=False, default="running", index=True)

    # SET NULL rather than CASCADE: if the golden snapshot is deleted
    # from the archive, the baseline should become "no longer has a
    # snapshot" -- a visible, fixable state -- rather than silently
    # vanishing along with the operator's intent.
    configuration_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ncm_configurations.id", ondelete="SET NULL"), nullable=True
    )
    # Denormalised so the baseline still reports which version was
    # designated even if that snapshot is later removed.
    version_number: Mapped[int | None] = mapped_column(Integer, nullable=True)
    sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)

    notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    set_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    set_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class NcmCandidate(Base):
    """
    A proposed configuration change awaiting approval and deployment --
    NCM Phases 6-9.

    Stores the CHANGE (configuration lines to send), not a whole target
    configuration. That is a deliberate limit: this platform cannot
    safely compute the command sequence that transforms one full Cisco
    configuration into another -- doing so requires modelling negation
    (`no ...`), sub-mode context and ordering rules per platform. An
    operator writes the lines they want applied, exactly as they would
    type them, and the platform handles safety, review and rollback
    around that.

    Lifecycle, enforced in the service layer:

        draft -> pending_approval -> approved -> deployed
                                  \\-> rejected
                        (any state) -> cancelled

    A candidate that has been deployed is never reused: redeploying
    means creating a new candidate, so the record of what was approved
    and what was sent can never drift apart.
    """

    __tablename__ = "ncm_candidates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    display_number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)

    device_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_name: Mapped[str] = mapped_column(String(64), nullable=False)

    title: Mapped[str] = mapped_column(String(200), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    #: The configuration lines to send, one per line, as typed.
    configuration_lines: Mapped[str] = mapped_column(Text, nullable=False)

    # draft | pending_approval | approved | rejected | deployed | cancelled | failed
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="draft", index=True)

    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)

    # Approval is recorded separately from creation so "who signed off"
    # is always answerable, and so the service layer can refuse
    # self-approval when the platform is configured to require it.
    approved_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)


class NcmDeployment(Base):
    """
    One attempt to push a candidate to a device -- Phases 7 and 9.

    `pre_configuration_id` is the rollback point: a fresh backup taken
    IMMEDIATELY BEFORE the change, not the last scheduled one. Using a
    stale snapshot as a rollback target would restore a state the
    device was never actually in at the moment of the change.

    `post_configuration_id` is the verification backup taken after, so
    what actually changed on the device is a real archived diff rather
    than an assumption that the commands did what they said.
    """

    __tablename__ = "ncm_deployments"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    display_number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)

    candidate_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ncm_candidates.id", ondelete="SET NULL"), nullable=True, index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    device_name: Mapped[str] = mapped_column(String(64), nullable=False)

    # running | succeeded | failed | rolled_back | rollback_failed
    status: Mapped[str] = mapped_column(String(24), nullable=False, default="running", index=True)
    #: True when the post-deployment backup differs from the pre one --
    #: i.e. the device really changed, rather than the commands being
    #: accepted with no effect.
    verified_changed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    pre_configuration_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ncm_configurations.id", ondelete="SET NULL"), nullable=True
    )
    post_configuration_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("ncm_configurations.id", ondelete="SET NULL"), nullable=True
    )

    #: Full device transcript. Sanitised before storage -- see
    #: ncm_deploy._sanitise_transcript.
    transcript: Mapped[str | None] = mapped_column(Text, nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    started_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, index=True)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
