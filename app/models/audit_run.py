"""
app.models.audit_run
=======================
Security Center audit persistence -- one row per audit execution
(`AuditRun`) and one row per individual finding it produced
(`AuditFinding`). Additive tables only, per the migration architecture
agreed for this project: no existing table's schema changes.

`AuditRun.device_id` is nullable, SET NULL on delete, with a
`device_name` snapshot alongside it -- the same "history stays
readable even if the referenced row is later deleted" discipline
app.models.network_ops_audit's `AuditRun` already established for its
own `audit_id`/`job_id` (name snapshot next to a nullable FK, not a
hard-required one).

`AuditFinding.interface_name` is plain text, not a foreign key --
this project has no `interfaces` table (confirmed absent during the
Security Center migration inspection), and inventing one now, only to
attach findings to it, would be exactly the kind of half-built,
premature feature this project's own conventions avoid. If per-
interface trending across runs becomes a real requirement later, that
is its own deliberate decision, not implied here.

`evidence` and `compliance_refs` are JSONB, matching this project's
established pattern (e.g. `network_ops_audit.Audit.check_keys`,
`aaa_template_settings.AaaTemplateSettings.commands`) for a field
whose shape is a list/dict rather than a scalar column.

NOTE: no `from __future__ import annotations` here -- see the note in
app/models/admin.py for why (Python 3.14 + SQLAlchemy + stringified
`X | None` annotations is a confirmed CPython typing regression, and
this file has several `X | None` columns).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditRun(Base):
    __tablename__ = "security_audit_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True
    )
    device_name: Mapped[str] = mapped_column(String(64), nullable=False)

    # "live" (SSH show running-config), "upload" (pasted/uploaded text),
    # or "snapshot" (a previously stored config, once that source exists).
    source: Mapped[str] = mapped_column(String(16), nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")  # running | completed | failed
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Hash of the exact config text this run analyzed -- lets Compare
    # Audits (spec) detect "nothing actually changed" without storing
    # the full text twice if a snapshot/backup feature already has it.
    config_snapshot_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    raw_config: Mapped[str | None] = mapped_column(Text, nullable=True)

    overall_score: Mapped[float | None] = mapped_column(Float, nullable=True)
    compliance_score: Mapped[float | None] = mapped_column(Float, nullable=True)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    started_by_admin_username: Mapped[str | None] = mapped_column(String(64), nullable=True)


class AuditFinding(Base):
    __tablename__ = "security_audit_findings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    audit_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("security_audit_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True
    )

    # None for a device-wide finding, set for an interface-scoped one.
    # See module docstring for why this is text, not a foreign key.
    interface_name: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)

    domain: Mapped[str] = mapped_column(String(64), nullable=False, index=True)
    check_id: Mapped[str] = mapped_column(String(32), nullable=False, index=True)
    title: Mapped[str] = mapped_column(String(256), nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False)    # pass | fail | na | manual_review
    severity: Mapped[str] = mapped_column(String(16), nullable=False)  # critical | high | medium | low | info

    evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)
    evidence_label: Mapped[str] = mapped_column(String(128), nullable=False, default="Affected items")
    recommendation: Mapped[str] = mapped_column(Text, nullable=False, default="")
    detail: Mapped[str] = mapped_column(Text, nullable=False, default="")
    fix_command: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Interface-engine-only narrative fields -- empty for device-level
    # findings. See app.security_center.engine.finding's own docstring.
    why: Mapped[str] = mapped_column(Text, nullable=False, default="")
    risk: Mapped[str] = mapped_column(Text, nullable=False, default="")
    attack: Mapped[str] = mapped_column(Text, nullable=False, default="")
    best: Mapped[str] = mapped_column(Text, nullable=False, default="")
    performance: Mapped[str] = mapped_column(Text, nullable=False, default="")
    operational: Mapped[str] = mapped_column(Text, nullable=False, default="")
    compatibility: Mapped[str] = mapped_column(Text, nullable=False, default="")
    references: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # Set by app.security_center.engine.correlation when this finding is
    # part of a correlated group; null for an individual finding.
    correlation_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    compliance_refs: Mapped[dict] = mapped_column(JSONB, nullable=False, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class AuditDomainScore(Base):
    __tablename__ = "security_audit_domain_scores"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    audit_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("security_audit_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    domain: Mapped[str] = mapped_column(String(64), nullable=False)
    score: Mapped[float] = mapped_column(Float, nullable=False)
    fail_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    manual_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)


class AuditComplianceResult(Base):
    __tablename__ = "security_audit_compliance"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    audit_run_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("security_audit_runs.id", ondelete="CASCADE"), nullable=False, index=True
    )
    framework: Mapped[str] = mapped_column(String(64), nullable=False)   # e.g. "nist_800_53", "iso27002"
    control_id: Mapped[str] = mapped_column(String(32), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)      # pass | fail | manual_review | na
