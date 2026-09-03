"""
app.models.network_ops_audit
===============================
Network Operations & Assurance Engine, Phase 4 (Audit engine).

`Audit` is a named, reusable collection of check_keys (spec section
14's own example: "Cisco Enterprise Access Switch Security Baseline"
grouping several individual checks) -- the same relationship
CommandTemplate has to raw commands, just one layer up: a Template
groups commands, an Audit groups checks.

`AuditRun` is one execution of an Audit against one Command Job's
already-collected targets -- deliberately NOT a new column added to
the existing `CheckResult` table (app.models.network_ops_check,
already shipped in Phase 3): altering an already-existing table's
schema is a real risk this project's clean-install-only,
`create_all()`-only deployment model (app/database.py's own
docstring) doesn't handle automatically the way a brand new table
does. Instead, `AuditRun.check_result_ids` is a SOFT reference (a
JSONB list of `CheckResult.id` values) -- the same soft-reference
pattern this project already established for
`PolicyCondition.referenced_object_id`, chosen here for the same
reason: it lets a new table point at rows in an existing one without
requiring that existing table's schema to change at all.

Both `audit_id` and `job_id` here are nullable, SET NULL on delete,
with name snapshots alongside them -- an AuditRun's own history stays
readable ("Cisco Baseline was run against Job X on this date") even
if the Audit definition or the Job itself is later deleted, the same
snapshot discipline CommandJob already applies to
source_template_name.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Audit(Base):
    __tablename__ = "network_ops_audits"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    check_keys: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class AuditRun(Base):
    __tablename__ = "network_ops_audit_runs"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    audit_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("network_ops_audits.id", ondelete="SET NULL"), nullable=True)
    audit_name: Mapped[str] = mapped_column(String(128), nullable=False)

    job_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("command_jobs.id", ondelete="SET NULL"), nullable=True)
    job_name: Mapped[str] = mapped_column(String(128), nullable=False)

    # Soft reference -- see module docstring for why this isn't a hard
    # FK column added to CheckResult instead.
    check_result_ids: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    created_by_admin_username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
