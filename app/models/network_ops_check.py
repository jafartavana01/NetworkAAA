"""
app.models.network_ops_check
===============================
Network Operations & Assurance Engine, Phase 3 (Check engine).

`Check` is a REGISTERED, code-defined evaluator (see
app.services.network_ops_checks._REGISTRY), not an admin-authored rule
-- there is deliberately no scripting/rule-builder surface in Phase 3.
The `Check` table exists so a check has a stable id or reference,
a severity, a description, and can be selected/toggled from the GUI,
the same way CommandCategory (PAM Expansion Plan §6) is a real,
selectable database row whose actual categorization LOGIC still lives
in code, not in the row itself.

`CheckResult` matches spec section 12's field list closely:
check_id, device (via job_target), status, severity, title,
description, evidence, actual_value, expected_value, recommendation,
timestamp. `remediation`/`verification` fields are deferred (Phase 8
territory -- no remediation/approval workflow exists yet in this
project) rather than added now with nothing to populate them.

Statuses (spec section 12): PASS, FAIL, WARNING, NOT_APPLICABLE,
MANUAL_REVIEW, UNKNOWN -- plain strings, not a DB enum, same reasoning
as CommandJob.status. NOT_APPLICABLE and MANUAL_REVIEW are not
failure states to be dodged -- they are the HONEST result when a
check's required evidence wasn't collected, or when the answer
genuinely can't be determined from command output alone (the same
philosophy the referenced cisco-ios-security-auditor project's own
MANUAL_REVIEW status embodies, and the same "do not falsely mark
PASS/FAIL when evidence is insufficient" instruction spec section 12
states directly).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Check(Base):
    __tablename__ = "network_ops_checks"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Stable key into app.services.network_ops_checks's registry --
    # the actual evaluator function this row selects. Unique so a
    # given evaluator is only ever seeded once.
    check_key: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    name: Mapped[str] = mapped_column(String(128), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    category: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "Management Plane", "Layer 2 Security"
    default_severity: Mapped[str] = mapped_column(String(16), nullable=False, default="MEDIUM")  # CRITICAL|HIGH|MEDIUM|LOW|INFO

    # Which raw command output this check needs to be evaluable at all
    # -- informational (shown in the GUI so an admin knows what to
    # include in a job's commands), not enforced at the database
    # level; the evaluator itself is what decides NOT_APPLICABLE vs a
    # real result when the needed output wasn't collected.
    required_commands: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class CheckResult(Base):
    __tablename__ = "network_ops_check_results"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    check_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), ForeignKey("network_ops_checks.id", ondelete="SET NULL"), nullable=True)
    check_key: Mapped[str] = mapped_column(String(64), nullable=False)  # snapshotted -- survives the Check row being deleted
    check_name: Mapped[str] = mapped_column(String(128), nullable=False)  # snapshotted, same reason

    job_target_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("command_job_targets.id", ondelete="CASCADE"), nullable=False, index=True)
    device_name: Mapped[str] = mapped_column(String(64), nullable=False)  # snapshotted for display without a join

    status: Mapped[str] = mapped_column(String(16), nullable=False)  # PASS|FAIL|WARNING|NOT_APPLICABLE|MANUAL_REVIEW|UNKNOWN
    severity: Mapped[str] = mapped_column(String(16), nullable=False)

    title: Mapped[str] = mapped_column(String(256), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    evidence: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)  # list of plain strings -- the specific interfaces/lines involved
    actual_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    expected_value: Mapped[str | None] = mapped_column(Text, nullable=True)
    recommendation: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
