"""
app.models.audit_batch
=========================
Groups multiple per-device `AuditRun` rows (app.models.audit_run) into
one numbered, fleet-wide "Audit Report" -- confirmed as a genuine gap
before adding this, not assumed: `AuditRun` is strictly one row per
device per audit, with no existing concept tying "every device audited
by this one scheduled/bulk run" together under a single ID. A
single-device audit triggered from that device's own page has no
batch at all (`AuditRun.batch_id` stays NULL) -- this table exists
specifically for fleet-wide runs (scheduled or manually triggered via
"Run Now"/a future bulk-audit action), not to wrap every audit ever
run.

`display_number` is a separate, sequential integer distinct from the
UUID primary key, specifically so the GUI can show a short, stable
"Audit Report #100" the way an admin would actually refer to one in
conversation -- a UUID in that position would defeat the purpose.
Assigned via `MAX(display_number) + 1` in application code at insert
time (see app.services.scheduled_audit's own next-number helper) --
the exact same pattern this project's own `ConfigVersion.version_number`
already uses (app.services.config_compiler._next_version_number), not
a database-level SEQUENCE object, which this sandbox has no way to
confirm `create_all()` provisions correctly for a fresh install.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditBatch(Base):
    __tablename__ = "security_audit_batches"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    display_number: Mapped[int] = mapped_column(Integer, unique=True, index=True, nullable=False)

    # "scheduled" (the daily background job) | "manual" (an admin's own
    # "Run Now"/bulk-audit trigger) -- mirrors AuditRun.source's own
    # vocabulary rather than inventing a parallel one.
    source: Mapped[str] = mapped_column(String(16), nullable=False)

    status: Mapped[str] = mapped_column(String(16), nullable=False, default="running")  # running | completed | failed | partial
    target_description: Mapped[str] = mapped_column(String(255), nullable=False, default="All Network Devices")
    started_by_admin_username: Mapped[str | None] = mapped_column(String(64), nullable=True)

    total_devices: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    devices_succeeded: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    devices_failed: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
