"""
app.models.monitoring_settings
=================================
"Monitoring mode": when enabled, the compiler emits a catch-all
`host = world {}` block (confirmed real syntax -- see
app.services.config_compiler's monitoring section) so a connection
attempt from a device with NO matching specific host block still
reaches tac_plus-ng far enough to be logged, instead of being
rejected at a lower level with nothing observable at all. The Devices
page then surfaces recent connection attempts whose source IP doesn't
match any currently-configured device, with a one-click "Add" that
creates the device and assigns it to the seeded "monitor" DeviceGroup.

SAFE BY CONSTRUCTION, regardless of which host-matching precedence
tac_plus-ng actually uses (not independently confirmed either way --
see the compiler module's own notes): the catch-all is always emitted
LAST, after every specific host block. If matching is most-specific-
wins, order is irrelevant. If it's first-declared-wins (the pattern
confirmed everywhere else in this daemon's rule-based constructs --
ACLs, rulesets), declaring it last means it's only ever reached when
nothing more specific already matched. Either way, an already-
configured device's behavior is completely unaffected by this
feature existing.

`placeholder_key` is NOT a real, working shared secret for any actual
device -- it exists only so the daemon attempts to process the
connection (and therefore logs it) rather than rejecting it outright
for having no key configured at all. It's generated once, randomly,
and reused across recompiles so the catch-all host block doesn't
change on every apply. A real device connecting through this
catch-all will fail decryption against it (its own real key won't
match), which is expected -- see the module docstring in
app.services.monitoring for why that failure is still detectable.
"""
import secrets
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _generate_placeholder_key() -> str:
    return secrets.token_urlsafe(24)


class MonitoringSettings(Base):
    __tablename__ = "monitoring_settings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    placeholder_key: Mapped[str] = mapped_column(String(64), nullable=False, default=_generate_placeholder_key)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
