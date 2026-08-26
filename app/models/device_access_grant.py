"""
app.models.device_access_grant
=================================
Device-level access override: "if any user (via their group) is
granted for this device or device group, that group becomes
privilege 15 without any limitation, taking precedence over whatever
the Policies section would otherwise decide." Requested directly, and
implemented using ONLY mechanisms already confirmed and shipped
elsewhere in this project -- no new tac_plus-ng syntax was needed:

- `member == <group>` / `device == <name>` -- confirmed (Policy's own
  condition compilation already uses these).
- An OR-chain of `device == <name>` for a device-group grant -- the
  same generated pattern Policy's device_group conditions already use.
- Ruleset rules evaluated in DECLARATION order, first-match-wins --
  already established and relied on for Policy priority ordering.

"Upper priority than policy" is achieved by WHERE these rules are
EMITTED in the generated ruleset (see app.services.config_compiler),
not by manipulating Policy.priority numbers -- grants are written
first, so they're checked first, guaranteed by ordering rather than by
picking a priority value low enough to always win.

GROUP-ONLY, deliberately -- not a bare user. Direct per-user matching
has no confirmed tac_plus-ng syntax anywhere in this project (see
app.models.policy's docstring and app.services.condition_engine's
same finding); rather than introduce a second "accepted but silently
uncompilable" trap, this feature simply doesn't offer per-user
targeting at all. Granting one specific person means putting them in
a dedicated group with just that one member -- an existing, ordinary
TacacsGroup, nothing new.

Exactly one of `device_id` / `device_group_id` is set -- enforced at
the API layer (a single CHECK constraint expressing "exactly one of
two nullable FKs" is awkward in portable SQL; validated the same way
Policy's own condition fields already are, with a clear 400 instead
of a raw constraint violation).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DeviceAccessGrant(Base):
    __tablename__ = "device_access_grants"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="CASCADE"), nullable=True
    )
    device_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("device_groups.id", ondelete="CASCADE"), nullable=True
    )
    user_group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tacacs_groups.id", ondelete="CASCADE"), nullable=False
    )

    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)  # admin username, not a hard FK
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
