"""
app.models.group
==================
TACACS+ groups (spec section 16's "Groups", section 53's Phase 4).
This is tac_plus-ng's own native grouping concept, confirmed against
the same real working config found for Phase 3 (app/services/
config_compiler.py's Phase 3 notes) -- `group admins { }` appeared
there as a valid, empty block, referenced by users via `member =
admins` and by authorization scripts via `if (member == admins)`.

SUPERSEDED (PAM Expansion Plan Increment 1): this model used to carry
its own `policy_id`, a one-group-owns-one-policy link. That's now
backwards from how targeting works -- a Policy declares which group
(among other conditions) it applies to via its OWN
`condition_group_id` (app/models/policy.py), not the other way
around, and a single group can now legitimately be referenced by
several policies with different device/device-group scoping (the
whole point of Increment 1's condition model). The field is removed
outright rather than left in place unused: this project targets clean
installs only (see app/database.py), so there's no upgrade path that
would need it preserved for compatibility, and a redundant column
that the compiler no longer reads is worse than no column at all --
it's a trap for a future change to silently start trusting again.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TacacsGroup(Base):
    __tablename__ = "tacacs_groups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Also used as the tac_plus-ng `group <name> { }` block identifier
    # -- same identifier-safe-charset restriction as NetworkDevice.name
    # and TacacsUser.username, and for the same reason.
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # Optional link to a real Active Directory group (its CN, e.g.
    # "tacacs_admins") -- lets an admin browse/select a real AD group
    # from app.services.ad_directory rather than typing a name blind.
    # This platform's own `name` field above is still what's actually
    # emitted as the tac_plus-ng `group {}` identifier and what
    # policies reference -- `ad_group_name` is a cross-reference for
    # display/lookup, not a second identity. Whether AD group
    # membership derived by tac_plus-ng's own MAVIS backend at
    # authentication time lines up with THIS group's `name` depends on
    # AdSettings.group_prefix stripping to the same string -- see
    # app.services.config_compiler's AD integration section.
    ad_group_name: Mapped[str | None] = mapped_column(String(255), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
