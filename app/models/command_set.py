"""
app.models.command_set
========================
PAM Expansion Plan §5: reusable, named collections of command rules
(READ_ONLY, BGP_OPERATOR, ...) that a Policy references instead of
duplicating a permit/deny list inline. This is what CommandRule now
belongs to (command_set_id), replacing the Phase 5 design where a
CommandRule belonged directly to a single Policy.

`enabled` gates the whole set at once -- a disabled CommandSet is
skipped by the compiler regardless of which policies reference it,
without needing to touch each policy individually. Deletion is
blocked in the API layer (not here) when a CommandSet is still
referenced by any Policy, per §5's explicit "show where referenced
before allowing destructive deletion" requirement.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CommandSet(Base):
    __tablename__ = "command_sets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Not used as a tac_plus-ng config identifier directly (unlike
    # Policy.name, which becomes a `profile` block name) -- a
    # CommandSet's rules get inlined into whichever profile(s)
    # reference it at compile time (see config_compiler.py). Still
    # kept to the same conservative identifier charset for consistency
    # and because it's a natural, readable label either way.
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    vendor: Mapped[str] = mapped_column(String(32), nullable=False, default="cisco_ios")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
