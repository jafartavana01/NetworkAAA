"""
app.models.policy_command_set
===============================
PAM Expansion Plan §5's example -- a Policy references multiple
CommandSets rather than duplicating rules:

    Network-Engineer
        +-- READ_ONLY
        +-- ROUTING_OPERATOR
        +-- BGP_OPERATOR

`order` determines compile-time ordering when a policy references more
than one set (mirrors CommandRule.order's role within a single set --
both exist for the same reason: deterministic, reviewable generation
output for diffing, even though deny-overrides means the actual
permit/deny OUTCOME rarely depends on it -- see
app/services/policy_engine.py).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PolicyCommandSet(Base):
    __tablename__ = "policy_command_sets"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    command_set_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("command_sets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
