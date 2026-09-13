"""
app.models.policy_condition_group
====================================
The condition TREE structure for the new policy condition builder
(pasted spec §6-7, §17). A policy's conditions are no longer three
flat, implicitly-AND'd nullable columns on Policy itself (the
"legacy" model, still fully supported -- see app/services/
condition_engine.py's docstring for how the two coexist without
either one silently changing the other's behavior) -- they're a real
expression tree: PolicyConditionGroup nodes (AND / OR / NOT, each
with an optional parent for nesting) containing PolicyCondition leaf
nodes and/or further nested groups.

A policy using the new tree has exactly one ROOT group
(parent_group_id IS NULL for that one row) -- everything else nests
under it. A policy that hasn't been migrated has NO rows here at all;
app.services.condition_engine checks for a root group's existence to
decide which evaluation path a given policy uses, never both at once
for the same policy.

`logical_operator = NOT` is defined to negate the combined result of
its own children the same way AND/OR combine theirs (i.e. NOT wraps
one or more children and negates their overall AND/OR-combined
truth), rather than requiring exactly one child -- this keeps the
model uniform (every group works the same way regardless of operator)
without limiting the builder to needing a wrapper group around a
NOT'd single condition.

CASCADE on both FKs: deleting a policy deletes its entire condition
tree (the tree has no meaning independent of the policy it belongs
to), and deleting a parent group deletes its whole subtree -- both
consistent with a tree structure that's meaningless in fragments.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base

VALID_LOGICAL_OPERATORS = ("AND", "OR", "NOT")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PolicyConditionGroup(Base):
    __tablename__ = "policy_condition_groups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    parent_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policy_condition_groups.id", ondelete="CASCADE"), nullable=True, index=True
    )
    logical_operator: Mapped[str] = mapped_column(String(8), nullable=False, default="AND")
    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
