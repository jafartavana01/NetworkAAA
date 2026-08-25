"""
app.models.policy_version
===========================
PAM Expansion Plan §22: every Policy modification creates a version
row here -- name, description, enabled, priority, every condition,
the privilege/default-action grant, and the referenced Command Set
names, captured as a JSON snapshot at that moment in time. Follows
the same pattern as app.models.config_version (Phase 2's config
history): the full state is stored, not a diff against the previous
version, so a version is restorable and diffable even if the policy
it belonged to was later deleted entirely, and nothing here depends
on anything else still existing.

Restore works the same way Config restore does (spec section 15's
established pattern): re-applying an old version creates a NEW
version with that old snapshot's values, rather than deleting
everything after it. Historical versions are never destroyed, per
§22's explicit instruction.

Version numbers are scoped PER POLICY (not global like
ConfigVersion's), since "policy CORE-ADMIN v1, v2, v3, v4" (the
spec's own example) reads as a per-policy sequence, not a shared
counter across every policy in the system.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PolicyVersion(Base):
    __tablename__ = "policy_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    # Nullable + SET NULL, not CASCADE: a version's snapshot already
    # contains the full historical policy state independent of the
    # live Policy row, so deleting the policy must NOT delete its
    # version history -- doing so would directly contradict this
    # model's own "restorable and diffable even if the policy it
    # belonged to was later deleted entirely" design (stated above)
    # and the spec's explicit "never destroy historical versions"
    # instruction. An orphaned version (policy_id=NULL) stays fully
    # readable; it just can no longer be restored onto a live policy.
    policy_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policies.id", ondelete="SET NULL"), nullable=True, index=True
    )
    version_number: Mapped[int] = mapped_column(Integer, nullable=False)

    # Full policy state at this point, as JSON text (matching
    # ConfigVersion's "store the whole thing" pattern) -- see
    # app.api.routes_policy_versions for the exact shape written here.
    snapshot: Mapped[str] = mapped_column(Text, nullable=False)

    change_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)  # admin username, not a hard FK

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
