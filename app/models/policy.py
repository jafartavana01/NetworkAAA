"""
app.models.policy
===================
Authorization policies (spec section 20; PAM Expansion Plan §4). Maps
to a named tac_plus-ng `profile <name> { script { ... } }` block.

Confirmed against FOUR independent real sources (the official upstream
sample config, two mailing-list posts, and a tactrace.pl debug
example) that all use the identical pattern:

    profile <name> {
        script {
            if (service == shell) {
                if (cmd == "") {
                    set priv-lvl = <N>
                }
                permit
            }
        }
    }

`default_priv_lvl` maps to that `set priv-lvl = <N>`, applied on
initial shell login (`cmd == ""`). `default_action` is the fallback
permit/deny for anything none of the policy's referenced CommandSets
match (see PolicyCommandSet, CommandSet -- Increment 1 of the PAM
Expansion Plan replaced the old direct Policy -> CommandRule
relationship with Policy -> [CommandSet] -> CommandRule).

PAM EXPANSION PLAN §4 -- CONDITIONS LIVE DIRECTLY ON POLICY, NOT A
SEPARATE ASSIGNMENT TABLE. A Policy is self-contained: it declares both
"when do I match" (the condition_* fields below) and "what do I grant"
(priv-lvl + referenced CommandSets). Multiple policies with different
conditions and priorities coexist; app.services.policy_engine (next
increment) walks them in ascending priority order and the first full
match wins -- this is the explicit design decision recorded in
docs/PAM_EXPANSION_PLAN.md §1.1/§1.4, not an implicit default.

CONDITION FIELDS IMPLEMENTED vs. DEFERRED:
Implemented now -- condition_group_id, condition_device_id,
condition_device_group_id. Group and device targeting are CONFIRMED
real tac_plus-ng mechanics (`if (member == <group>)`, and
`if (device == <hostname>)` from the official upstream sample).
Device-group targeting compiles to a generated OR-chain of individual
`device == ...` checks (real syntax, generated rather than native).

NOT yet added -- condition_user_id (direct per-user targeting has no
confirmed tac_plus-ng example; every real one matches via `member ==`,
not a bare username), condition_source_cidr (source-IP/CIDR matching
via ACL blocks IS confirmed real syntax from Phase 5 research, just
not wired into this model yet), condition_service/protocol, and
condition_time_start/end/days_of_week (time-of-day matching has no
confirmed tac_plus-ng example at all -- see docs/PAM_EXPANSION_PLAN.md
§1.4 for why this might end up being engine-only, not compilable).
Each is a follow-up column addition when needed -- see this project's
"clean install only" note in app/database.py: there is no in-place
upgrade path to design around, so adding a field later just means
adding it to this model before the next install, not a migration.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Policy(Base):
    __tablename__ = "policies"
    __table_args__ = (
        # DEFERRABLE INITIALLY DEFERRED, not a plain unique constraint:
        # the bulk reorder endpoint (routes_policies.reorder_policies)
        # reassigns every affected policy's priority within ONE
        # transaction, and a plain (immediately-checked) unique
        # constraint would reject that transaction's OWN intermediate
        # states -- e.g. moving policy A onto policy B's current
        # priority a moment before B is moved off it -- even though
        # the transaction's FINAL, committed state is fully unique.
        # Deferring the check to commit time is exactly what lets a
        # multi-row reorder happen as one atomic, constraint-respecting
        # operation instead of needing a fragile two-phase temporary-
        # value dance in application code.
        UniqueConstraint("priority", name="uq_policies_priority", deferrable=True, initially="DEFERRED"),
    )

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Also used as the tac_plus-ng `profile <name> { }` block identifier
    # -- same identifier-safe-charset restriction as every other named
    # config entity in this project.
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Ascending: lower numbers are evaluated first, first full match
    # wins (PAM Expansion Plan §4's "Priority 10, Priority 20, Priority
    # 30, Priority 100" example ordering). UNIQUE (see __table_args__
    # above for why it's deferrable) -- a duplicate priority would
    # make evaluation order depend silently on creation time, which is
    # real, deterministic behavior but not something an admin managing
    # priorities by number should have to know about or rely on.
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    # --- Conditions (nullable = "matches anything" for that dimension) ---
    condition_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tacacs_groups.id", ondelete="SET NULL"), nullable=True
    )
    condition_device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True
    )
    condition_device_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("device_groups.id", ondelete="SET NULL"), nullable=True
    )

    # --- Authorization grant ---
    default_priv_lvl: Mapped[int] = mapped_column(Integer, default=1, nullable=False)  # 0-15, TACACS+ convention

    # "permit" | "deny" -- fallback when no referenced CommandSet's
    # rules match a non-empty `cmd`.
    default_action: Mapped[str] = mapped_column(String(8), default="deny", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
