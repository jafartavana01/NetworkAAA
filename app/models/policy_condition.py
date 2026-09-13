"""
app.models.policy_condition
=============================
Leaf nodes of the condition tree (see app.models.policy_condition_group
for the tree structure these attach to). Pasted spec §2-4, §18.

OBJECT TYPES IMPLEMENTED THIS INCREMENT -- user, user_group, device,
device_group, source_ip. Each has a REAL, checkable source, per the
spec's explicit "every object must have a real source" requirement:
user/user_group/device/device_group come from PostgreSQL (this
platform's own TacacsUser/TacacsGroup/NetworkDevice/DeviceGroup
tables); source_ip comes from the TACACS+ request context (the `nac`
field, already used elsewhere in this project for accounting and
ACL matching).

`command` is deliberately NOT an object type here -- the pasted
spec's own §12 is explicit that command authorization must stay
separate from policy conditions and live in Command Sets (already
built, already working); mixing it into the condition tree would
contradict that spec's own architecture, not just add scope.

`user` is evaluable (the Policy Simulator and Effective Access can
check it) but NOT compilable into tac_plus-ng config -- see
app.services.condition_engine's docstring for why: every confirmed
real tac_plus-ng example matches via `member == <group>`, never a
bare username, so there is no confirmed syntax for "if (user ==
alice)" to emit. A policy whose tree uses `user` conditions still
evaluates correctly in the Simulator; app.services.config_compiler
refuses to silently compile a fake equivalent for it (see that
module's docstring for the exact behavior: such a policy is skipped
from the generated ruleset with a clear reason recorded, not guessed
at).

OPERATORS IMPLEMENTED THIS INCREMENT -- equal, not_equal (for all
five object types) and is_in_cidr, is_not_in_cidr (source_ip only).
The pasted spec lists a much larger operator set (contains, starts
with, regex, in/not-in lists, etc.) for a future increment -- adding
them means adding to VALID_OPERATORS_BY_OBJECT_TYPE and a matching
branch in condition_engine.evaluate_condition(), not a schema change,
since operator is already just a string column.

`value_type` distinguishes a database-backed reference
(`referenced_object_id` is the real, authoritative FK-like value;
`value` caches its display name so the condition stays readable even
if the referenced row is later renamed) from a manual, request-context
value (source_ip's CIDR/address text -- `referenced_object_id` is
always NULL for these). A database-backed condition whose
`referenced_object_id` no longer resolves to a real row is treated by
the engine as never matching (fails closed, per this project's
consistent "unmatched means denied" default) rather than silently
matching everything or crashing -- see condition_engine.py.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base

VALID_OBJECT_TYPES = ("user", "user_group", "device", "device_group", "source_ip")

VALID_OPERATORS_BY_OBJECT_TYPE = {
    "user": ("equal", "not_equal"),
    "user_group": ("equal", "not_equal"),
    "device": ("equal", "not_equal"),
    "device_group": ("equal", "not_equal"),
    "source_ip": ("equal", "not_equal", "is_in_cidr", "is_not_in_cidr"),
}

# Object types with a real PostgreSQL source -- these use value_type="database_id"
# with a real referenced_object_id. source_ip is the one manual/request-context type.
DATABASE_BACKED_OBJECT_TYPES = ("user", "user_group", "device", "device_group")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PolicyCondition(Base):
    __tablename__ = "policy_conditions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    group_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("policy_condition_groups.id", ondelete="CASCADE"), nullable=False, index=True
    )

    object_type: Mapped[str] = mapped_column(String(32), nullable=False)
    operator: Mapped[str] = mapped_column(String(32), nullable=False)
    value_type: Mapped[str] = mapped_column(String(16), nullable=False)  # "database_id" | "manual"

    # Manual value (source_ip's CIDR/address text), or a display-name
    # cache for a database-backed condition -- see module docstring.
    value: Mapped[str] = mapped_column(Text, nullable=False)

    # Only set when value_type == "database_id". No hard FK: this one
    # column points at different tables depending on object_type
    # (TacacsUser/TacacsGroup/NetworkDevice/DeviceGroup), which a
    # single FK constraint can't express -- integrity is enforced at
    # the API layer instead (a referenced id is verified to exist,
    # for the right table, at save time), and the engine fails closed
    # if it's since been deleted (see module docstring).
    referenced_object_id: Mapped[uuid.UUID | None] = mapped_column(UUID(as_uuid=True), nullable=True)

    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
