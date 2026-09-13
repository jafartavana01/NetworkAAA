"""
app.models.radius_policy
===========================
RADIUS authorization policies -- "who may authenticate where, and what
attributes come back".

Deliberately NOT a copy of the TACACS+ policy model. TACACS+ policies
answer "which commands may this user run"; RADIUS has no per-command
authorization, and pretending otherwise would invite an operator to
configure something the protocol cannot enforce. A RADIUS policy here
answers two questions only:

  * Does this request get an Access-Accept or an Access-Reject?
  * If accepted, which RADIUS attributes are returned?

Conditions reuse this platform's existing objects -- a TACACS+ group
(which is how an AD group is represented here) and a device or device
group -- rather than introducing a parallel identity model.

Generated form, confirmed against the upstream sample
`tac_plus-ng/sample/tac_plus-ng-radius.cfg`:

    profile <name> {
        script {
            if (aaa.protocol == radius) {
                set radius[Vendor:Attribute] = "value"
                permit
            }
        }
    }
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RadiusPolicy(Base):
    __tablename__ = "radius_policies"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    name: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    # Lower runs first, matching the TACACS+ policy convention already
    # established in this project so the two orderings cannot be read
    # differently by mistake.
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=100)

    # --- conditions (all optional; an unset condition matches anything)
    condition_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tacacs_groups.id", ondelete="SET NULL"), nullable=True, index=True
    )
    condition_device_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("network_devices.id", ondelete="SET NULL"), nullable=True, index=True
    )
    condition_device_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("device_groups.id", ondelete="SET NULL"), nullable=True, index=True
    )
    #: Optional match on the request's Service-Type, by NAME as it
    #: appears in the dictionary (e.g. "Administrative-User"). Stored as
    #: text rather than an integer so it stays readable and survives a
    #: dictionary change.
    condition_service_type: Mapped[str | None] = mapped_column(String(64), nullable=True)

    # --- result
    #: permit -> Access-Accept, deny -> Access-Reject.
    action: Mapped[str] = mapped_column(String(8), nullable=False, default="permit")

    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)


class RadiusPolicyAttribute(Base):
    """
    One attribute returned when a policy permits.

    `attribute` holds the dictionary's qualified name -- `Service-Type`
    for a standard attribute, `Cisco:Cisco-AVPair` or
    `MikroTik:MikroTik-Group` for a vendor one -- which is exactly the
    token the generated script uses inside `radius[...]`. Storing the
    qualified name rather than a numeric code keeps the stored policy
    readable and means a dictionary update cannot silently repoint an
    attribute at a different meaning.
    """

    __tablename__ = "radius_policy_attributes"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    policy_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("radius_policies.id", ondelete="CASCADE"), nullable=False, index=True
    )
    attribute: Mapped[str] = mapped_column(String(128), nullable=False)
    value: Mapped[str] = mapped_column(String(512), nullable=False)
    sort_order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
