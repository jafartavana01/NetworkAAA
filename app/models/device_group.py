"""
app.models.device_group
=========================
Device groups (spec section 19: "Core Switches, Access Switches,
Routers, Firewalls, Data Center, Branches..."). Unlike TacacsGroup,
this has no direct tac_plus-ng syntax counterpart -- there is no
confirmed "device group" concept in the daemon's config language, and
inventing one would repeat the exact mistake this project has
deliberately avoided elsewhere (spec section 20: don't generate config
that doesn't correspond to something the core actually supports).

What this DOES do today: organizes devices in the GUI, and gives
Phase 5's authorization engine something to target ("apply this policy
to every Core Switch") once ruleset/profile support exists. Until
then, it's a real, functional grouping feature for the management
plane -- just not something the compiler emits as its own config
block. Devices reference it via NetworkDevice.device_group_id.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class DeviceGroup(Base):
    __tablename__ = "device_groups"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
