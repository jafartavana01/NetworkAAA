"""
app.models.device
===================
Network devices (NAS clients) -- spec section 18. Every field the GUI
exposes maps directly to something the configuration compiler
(app.services.config_compiler) writes into a tac_plus-ng `host {}`
block; there is no field here that doesn't correspond to real
generated config, per spec section 61 (no fake features).

`device_group_id` is added in Phase 4 below, now that DeviceGroup
exists. The policy-reference fields (authentication/authorization/
accounting policy) are still NOT included -- Authorization policy is
Phase 5, and adding a foreign key to a table that doesn't exist yet
would be exactly the half-built feature spec section 49 prohibits.

`shared_secret_encrypted` stores a Fernet token (app.security.encrypt_secret),
never plaintext. Only the configuration compiler ever decrypts it.

NOTE: no `from __future__ import annotations` here -- see the note in
app/models/admin.py for why (Python 3.14 + SQLAlchemy + stringified
`X | None` annotations is a confirmed CPython typing regression, and
this file has several `X | None` columns).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class NetworkDevice(Base):
    __tablename__ = "network_devices"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Also used as the tac_plus-ng `host <name> { }` block identifier --
    # constrained to an identifier-safe charset by app.schemas.device
    # (never escaped into the config; restricted at input time instead,
    # since bare-identifier grammar can't be safely quote-escaped).
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)     # CIDR, e.g. 10.10.10.10/32
    ipv6_address: Mapped[str | None] = mapped_column(String(64), nullable=True)  # CIDR, e.g. 2001:db8::1/128

    vendor: Mapped[str | None] = mapped_column(String(64), nullable=True)
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    device_group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("device_groups.id", ondelete="SET NULL"), nullable=True
    )

    shared_secret_encrypted: Mapped[str] = mapped_column(Text, nullable=False)

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
