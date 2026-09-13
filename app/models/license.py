"""
app.models.license
=====================
Stores the installation's license.

Only `license_text` is AUTHORITATIVE. Everything else on this row is a
cache for display and is re-derived from the signature on every read,
so editing a cached column in the database changes what is shown for a
moment and nothing about what is enforced.

`highest_seen_utc` exists to blunt clock rollback: it only ever moves
FORWARD. If the system clock jumps backwards past it, expiry is
evaluated against the highest time the installation has ever seen
rather than the current clock, so winding the clock back does not
revive an expired license.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PlatformLicense(Base):
    __tablename__ = "platform_license"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    #: The signed license, exactly as imported. The single source of
    #: truth: every entitlement decision re-verifies this text.
    license_text: Mapped[str | None] = mapped_column(Text, nullable=True)

    # --- cached for display only; never trusted for enforcement ------
    cached_edition: Mapped[str | None] = mapped_column(String(32), nullable=True)
    cached_customer: Mapped[str | None] = mapped_column(String(200), nullable=True)
    cached_device_limit: Mapped[int | None] = mapped_column(Integer, nullable=True)
    cached_expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    #: Monotonic high-water mark; see the module docstring.
    highest_seen_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    #: Devices that existed before a limit began applying to them. They
    #: keep working; they do not license new additions. See
    #: services.entitlements.
    grandfathered_device_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    imported_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    imported_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
