"""
app.models.audit_schedule_settings
=====================================
Settings for automatic, unattended Security Center auditing: a single
platform-owned SSH service account (used for every scheduled run,
across every device, rather than requiring a human to type
credentials in each time) plus the schedule itself.

Singleton by convention, not by a database constraint -- same pattern
as app.models.ad_settings: the API only ever reads/writes the first
(and normally only) row. `ssh_password_encrypted` follows the EXACT
same Fernet-encryption pattern as NetworkDevice.shared_secret_encrypted
and AdSettings.bind_password_encrypted (app.security.encrypt_secret /
decrypt_secret) -- a service account capable of reaching every device
unattended is at least as sensitive as either of those, never stored
or logged in plaintext.

`management_ip_note` is deliberately a free-text field the admin fills
in themselves, not an auto-detected value: this platform may have
multiple network interfaces, and guessing wrong about which outbound
IP devices will actually see would be worse than not guessing at all
-- presented in the GUI as "the IP address to allow-list on each
device's own ACL for this account," not as something NetworkAAA
itself enforces (it has no ability to configure a device's own access
control).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AuditScheduleSettings(Base):
    __tablename__ = "audit_schedule_settings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    ssh_username: Mapped[str] = mapped_column(String(128), nullable=False, default="")
    ssh_password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)

    # 24-hour "HH:MM" in the server's own local time -- deliberately a
    # single daily time, not a full cron expression: the request was
    # "by default every day," and a single field an admin can read at
    # a glance is more honest about what this actually offers than a
    # cron syntax input inviting schedules this was never built to
    # guarantee (e.g. sub-daily runs against a fleet that can take
    # meaningful time to audit one device at a time).
    daily_run_time: Mapped[str] = mapped_column(String(5), nullable=False, default="02:00")

    management_ip_note: Mapped[str | None] = mapped_column(String(255), nullable=True)

    last_run_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_run_status: Mapped[str | None] = mapped_column(String(32), nullable=True)  # completed | failed | partial
    last_run_summary: Mapped[str | None] = mapped_column(Text, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
