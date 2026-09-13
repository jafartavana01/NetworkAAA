"""
app.models.aaa_template_settings
===================================
The default Cisco IOS AAA command template used by Network Scan &
Provision's Apply flow (app.services.ssh_provision) -- stored so an
admin can permanently customize it for future use, not just edit it
per-apply (the existing "Edit commands before applying" panel already
covers the one-off case). Singleton, same convention as AdSettings
and MonitoringSettings.

Stored as a list of command-line TEMPLATE strings using Python
`.format()`-style placeholders (`{platform_ip}`, `{shared_secret}`) --
substituted at generation time by
app.services.ssh_provision.build_cisco_ios_aaa_commands, which falls
back to the original built-in template when no row exists yet (a
fresh install, or one where the admin has never opened the template
editor), so this feature is purely additive: nothing changes for an
install that never touches it.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AaaTemplateSettings(Base):
    __tablename__ = "aaa_template_settings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    commands: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # Admin-configurable defaults for app.services.ssh_provision's own
    # DEFAULT_CONNECT_TIMEOUT_SECONDS / DEFAULT_COMMAND_TIMEOUT_SECONDS
    # -- added directly in response to a real report that "Apply" got
    # stuck with no way to adjust it for a slow/high-latency device
    # link short of editing that file directly. Nullable so an
    # install that's never opened the timeout settings still falls
    # back to those same built-in defaults, the same "purely additive"
    # convention this file's own docstring already established for
    # `commands`.
    connect_timeout_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)
    command_timeout_seconds: Mapped[int | None] = mapped_column(Integer, nullable=True)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
