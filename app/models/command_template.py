"""
app.models.command_template
==============================
Network Operations & Assurance Engine, Phase 1. A reusable, named list
of raw CLI command strings meant to be *executed* against a device
over SSH -- e.g. "Cisco IOS Basic Health": terminal length 0, show
version, show inventory, ...

DELIBERATELY NOT the same thing as CommandSet (app.models.command_set):
CommandSet is a list of permit/deny AUTHORIZATION rules the TACACS+
policy engine evaluates when deciding whether a logged-in user may
run a command a NAS is asking about. CommandTemplate is a list of
commands THIS PLATFORM will actively run against a device to collect
output. One is an authorization decision input; the other is an
execution script. Conflating them was explicitly warned against by
the spec this feature was built from ("Do not collapse these objects
into one generic 'command' object") and would also be a real
correctness bug -- an authorization rule list and a command list have
no reason to share a schema just because both mention "commands".

`commands` is stored as an ordered JSONB list of plain strings, same
storage shape as AaaTemplateSettings.commands (app.models.aaa_template_settings)
-- no separate CommandTemplateVersion table yet in Phase 1; version
history for templates is deferred, same "don't build a schema for a
feature phase that hasn't arrived" discipline this project has
followed throughout (see e.g. PolicyVersion existing only once Policy
versioning was actually the increment being built).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CommandTemplate(Base):
    __tablename__ = "command_templates"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(128), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # "cisco_ios" today (the only platform this project's execution
    # engine targets so far -- see app.services.network_ops_execution's
    # own docstring on the vendor-adapter seam left for later
    # platforms); a plain string, not an enum, for the exact reason
    # CommandCategory.vendor already is one.
    vendor: Mapped[str] = mapped_column(String(64), nullable=False, default="cisco_ios")
    platform: Mapped[str | None] = mapped_column(String(64), nullable=True)  # e.g. "IOS-XE" -- optional, informational
    device_role: Mapped[str | None] = mapped_column(String(64), nullable=True)  # e.g. "ACCESS", "CORE" -- optional, informational

    commands: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    command_timeout_seconds: Mapped[int] = mapped_column(Integer, nullable=False, default=30)

    created_by_admin_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("admin_users.id", ondelete="SET NULL"), nullable=True
    )

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
