"""
app.models.system_info
========================
Persists a light audit trail of installation/build events (spec
section 16: "Installation/build information"). The authoritative,
detailed build record is the JSON file the installer writes to
/etc/aaa-platform/build_info.json (app.config.load_build_info); this
table just keeps a queryable history of when builds/installs happened,
independent of that file being overwritten by a future upgrade.

NOTE: no `from __future__ import annotations` here -- see the note in
app/models/admin.py for why (Python 3.14 + SQLAlchemy + stringified
`X | None` annotations is a confirmed CPython typing regression).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class InstallEvent(Base):
    __tablename__ = "install_events"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    event_type: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. "initial_install", "rebuild"
    commit_hash: Mapped[str] = mapped_column(String(64), nullable=True)
    detail: Mapped[str] = mapped_column(Text, nullable=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
