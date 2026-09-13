"""
app.models.config_version
===========================
Every successfully applied configuration gets a row here (spec section
15). `content` stores the full compiled tac_plus-ng.conf text so
"View / Diff / Restore / Download" (section 15) don't depend on
anything still being on disk -- a version is restorable even if the
active file on disk was hand-edited or lost.

Version numbers are sequential per-installation, assigned by
app.services.config_compiler under a row lock so concurrent applies
can't collide.

NOTE: no `from __future__ import annotations` here -- see the note in
app/models/admin.py for why (Python 3.14 + SQLAlchemy + stringified
`X | None` annotations is a confirmed CPython typing regression, and
this file has several `X | None` columns).
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ConfigVersion(Base):
    __tablename__ = "config_versions"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    version_number: Mapped[int] = mapped_column(Integer, nullable=False, unique=True, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)

    # applied | rolled_back | superseded | restore_failed
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="applied")

    created_by: Mapped[str | None] = mapped_column(String(64), nullable=True)  # admin username, not a hard FK
    note: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
