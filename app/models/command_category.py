"""
app.models.command_category
=============================
PAM Expansion Plan §6: a vendor-neutral categorization layer for
commands (SHOW, INTERFACE, ROUTING, BGP, OSPF, SECURITY, AAA, SYSTEM,
CONFIGURATION, DANGEROUS). Purely a management/reporting abstraction --
`vendor` is a plain string (starting with "cisco_ios") rather than an
enum, specifically so a second vendor's category set can be added
later as new rows, not a schema change.

IMPORTANT (carried forward from CommandRule's own docstring, and
restated here because it applies just as much to categorization):
assigning a category to a command NEVER changes authorization
behavior on its own -- app/services/policy_engine.py (Phase 1,
Increment 2) must never branch on `category` when deciding
permit/deny. Category is for filtering, reporting, and risk-labeling
(§11) only, unless a future policy explicitly opts into using it as a
condition -- and even then, that's a deliberate, visible choice on
that one policy, not implicit behavior baked into the category itself.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CommandCategory(Base):
    __tablename__ = "command_categories"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), nullable=False)
    vendor: Mapped[str] = mapped_column(String(32), nullable=False, default="cisco_ios")
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # LOW | MEDIUM | HIGH | CRITICAL -- §11's static risk label. Lives
    # on the category rather than per-CommandRule: a risk level is a
    # property of "what kind of command is this" (reload is always
    # CRITICAL), not of any one policy's specific rule referencing it.
    risk_level: Mapped[str | None] = mapped_column(String(16), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
