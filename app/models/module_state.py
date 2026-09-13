"""
app.models.module_state
=========================
Persists which registered modules (app.modules.registry) are enabled,
so the choice survives restarts (spec section 28). The `core` module
row is seeded enabled+mandatory at install time and the API refuses to
disable any module with mandatory=True at the registry level, not just
in this table, so a direct DB edit can't silently take TACACS+ core
out of a mandatory state either (app.api routes re-check the registry).

NOTE: no `from __future__ import annotations` here -- see the note in
app/models/admin.py (kept consistent across all model files even
though this one has no union-typed columns today).
"""
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ModuleState(Base):
    __tablename__ = "module_state"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
