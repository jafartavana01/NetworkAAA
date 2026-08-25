"""
app.models.admin
==================
Platform administrator accounts (spec section 16: "Platform
administrators"). This is distinct from TACACS+ end-user accounts,
which arrive in Phase 3 -- these are the people who log into the Web
GUI/REST API to manage the platform itself.

Primary keys are UUIDs rather than auto-increment integers throughout
the schema (here and in every model added in later phases). Spec
section 45 requires the data model not assume a single, permanently
local TACACS+ node; UUIDs avoid ID collisions if/when a future version
introduces multiple management-plane or database nodes, without
requiring a primary-key migration later.

NOTE: this file deliberately does NOT use
`from __future__ import annotations`. SQLAlchemy's declarative mapper
has to reconstruct `X | None` union annotations at class-definition
time, and on Python 3.14 doing that from a *stringified* annotation
(which is what `from __future__ import annotations` produces) hits a
confirmed CPython 3.14 typing regression
(https://github.com/python/cpython/issues/140348) that crashes with
`TypeError: descriptor '__getitem__' requires a 'typing.Union' object
but received a 'tuple'`. Without the future-annotations import,
`str | None` evaluates immediately to a real `types.UnionType` object
at class-body execution time (this has worked directly since Python
3.10, no future import needed for that part) and SQLAlchemy never
has to de-stringify anything, sidestepping the bug entirely rather
than depending on a specific SQLAlchemy patch version to work around
it.
Phase 8-adjacent addition: `allowed_source_ips` restricts which
source IPs/CIDRs an account may log in from at all (spec-adjacent
request: per-admin trusted-host restriction). NULL/empty means
unrestricted -- the default, and the only possible state for the
very first admin account, since restricting it before confirming
network access works would risk a self-lockout during initial setup.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_superadmin: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Comma-separated list of IPs/CIDRs (e.g. "10.0.0.5,192.168.1.0/24").
    # Stored as text rather than a normalized join table -- this is a
    # short, admin-edited allowlist per account, not a large or
    # independently-queried dataset; a table would be pure overhead
    # here.
    allowed_source_ips: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
