"""
app.models.user
=================
TACACS+ end-user accounts (spec section 17) -- distinct from
AdminUser (app.models.admin), which is who logs into this platform's
own GUI/API. These are the accounts that authenticate against
tac_plus-ng from a NAS (switch/router) login prompt.

`password_hash` uses the exact same bcrypt scheme as AdminUser
(app.security.hash_password/verify_password) -- and, unlike device
shared secrets, does NOT need reversible encryption. TACACS+ login
passwords are verified against a `password login = crypt <hash>`
directive in the generated config (confirmed against a real working
tac_plus-ng config posted by a user and replied to by the project's
own maintainer -- see app/services/config_compiler.py), and tac_plus-ng
verifies via the system's crypt() library the same way a Unix login
does: it hashes the *supplied* password and compares hashes, never
needing the stored value back in plaintext. One hashing scheme, two
consumers (this app's own login check, and the value handed to
tac_plus-ng) -- no separate secret-management story needed here.

No privilege level / profile reference yet -- that's Phase 5
(Authorization). Adding it now would be exactly the half-built,
references-nothing kind of field spec section 49 warns against.
Group membership (`group_id`) is added in Phase 4 below -- single
group per user for now, matching every real-world example found
during research (`member = <one-group>`); multi-group membership
isn't confirmed and isn't implemented speculatively.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class TacacsUser(Base):
    __tablename__ = "tacacs_users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Also used as the tac_plus-ng `user <name> { }` block identifier --
    # same identifier-safe-charset restriction as NetworkDevice.name,
    # and for the same reason (app.schemas.user).
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)

    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    full_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tacacs_groups.id", ondelete="SET NULL"), nullable=True
    )

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
