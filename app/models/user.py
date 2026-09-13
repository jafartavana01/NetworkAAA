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

    # Nullable now (was NOT NULL): an "ad"-sourced user has no local
    # password at all -- tac_plus-ng's MAVIS backend authenticates
    # them against Active Directory directly (see
    # app.services.config_compiler's AD integration section), so
    # there's nothing to hash locally. Required (enforced at the
    # schema layer, app.schemas.user) only when auth_source == "local".
    password_hash: Mapped[str | None] = mapped_column(Text, nullable=True)

    # "local" (this platform's own bcrypt-hashed password, the
    # original and still-default model) or "ad" (authentication
    # delegated entirely to tac_plus-ng's MAVIS AD backend; this row
    # exists in OUR database purely so the admin can assign a group
    # and have policies apply to this identity within this platform's
    # own UI -- it is a REFERENCE record, not a credential store, for
    # an "ad" user).
    auth_source: Mapped[str] = mapped_column(String(16), nullable=False, default="local")

    # The real AD identity this record refers to (a sAMAccountName or
    # UPN, e.g. "jdoe" or "jdoe@corp.example.com") -- browsable/
    # searchable via app.services.ad_directory, or typed manually.
    # NULL for a "local" user.
    ad_identity: Mapped[str | None] = mapped_column(String(255), nullable=True)

    full_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("tacacs_groups.id", ondelete="SET NULL"), nullable=True
    )

    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Trusted-host allowlist -- SAME storage/parsing convention as
    # AdminUser.allowed_source_ips (comma-separated IPs/CIDRs, parsed
    # by the same generic app.security.parse_allowed_source_ips /
    # is_source_ip_allowed helpers, reused as-is rather than
    # duplicated). NOT YET ENFORCED by the generated tac_plus-ng
    # config -- see app.services.condition_engine's docstring and
    # docs/ARCHITECTURE.md for exactly why: AdminUser's version works
    # because THIS platform's own login check enforces it directly;
    # a TACACS+ end-user authenticates THROUGH tac_plus-ng, and
    # per-user (not per-group) source-IP restriction has no directly
    # confirmed tac_plus-ng syntax for this project's data model
    # (each TacacsUser has exactly one group, and the confirmed
    # ACL-restriction examples found during research were all
    # group-level, not user-level, for tac_plus-ng's newer
    # scripting-style config specifically -- restricting the shared
    # group would wrongly restrict every member, not just one user).
    # Stored now so the GUI/API/Simulator can exist and be tested
    # ahead of that compiler work, but this field intentionally does
    # NOT yet change what any real login is allowed to do -- the GUI
    # says so explicitly, not just this comment.
    allowed_source_ips: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
