"""
app.models.admin_role
=======================
Granular RBAC (PAM Expansion Plan §29), built additively on top of the
existing two-tier model rather than replacing it -- per that section's
own explicit "maintain backward compatibility with the current
two-tier model" requirement.

AdminUser.is_superadmin is UNCHANGED and keeps meaning exactly what it
already means: unconditional access to everything, checked FIRST and
bypassing role permissions entirely (see app.api.deps.require_permission).
An AdminUser with no role assigned (`role_id IS NULL`) also keeps
behaving exactly as it already does today -- full access to every
route that only requires *some* authenticated admin (the vast
majority of this API), gated superadmin-only where it already was.
Nothing about existing accounts' access changes by this model
existing.

A role is a named, reusable set of permission strings (see
PERMISSION_CATALOG in app.services.permissions for the full list and
what each one actually gates) -- flat, not a nested per-resource
matrix. Simpler to store, check, and display, and every real request
this project has seen for granular RBAC ("Users: view/create/modify/
delete", "Policies: view/create/modify/activate/rollback") reduces
cleanly to a flat set of "<resource>:<action>" strings without losing
meaning.

`permissions` is stored as a JSON array of strings (Postgres JSONB)
rather than a normalized role_permissions join table -- a role's
permission set is edited as a whole from the GUI (the same "replace on
save" pattern this project already uses for CommandSet.rules and
Policy.command_set_ids), not queried or joined against independently,
so the normalization a join table would buy isn't needed here.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AdminRole(Base):
    __tablename__ = "admin_roles"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(64), unique=True, nullable=False, index=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    # List[str] of permission keys -- see app.services.permissions.PERMISSION_CATALOG.
    permissions: Mapped[list] = mapped_column(JSONB, nullable=False, default=list)

    # Marks the handful of starter templates (Read-Only Auditor,
    # Policy Manager, ...) seeded on first boot -- purely informational
    # (lets the GUI show "Template" next to these), never checked by
    # any permission logic. A template is an ordinary, fully editable
    # role once created; nothing about it is special or protected.
    is_template: Mapped[bool] = mapped_column(default=False, nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
