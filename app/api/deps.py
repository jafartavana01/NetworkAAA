"""
app.api.deps
=============
Shared FastAPI dependencies: resolves the authenticated admin from the
signed session cookie, enforces CSRF-token matching on state-changing
requests (spec section 35: CSRF protection), gates superadmin-only
actions behind AdminUser.is_superadmin, and -- PAM Expansion Plan §29
-- gates a growing set of routes behind granular permissions via
`require_permission()`.

`require_permission()` is strictly additive on top of the original
two-tier model, per §29's own explicit "maintain backward
compatibility" requirement: a superadmin bypasses it unconditionally
(checked first, always allowed, exactly as before); an account with no
role assigned (`role_id IS NULL` -- every account that existed before
this feature, and every new one by default) also passes unconditionally,
behaving EXACTLY as it always did -- full access to anything that only
ever required "some authenticated admin." A role only ever narrows
access for an account it's deliberately assigned to; nothing about
any existing account's access changes by this mechanism existing.
"""
from __future__ import annotations

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..models.admin_role import AdminRole


def get_current_admin(
    db: Session = Depends(get_db),
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
) -> AdminUser:
    if not session_token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")

    username = security.read_session_token(session_token)
    if not username:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Session expired or invalid")

    admin = db.query(AdminUser).filter(AdminUser.username == username).first()
    if not admin or not admin.is_active:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Account disabled or not found")

    return admin


def get_current_superadmin(
    admin: AdminUser = Depends(get_current_admin),
) -> AdminUser:
    if not admin.is_superadmin:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="Superadmin privileges required.")
    return admin


def require_permission(permission_key: str):
    """
    Dependency FACTORY, not a dependency itself -- use as
    `Depends(require_permission("policies:write"))`. See module
    docstring for the exact backward-compatibility guarantees
    (superadmin and no-role-assigned both bypass unconditionally).

    Applied so far to Policies, Command Sets, Devices, Device Groups,
    and Device Access Grants -- the resource categories the original
    request for this feature named explicitly. Not yet applied to
    every route in the API (accounting, diagnostics, config,
    TACACS+ users/groups, admin user management still only require
    *some* authenticated admin, or superadmin where they already did)
    -- extending coverage is a matter of adding this same dependency
    to more routes over time, not a further schema or mechanism change.
    See docs/ARCHITECTURE.md for the exact, current list.
    """
    def check_permission(
        admin: AdminUser = Depends(get_current_admin),
        db: Session = Depends(get_db),
    ) -> AdminUser:
        if admin.is_superadmin:
            return admin
        if admin.role_id is None:
            return admin
        role = db.query(AdminRole).filter(AdminRole.id == admin.role_id).first()
        if role and permission_key in (role.permissions or []):
            return admin
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            detail=f"Your role doesn't include the '{permission_key}' permission.",
        )
    return check_permission


def verify_csrf(
    x_csrf_token: str | None = Header(default=None),
    csrf_cookie: str | None = Cookie(default=None, alias=security.CSRF_COOKIE_NAME),
) -> None:
    if not x_csrf_token or not csrf_cookie or x_csrf_token != csrf_cookie:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="CSRF token missing or invalid")


def require_feature(feature_key: str):
    """
    Dependency that refuses a request when the installation's licence
    does not include `feature_key`.

    Checked PER REQUEST rather than at router-mount time, because a
    licence can be imported while the service is running -- gating at
    startup would mean a customer had to restart to use what they just
    bought, and would leave routes mounted-but-unlicensed after a
    licence expired.

    Returns 402 rather than 403: this is "your plan does not include
    this", not "you lack permission", and conflating them would send an
    operator to check their role when the answer is their licence.
    """
    from fastapi import HTTPException, status

    from ..services import editions as _editions
    from ..services import entitlements as _entitlements

    def _dependency(db: Session = Depends(get_db)):
        if _entitlements.has_feature(db, feature_key):
            return
        feature = _editions.FEATURES_BY_KEY.get(feature_key)
        name = feature.name if feature else feature_key
        current = _entitlements.current(db)
        raise HTTPException(
            status.HTTP_402_PAYMENT_REQUIRED,
            detail=(
                f"{name} is not included in the {current.edition_name} edition. "
                "Import a licence that includes it to enable this area."
            ),
        )

    return _dependency
