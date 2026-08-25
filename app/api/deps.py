"""
app.api.deps
=============
Shared FastAPI dependencies: resolves the authenticated admin from the
signed session cookie, enforces CSRF-token matching on state-changing
requests (spec section 35: CSRF protection), and gates
superadmin-only actions (managing other admin accounts, platform
network/TLS settings) behind AdminUser.is_superadmin -- the two-tier
RBAC this project implements: superadmin (everything) vs standard
admin (everything except platform self-management). Finer-grained,
per-permission RBAC is a reasonable future enhancement, not something
this pass claims to deliver.
"""
from __future__ import annotations

from fastapi import Cookie, Depends, Header, HTTPException, status
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser


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


def verify_csrf(
    x_csrf_token: str | None = Header(default=None),
    csrf_cookie: str | None = Cookie(default=None, alias=security.CSRF_COOKIE_NAME),
) -> None:
    if not x_csrf_token or not csrf_cookie or x_csrf_token != csrf_cookie:
        raise HTTPException(status.HTTP_403_FORBIDDEN, detail="CSRF token missing or invalid")
