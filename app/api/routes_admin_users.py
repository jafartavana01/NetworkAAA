"""
app.api.routes_admin_users
============================
CRUD for platform admin accounts -- superadmin-only (spec section 35:
RBAC). Several guardrails here exist specifically to prevent an admin
from locking themselves, or everyone, out of the platform by mistake:

  - An admin can never delete or deactivate their OWN account (their
    current session would be invalidated on the very next request --
    app.api.deps.get_current_admin checks is_active on every request,
    not just at login).
  - The last remaining ACTIVE superadmin can never be deleted,
    deactivated, or demoted -- whether that's an admin acting on
    someone else's account or (blocked by the rule above anyway) their
    own.
  - Changing your OWN trusted-host allowlist is checked against the
    CURRENT request's source IP before being accepted -- rejecting a
    change that would immediately lock the editor themselves out,
    rather than letting them find out on their next login attempt.

None of these are enforced by the database -- they're business rules
specific to "don't let an admin brick their own access," checked here
in the API layer.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..schemas.admin import AdminUserCreate, AdminUserOut, AdminUserUpdate
from .deps import get_current_superadmin, verify_csrf

router = APIRouter(prefix="/api/admin-users", tags=["admin-users"])


def _to_out(admin: AdminUser, requesting_admin_id: uuid.UUID) -> AdminUserOut:
    return AdminUserOut(
        id=str(admin.id),
        username=admin.username,
        is_active=admin.is_active,
        is_superadmin=admin.is_superadmin,
        allowed_source_ips=admin.allowed_source_ips,
        created_at=admin.created_at.isoformat(),
        last_login_at=admin.last_login_at.isoformat() if admin.last_login_at else None,
        is_self=(admin.id == requesting_admin_id),
    )


def _active_superadmin_count(db: Session, *, excluding: uuid.UUID | None = None) -> int:
    query = db.query(AdminUser).filter(AdminUser.is_superadmin.is_(True), AdminUser.is_active.is_(True))
    if excluding is not None:
        query = query.filter(AdminUser.id != excluding)
    return query.count()


@router.get("", response_model=list[AdminUserOut])
def list_admin_users(
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_superadmin),
):
    admins = db.query(AdminUser).order_by(AdminUser.username.asc()).all()
    return [_to_out(a, admin.id) for a in admins]


@router.post("", response_model=AdminUserOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_admin_user(
    payload: AdminUserCreate,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_superadmin),
):
    new_admin = AdminUser(
        username=payload.username,
        password_hash=security.hash_password(payload.password),
        is_active=payload.is_active,
        is_superadmin=payload.is_superadmin,
        allowed_source_ips=payload.allowed_source_ips,
    )
    db.add(new_admin)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"An admin named '{payload.username}' already exists.")
    db.refresh(new_admin)
    return _to_out(new_admin, admin.id)


def _get_admin_or_404(db: Session, admin_id: str) -> AdminUser:
    try:
        parsed_id = uuid.UUID(admin_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Admin not found.")
    target = db.query(AdminUser).filter(AdminUser.id == parsed_id).first()
    if not target:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Admin not found.")
    return target


@router.put("/{admin_id}", response_model=AdminUserOut, dependencies=[Depends(verify_csrf)])
def update_admin_user(
    admin_id: str,
    payload: AdminUserUpdate,
    request: Request,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_superadmin),
):
    target = _get_admin_or_404(db, admin_id)
    is_self = target.id == admin.id

    if is_self and not payload.is_active:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="You cannot deactivate your own account.")

    would_lose_superadmin = target.is_superadmin and target.is_active and not (payload.is_superadmin and payload.is_active)
    if would_lose_superadmin and _active_superadmin_count(db, excluding=target.id) == 0:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="This is the last active superadmin -- promote another account first.",
        )

    if is_self and payload.allowed_source_ips:
        source_ip = request.client.host if request.client else None
        if not source_ip or not security.is_source_ip_allowed(payload.allowed_source_ips, source_ip):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail=f"That trusted-host list would exclude your current address ({source_ip or 'unknown'}). "
                       "Add it explicitly, or have another superadmin make this change instead.",
            )

    target.username = payload.username
    target.is_active = payload.is_active
    target.is_superadmin = payload.is_superadmin
    target.allowed_source_ips = payload.allowed_source_ips
    if payload.password:
        target.password_hash = security.hash_password(payload.password)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"An admin named '{payload.username}' already exists.")
    db.refresh(target)
    return _to_out(target, admin.id)


@router.delete("/{admin_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_admin_user(
    admin_id: str,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_superadmin),
):
    target = _get_admin_or_404(db, admin_id)

    if target.id == admin.id:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="You cannot delete your own account.")

    if target.is_superadmin and target.is_active and _active_superadmin_count(db, excluding=target.id) == 0:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="This is the last active superadmin -- promote another account before deleting it.",
        )

    db.delete(target)
    db.commit()
