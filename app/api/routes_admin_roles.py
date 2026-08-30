"""
app.api.routes_admin_roles
=============================
CRUD for granular RBAC roles (PAM Expansion Plan §29). Only a
superadmin can manage roles or the permission catalog -- creating or
editing a role is itself a privileged, security-relevant action, same
reasoning as why only a superadmin can manage other admin accounts.

`ensure_seeded` follows the exact pattern already established for
CommandCategory (app.api.routes_command_categories): seeds the
starter role templates once, on first boot, and is a no-op every
boot after that -- admin edits or deletions of the seeded templates
are never overwritten or reset.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.admin_role import AdminRole
from ..schemas.admin_role import AdminRoleCreate, AdminRoleOut, AdminRoleUpdate
from ..services.permissions import PERMISSION_CATALOG, ROLE_TEMPLATES
from .deps import get_current_superadmin, verify_csrf

router = APIRouter(prefix="/api/admin-roles", tags=["admin-roles"])


def ensure_seeded(db: Session) -> None:
    if db.query(AdminRole).first() is not None:
        return
    for template in ROLE_TEMPLATES:
        db.add(AdminRole(
            name=template["name"], description=template["description"],
            permissions=template["permissions"], is_template=True,
        ))
    db.commit()


@router.get("/permission-catalog")
def get_permission_catalog(
    _admin: AdminUser = Depends(get_current_superadmin),
):
    """The full, static list of permission keys a role can grant, with
    display labels and descriptions for the GUI -- see
    app.services.permissions for the canonical list."""
    return [{"key": p.key, "label": p.label, "description": p.description} for p in PERMISSION_CATALOG]


def _to_out(db: Session, role: AdminRole) -> AdminRoleOut:
    admin_count = db.query(func.count(AdminUser.id)).filter(AdminUser.role_id == role.id).scalar()
    return AdminRoleOut(
        id=str(role.id), name=role.name, description=role.description,
        permissions=list(role.permissions or []), is_template=role.is_template,
        admin_count=admin_count or 0,
    )


@router.get("", response_model=list[AdminRoleOut])
def list_roles(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    roles = db.query(AdminRole).order_by(AdminRole.name.asc()).all()
    return [_to_out(db, r) for r in roles]


@router.post("", response_model=AdminRoleOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_role(
    payload: AdminRoleCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    role = AdminRole(name=payload.name, description=payload.description, permissions=payload.permissions, is_template=False)
    db.add(role)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A role named '{payload.name}' already exists.")
    db.refresh(role)
    return _to_out(db, role)


def _get_role_or_404(db: Session, role_id: str) -> AdminRole:
    try:
        parsed_id = uuid.UUID(role_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Role not found.")
    role = db.query(AdminRole).filter(AdminRole.id == parsed_id).first()
    if not role:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Role not found.")
    return role


@router.put("/{role_id}", response_model=AdminRoleOut, dependencies=[Depends(verify_csrf)])
def update_role(
    role_id: str,
    payload: AdminRoleUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    role = _get_role_or_404(db, role_id)
    role.name = payload.name
    role.description = payload.description
    role.permissions = payload.permissions
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A role named '{payload.name}' already exists.")
    db.refresh(role)
    return _to_out(db, role)


@router.delete("/{role_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_role(
    role_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    """Deleting a role does NOT delete or lock out any admin using it
    -- AdminUser.role_id is ON DELETE SET NULL, so those accounts fall
    back to the safe, backward-compatible "no role assigned" behavior
    (full standard-admin access), never an error state."""
    role = _get_role_or_404(db, role_id)
    db.delete(role)
    db.commit()
