"""
app.api.routes_tacacs_users
=============================
CRUD for TACACS+ user accounts (spec section 17). Passwords are
write-only: TacacsUserOut never includes the hash or plaintext.
Changing DB state here does NOT touch the live tac_plus-ng
configuration by itself -- same explicit compile/diff/apply flow as
devices (app.api.routes_config), not an implicit side effect of
saving a user.

Phase 4 adds `group_id` -- validated against TacacsGroup explicitly
(rather than just letting a bad ID surface as an opaque FK
IntegrityError) so the GUI gets a clear "that group doesn't exist"
error instead of a generic database failure.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..models.group import TacacsGroup
from ..models.user import TacacsUser
from ..schemas.user import TacacsUserCreate, TacacsUserOut, TacacsUserUpdate
from .deps import get_current_admin, verify_csrf

router = APIRouter(prefix="/api/tacacs-users", tags=["tacacs-users"])


def _parse_group_id(group_id: str | None) -> uuid.UUID | None:
    if not group_id:
        return None
    try:
        return uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid group id.")


def _resolve_group(db: Session, group_id: str | None) -> TacacsGroup | None:
    parsed = _parse_group_id(group_id)
    if parsed is None:
        return None
    group = db.query(TacacsGroup).filter(TacacsGroup.id == parsed).first()
    if not group:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That group doesn't exist.")
    return group


def _to_out(user: TacacsUser, group_name: str | None = None) -> TacacsUserOut:
    return TacacsUserOut(
        id=str(user.id),
        username=user.username,
        full_name=user.full_name,
        description=user.description,
        group_id=str(user.group_id) if user.group_id else None,
        group_name=group_name,
        enabled=user.enabled,
        allowed_source_ips=user.allowed_source_ips,
    )


def _group_names(db: Session) -> dict[uuid.UUID, str]:
    return {g.id: g.name for g in db.query(TacacsGroup).all()}


@router.get("", response_model=list[TacacsUserOut])
def list_users(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    users = db.query(TacacsUser).order_by(TacacsUser.username.asc()).all()
    names = _group_names(db)
    return [_to_out(u, names.get(u.group_id)) for u in users]


@router.post("", response_model=TacacsUserOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_user(
    payload: TacacsUserCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    group = _resolve_group(db, payload.group_id)
    user = TacacsUser(
        username=payload.username,
        full_name=payload.full_name,
        description=payload.description,
        group_id=group.id if group else None,
        enabled=payload.enabled,
        allowed_source_ips=payload.allowed_source_ips,
        password_hash=security.hash_password(payload.password),
    )
    db.add(user)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A user named '{payload.username}' already exists.")
    db.refresh(user)
    return _to_out(user, group.name if group else None)


def _get_user_or_404(db: Session, user_id: str) -> TacacsUser:
    try:
        parsed_id = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found.")
    user = db.query(TacacsUser).filter(TacacsUser.id == parsed_id).first()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found.")
    return user


@router.get("/{user_id}", response_model=TacacsUserOut)
def get_user(
    user_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    user = _get_user_or_404(db, user_id)
    names = _group_names(db)
    return _to_out(user, names.get(user.group_id))


@router.put("/{user_id}", response_model=TacacsUserOut, dependencies=[Depends(verify_csrf)])
def update_user(
    user_id: str,
    payload: TacacsUserUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    user = _get_user_or_404(db, user_id)
    group = _resolve_group(db, payload.group_id)

    user.username = payload.username
    user.full_name = payload.full_name
    user.description = payload.description
    user.group_id = group.id if group else None
    user.enabled = payload.enabled
    user.allowed_source_ips = payload.allowed_source_ips
    if payload.password:
        user.password_hash = security.hash_password(payload.password)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A user named '{payload.username}' already exists.")
    db.refresh(user)
    return _to_out(user, group.name if group else None)


@router.delete("/{user_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    user = _get_user_or_404(db, user_id)
    db.delete(user)
    db.commit()
