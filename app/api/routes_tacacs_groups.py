"""
app.api.routes_tacacs_groups
==============================
CRUD for TACACS+ groups (spec section 16/53). Deleting a group does
NOT delete its member users -- the FK is ON DELETE SET NULL
(app.models.user.TacacsUser.group_id), so members just become
ungrouped rather than being destroyed alongside the group.

PAM Expansion Plan Increment 1: a group no longer owns a `policy_id`.
`referenced_by_policy_names` is a read-only reverse lookup (which
policies currently have their condition_group_id pointing at this
group) -- assigning a policy TO a group now happens on the policy's
own edit form (app.api.routes_policies), not here.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.group import TacacsGroup
from ..models.policy import Policy
from ..models.user import TacacsUser
from ..schemas.group import TacacsGroupCreate, TacacsGroupOut, TacacsGroupUpdate
from .deps import get_current_admin, verify_csrf

router = APIRouter(prefix="/api/tacacs-groups", tags=["tacacs-groups"])


def _member_counts(db: Session) -> dict[uuid.UUID, int]:
    rows = (
        db.query(TacacsUser.group_id, func.count(TacacsUser.id))
        .filter(TacacsUser.group_id.isnot(None))
        .group_by(TacacsUser.group_id)
        .all()
    )
    return {group_id: count for group_id, count in rows}


def _referencing_policy_names(db: Session) -> dict[uuid.UUID, list[str]]:
    rows = db.query(Policy).filter(Policy.condition_group_id.isnot(None)).all()
    result: dict[uuid.UUID, list[str]] = {}
    for p in rows:
        result.setdefault(p.condition_group_id, []).append(p.name)
    return result


def _to_out(group: TacacsGroup, member_count: int = 0, policy_names: list[str] | None = None) -> TacacsGroupOut:
    return TacacsGroupOut(
        id=str(group.id),
        name=group.name,
        description=group.description,
        member_count=member_count,
        referenced_by_policy_names=sorted(policy_names or []),
    )


@router.get("", response_model=list[TacacsGroupOut])
def list_groups(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    groups = db.query(TacacsGroup).order_by(TacacsGroup.name.asc()).all()
    counts = _member_counts(db)
    policy_names = _referencing_policy_names(db)
    return [_to_out(g, counts.get(g.id, 0), policy_names.get(g.id)) for g in groups]


@router.post("", response_model=TacacsGroupOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_group(
    payload: TacacsGroupCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    group = TacacsGroup(name=payload.name, description=payload.description)
    db.add(group)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A group named '{payload.name}' already exists.")
    db.refresh(group)
    return _to_out(group)


def _get_group_or_404(db: Session, group_id: str) -> TacacsGroup:
    try:
        parsed_id = uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Group not found.")
    group = db.query(TacacsGroup).filter(TacacsGroup.id == parsed_id).first()
    if not group:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Group not found.")
    return group


@router.get("/{group_id}", response_model=TacacsGroupOut)
def get_group(
    group_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    group = _get_group_or_404(db, group_id)
    count = db.query(func.count(TacacsUser.id)).filter(TacacsUser.group_id == group.id).scalar()
    policy_names = _referencing_policy_names(db)
    return _to_out(group, count or 0, policy_names.get(group.id))


@router.put("/{group_id}", response_model=TacacsGroupOut, dependencies=[Depends(verify_csrf)])
def update_group(
    group_id: str,
    payload: TacacsGroupUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    group = _get_group_or_404(db, group_id)
    group.name = payload.name
    group.description = payload.description
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A group named '{payload.name}' already exists.")
    db.refresh(group)
    count = db.query(func.count(TacacsUser.id)).filter(TacacsUser.group_id == group.id).scalar()
    policy_names = _referencing_policy_names(db)
    return _to_out(group, count or 0, policy_names.get(group.id))


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_group(
    group_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    group = _get_group_or_404(db, group_id)
    db.delete(group)
    db.commit()
