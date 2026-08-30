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
from pydantic import BaseModel
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
        ad_group_name=group.ad_group_name,
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
    group = TacacsGroup(name=payload.name, description=payload.description, ad_group_name=payload.ad_group_name)
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
    group.ad_group_name = payload.ad_group_name
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


@router.get("/{group_id}/members")
def list_members(
    group_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """The other half of the member_count already shown on every
    group -- this was previously the one thing you couldn't see or
    manage from the Groups page itself, only indirectly by editing
    each user's own group field one at a time."""
    group = _get_group_or_404(db, group_id)
    members = db.query(TacacsUser).filter(TacacsUser.group_id == group.id).order_by(TacacsUser.username.asc()).all()
    return [{"id": str(u.id), "username": u.username, "full_name": u.full_name, "enabled": u.enabled} for u in members]


class AddMemberRequest(BaseModel):
    user_id: str


@router.post("/{group_id}/members", dependencies=[Depends(verify_csrf)])
def add_member(
    group_id: str,
    payload: AddMemberRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """Adding a member here is the same underlying change as editing
    that user's own Group field -- TacacsUser.group_id is still a
    single FK (one group per user), so adding someone already in a
    DIFFERENT group here reassigns them, it doesn't add a second
    membership. The response says which happened so the GUI can be
    clear about it, not just silently move them."""
    group = _get_group_or_404(db, group_id)
    try:
        user_id = uuid.UUID(payload.user_id)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid user id.")
    user = db.query(TacacsUser).filter(TacacsUser.id == user_id).first()
    if not user:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That user doesn't exist.")

    reassigned_from = None
    if user.group_id and user.group_id != group.id:
        previous = db.query(TacacsGroup).filter(TacacsGroup.id == user.group_id).first()
        reassigned_from = previous.name if previous else None

    user.group_id = group.id
    db.commit()
    return {"status": "ok", "reassigned_from": reassigned_from}


@router.delete("/{group_id}/members/{user_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def remove_member(
    group_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """Ungroups the user -- does not delete their account, matching
    how deleting the whole group itself already behaves (SET NULL,
    never a cascading delete of the user)."""
    group = _get_group_or_404(db, group_id)
    try:
        parsed_user_id = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found.")
    user = db.query(TacacsUser).filter(TacacsUser.id == parsed_user_id, TacacsUser.group_id == group.id).first()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="That user is not a member of this group.")
    user.group_id = None
    db.commit()
