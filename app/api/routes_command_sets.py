"""
app.api.routes_command_sets
=============================
CRUD for reusable Command Sets (PAM Expansion Plan §5). Deletion is
blocked with a clear "referenced by N policies" message when a set is
still in use, rather than silently cascading and breaking whatever
policies relied on it -- the same explicit-reference-check pattern
already used for Policy deletion (which unassigns groups rather than
cascading) and Group deletion (which ungroups users rather than
cascading) elsewhere in this project.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.command_category import CommandCategory
from ..models.command_rule import CommandRule
from ..models.command_set import CommandSet
from ..models.policy_command_set import PolicyCommandSet
from ..schemas.command_set import CommandRuleOut, CommandSetCreate, CommandSetOut, CommandSetUpdate
from .deps import require_permission, verify_csrf

router = APIRouter(prefix="/api/command-sets", tags=["command-sets"])


def _policy_counts(db: Session) -> dict[uuid.UUID, int]:
    rows = (
        db.query(PolicyCommandSet.command_set_id, func.count(PolicyCommandSet.id))
        .group_by(PolicyCommandSet.command_set_id)
        .all()
    )
    return {cs_id: count for cs_id, count in rows}


def _category_names(db: Session) -> dict[uuid.UUID, str]:
    return {c.id: c.name for c in db.query(CommandCategory).all()}


def _to_out(cs: CommandSet, rules: list[CommandRule], category_names: dict, policy_count: int = 0) -> CommandSetOut:
    return CommandSetOut(
        id=str(cs.id),
        name=cs.name,
        description=cs.description,
        vendor=cs.vendor,
        enabled=cs.enabled,
        policy_count=policy_count,
        rules=[
            CommandRuleOut(
                id=str(r.id),
                order=r.order,
                action=r.action,
                command_pattern=r.command_pattern,
                description=r.description,
                category_id=str(r.category_id) if r.category_id else None,
                category_name=category_names.get(r.category_id),
            )
            for r in sorted(rules, key=lambda r: r.order)
        ],
    )


def _replace_rules(db: Session, command_set: CommandSet, rules_in: list) -> list[CommandRule]:
    db.query(CommandRule).filter(CommandRule.command_set_id == command_set.id).delete()
    new_rules = []
    for r in rules_in:
        category_id = None
        if r.category_id:
            try:
                category_id = uuid.UUID(r.category_id)
            except ValueError:
                raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid category id.")
            if not db.query(CommandCategory).filter(CommandCategory.id == category_id).first():
                raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That command category doesn't exist.")

        rule = CommandRule(
            command_set_id=command_set.id,
            order=r.order,
            action=r.action,
            command_pattern=r.command_pattern,
            description=r.description,
            category_id=category_id,
        )
        db.add(rule)
        new_rules.append(rule)
    return new_rules


@router.get("", response_model=list[CommandSetOut])
def list_command_sets(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:view")),
):
    sets = db.query(CommandSet).order_by(CommandSet.name.asc()).all()
    counts = _policy_counts(db)
    category_names = _category_names(db)
    all_rules = db.query(CommandRule).all()
    rules_by_set: dict[uuid.UUID, list[CommandRule]] = {}
    for r in all_rules:
        rules_by_set.setdefault(r.command_set_id, []).append(r)
    return [_to_out(cs, rules_by_set.get(cs.id, []), category_names, counts.get(cs.id, 0)) for cs in sets]


@router.post("", response_model=CommandSetOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_command_set(
    payload: CommandSetCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:write")),
):
    command_set = CommandSet(
        name=payload.name,
        description=payload.description,
        vendor=payload.vendor,
        enabled=payload.enabled,
    )
    db.add(command_set)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A command set named '{payload.name}' already exists.")

    rules = _replace_rules(db, command_set, payload.rules)
    db.commit()
    db.refresh(command_set)
    return _to_out(command_set, rules, _category_names(db))


def _get_command_set_or_404(db: Session, command_set_id: str) -> CommandSet:
    try:
        parsed_id = uuid.UUID(command_set_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Command set not found.")
    command_set = db.query(CommandSet).filter(CommandSet.id == parsed_id).first()
    if not command_set:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Command set not found.")
    return command_set


@router.get("/{command_set_id}", response_model=CommandSetOut)
def get_command_set(
    command_set_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:view")),
):
    command_set = _get_command_set_or_404(db, command_set_id)
    rules = db.query(CommandRule).filter(CommandRule.command_set_id == command_set.id).all()
    count = db.query(func.count(PolicyCommandSet.id)).filter(PolicyCommandSet.command_set_id == command_set.id).scalar()
    return _to_out(command_set, rules, _category_names(db), count or 0)


@router.put("/{command_set_id}", response_model=CommandSetOut, dependencies=[Depends(verify_csrf)])
def update_command_set(
    command_set_id: str,
    payload: CommandSetUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:write")),
):
    command_set = _get_command_set_or_404(db, command_set_id)
    command_set.name = payload.name
    command_set.description = payload.description
    command_set.vendor = payload.vendor
    command_set.enabled = payload.enabled

    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A command set named '{payload.name}' already exists.")

    rules = _replace_rules(db, command_set, payload.rules)
    db.commit()
    db.refresh(command_set)
    count = db.query(func.count(PolicyCommandSet.id)).filter(PolicyCommandSet.command_set_id == command_set.id).scalar()
    return _to_out(command_set, rules, _category_names(db), count or 0)


@router.delete("/{command_set_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_command_set(
    command_set_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:write")),
):
    command_set = _get_command_set_or_404(db, command_set_id)
    ref_count = db.query(func.count(PolicyCommandSet.id)).filter(PolicyCommandSet.command_set_id == command_set.id).scalar()
    if ref_count:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"This command set is referenced by {ref_count} polic{'y' if ref_count == 1 else 'ies'} -- remove those references first.",
        )
    db.delete(command_set)
    db.commit()
