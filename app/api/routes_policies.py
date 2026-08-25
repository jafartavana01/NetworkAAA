"""
app.api.routes_policies
=========================
CRUD for authorization policies (PAM Expansion Plan §4). A policy's
referenced Command Sets are replaced wholesale on every save (the full
ordered id list, same reasoning as command sets' own rule list -- see
app.schemas.policy). Condition fields (group/device/device-group) are
validated against real rows the same way routes_tacacs_groups.py
already validates policy_id -- a bad id surfaces as a clear 400, not
an opaque FK IntegrityError.

Deleting a policy does not touch anything it referenced or that
referenced it -- PolicyCommandSet rows cascade-delete (they're pure
join rows with no independent meaning once the policy is gone), and
nothing else points AT a policy in this model (conditions point the
other way: Policy -> Group/Device/DeviceGroup, not
Group/Device/DeviceGroup -> Policy), so there's no "N things reference
this, are you sure" check needed here the way CommandSet deletion
needs one.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.command_set import CommandSet
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..models.group import TacacsGroup
from ..models.policy import Policy
from ..models.policy_command_set import PolicyCommandSet
from ..schemas.policy import PolicyCreate, PolicyOut, PolicyUpdate, ReferencedCommandSet
from ..services import policy_versioning
from .deps import get_current_admin, verify_csrf

router = APIRouter(prefix="/api/policies", tags=["policies"])


def _parse_optional_uuid(value: str | None, *, field_label: str) -> uuid.UUID | None:
    if not value:
        return None
    try:
        return uuid.UUID(value)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Invalid {field_label} id.")


def _resolve_conditions(db: Session, payload) -> tuple[uuid.UUID | None, uuid.UUID | None, uuid.UUID | None]:
    group_id = _parse_optional_uuid(payload.condition_group_id, field_label="group")
    device_id = _parse_optional_uuid(payload.condition_device_id, field_label="device")
    device_group_id = _parse_optional_uuid(payload.condition_device_group_id, field_label="device group")

    if group_id and not db.query(TacacsGroup).filter(TacacsGroup.id == group_id).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That group condition doesn't exist.")
    if device_id and not db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That device condition doesn't exist.")
    if device_group_id and not db.query(DeviceGroup).filter(DeviceGroup.id == device_group_id).first():
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That device group condition doesn't exist.")

    return group_id, device_id, device_group_id


def _replace_command_sets(db: Session, policy: Policy, command_set_ids: list[str]) -> list[CommandSet]:
    db.query(PolicyCommandSet).filter(PolicyCommandSet.policy_id == policy.id).delete()

    resolved: list[CommandSet] = []
    for order, raw_id in enumerate(command_set_ids):
        try:
            cs_id = uuid.UUID(raw_id)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid command set id.")
        command_set = db.query(CommandSet).filter(CommandSet.id == cs_id).first()
        if not command_set:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That command set doesn't exist.")
        db.add(PolicyCommandSet(policy_id=policy.id, command_set_id=cs_id, order=order))
        resolved.append(command_set)
    return resolved


def policy_to_out(db: Session, policy: Policy, command_sets: list[CommandSet] | None = None) -> PolicyOut:
    if command_sets is None:
        joins = (
            db.query(PolicyCommandSet)
            .filter(PolicyCommandSet.policy_id == policy.id)
            .order_by(PolicyCommandSet.order.asc())
            .all()
        )
        command_sets = []
        for j in joins:
            cs = db.query(CommandSet).filter(CommandSet.id == j.command_set_id).first()
            if cs:
                command_sets.append(cs)

    group = db.query(TacacsGroup).filter(TacacsGroup.id == policy.condition_group_id).first() if policy.condition_group_id else None
    device = db.query(NetworkDevice).filter(NetworkDevice.id == policy.condition_device_id).first() if policy.condition_device_id else None
    device_group = db.query(DeviceGroup).filter(DeviceGroup.id == policy.condition_device_group_id).first() if policy.condition_device_group_id else None

    return PolicyOut(
        id=str(policy.id),
        name=policy.name,
        description=policy.description,
        enabled=policy.enabled,
        priority=policy.priority,
        condition_group_id=str(policy.condition_group_id) if policy.condition_group_id else None,
        condition_device_id=str(policy.condition_device_id) if policy.condition_device_id else None,
        condition_device_group_id=str(policy.condition_device_group_id) if policy.condition_device_group_id else None,
        condition_group_name=group.name if group else None,
        condition_device_name=device.name if device else None,
        condition_device_group_name=device_group.name if device_group else None,
        default_priv_lvl=policy.default_priv_lvl,
        default_action=policy.default_action,
        command_sets=[ReferencedCommandSet(id=str(cs.id), name=cs.name, enabled=cs.enabled) for cs in command_sets],
    )


def _check_priority_available(db: Session, priority: int, *, exclude_id: uuid.UUID | None = None) -> None:
    """
    Explicit pre-check for a clear, specific error message -- the
    DEFERRABLE INITIALLY DEFERRED unique constraint on Policy.priority
    (see app/models/policy.py) is the real, authoritative guarantee,
    but it only fires at commit time with a generic IntegrityError.
    Checking here first means a single-policy create/update gets a
    friendly, actionable message immediately; the bulk reorder
    endpoint below doesn't need this check at all, since it's the one
    legitimate case where priorities are SUPPOSED to pass through
    other policies' current values on the way to their final,
    collectively-unique state within one transaction.
    """
    query = db.query(Policy).filter(Policy.priority == priority)
    if exclude_id is not None:
        query = query.filter(Policy.id != exclude_id)
    conflict = query.first()
    if conflict is not None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            detail=f"Priority {priority} is already used by policy '{conflict.name}' -- "
                   "choose a different value, or drag rows on the Policies page to reorder automatically.",
        )


@router.get("", response_model=list[PolicyOut])
def list_policies(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    policies = db.query(Policy).order_by(Policy.priority.asc(), Policy.created_at.asc()).all()
    return [policy_to_out(db, p) for p in policies]


@router.post("", response_model=PolicyOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_policy(
    payload: PolicyCreate,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    _check_priority_available(db, payload.priority)
    group_id, device_id, device_group_id = _resolve_conditions(db, payload)

    policy = Policy(
        name=payload.name,
        description=payload.description,
        enabled=payload.enabled,
        priority=payload.priority,
        condition_group_id=group_id,
        condition_device_id=device_id,
        condition_device_group_id=device_group_id,
        default_priv_lvl=payload.default_priv_lvl,
        default_action=payload.default_action,
    )
    db.add(policy)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A policy named '{payload.name}' already exists.")

    command_sets = _replace_command_sets(db, policy, payload.command_set_ids)
    policy_versioning.record_version(
        db, policy, created_by=admin.username,
        change_description=payload.change_description or "Created",
    )
    db.commit()
    db.refresh(policy)
    return policy_to_out(db, policy, command_sets)


def _get_policy_or_404(db: Session, policy_id: str) -> Policy:
    try:
        parsed_id = uuid.UUID(policy_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Policy not found.")
    policy = db.query(Policy).filter(Policy.id == parsed_id).first()
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Policy not found.")
    return policy


@router.get("/{policy_id}", response_model=PolicyOut)
def get_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    policy = _get_policy_or_404(db, policy_id)
    return policy_to_out(db, policy)


@router.put("/{policy_id}", response_model=PolicyOut, dependencies=[Depends(verify_csrf)])
def update_policy(
    policy_id: str,
    payload: PolicyUpdate,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    policy = _get_policy_or_404(db, policy_id)
    if payload.priority != policy.priority:
        _check_priority_available(db, payload.priority, exclude_id=policy.id)
    group_id, device_id, device_group_id = _resolve_conditions(db, payload)

    policy.name = payload.name
    policy.description = payload.description
    policy.enabled = payload.enabled
    policy.priority = payload.priority
    policy.condition_group_id = group_id
    policy.condition_device_id = device_id
    policy.condition_device_group_id = device_group_id
    policy.default_priv_lvl = payload.default_priv_lvl
    policy.default_action = payload.default_action

    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A policy named '{payload.name}' already exists.")

    command_sets = _replace_command_sets(db, policy, payload.command_set_ids)
    policy_versioning.record_version(
        db, policy, created_by=admin.username,
        change_description=payload.change_description,
    )
    db.commit()
    db.refresh(policy)
    return policy_to_out(db, policy, command_sets)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    policy = _get_policy_or_404(db, policy_id)
    db.delete(policy)
    db.commit()


class ReorderRequest(BaseModel):
    ordered_ids: list[str]


@router.post("/reorder", dependencies=[Depends(verify_csrf)])
def reorder_policies(
    payload: ReorderRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """
    Drag-and-drop reorder support: reassigns priority = (index+1)*10
    for every policy in `ordered_ids`, in ONE transaction. This is
    the one legitimate case where a policy's priority is expected to
    pass through another policy's CURRENT value on the way to the
    final, collectively-unique arrangement -- exactly what
    Policy.priority's DEFERRABLE INITIALLY DEFERRED unique constraint
    exists to allow (see app/models/policy.py): the constraint is only
    checked once, at this function's single commit, against the fully
    -reassigned final state, not after each individual row update.
    `_check_priority_available()` (used by create/update above) is
    deliberately NOT called here -- transient collisions mid-sequence
    are expected and fine.
    """
    resolved_ids = []
    for raw_id in payload.ordered_ids:
        try:
            resolved_ids.append(uuid.UUID(raw_id))
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid policy id in ordered_ids.")

    policies = db.query(Policy).filter(Policy.id.in_(resolved_ids)).all()
    by_id = {p.id: p for p in policies}
    missing = [str(pid) for pid in resolved_ids if pid not in by_id]
    if missing:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Unknown policy id(s): {', '.join(missing)}")

    for index, pid in enumerate(resolved_ids):
        by_id[pid].priority = (index + 1) * 10

    db.commit()
    return {"status": "ok", "reordered": len(resolved_ids)}
