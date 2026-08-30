"""
app.api.routes_policy_conditions
===================================
Migration, read access, and full tree editing for the new
condition-tree model (pasted policy-condition-builder spec). Migration
is a deliberate, per-policy admin action -- never automatic -- per
that spec's backward-compatibility requirement: an existing policy
keeps using the legacy flat-field model, unchanged, until an admin
explicitly converts it (see app.services.condition_engine.
migrate_legacy_policy for the exact, lossless conversion and why it
can refuse for an unconditional policy).

Tree EDITING follows this project's established "replace the whole
thing on save" pattern (the same one CommandSet.rules and
Policy.command_set_ids already use) rather than granular per-node
CRUD endpoints: the GUI builds up the tree locally, then PUTs the
complete structure, which atomically replaces whatever was there
before. This is simpler to validate correctly (every node is checked
together, as a whole tree, not as a sequence of independently-valid-
but-collectively-inconsistent edits) and matches how every other
multi-item editor in this project already works.
"""
from __future__ import annotations

import ipaddress
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..models.group import TacacsGroup
from ..models.policy import Policy
from ..models.policy_condition import (
    DATABASE_BACKED_OBJECT_TYPES,
    VALID_OBJECT_TYPES,
    VALID_OPERATORS_BY_OBJECT_TYPE,
    PolicyCondition,
)
from ..models.policy_condition_group import VALID_LOGICAL_OPERATORS, PolicyConditionGroup
from ..models.user import TacacsUser
from ..services import condition_engine
from .deps import require_permission, verify_csrf

router = APIRouter(prefix="/api/policies", tags=["policy-conditions"])

_OBJECT_TYPE_TO_MODEL = {
    "user": TacacsUser,
    "user_group": TacacsGroup,
    "device": NetworkDevice,
    "device_group": DeviceGroup,
}


class ConditionInput(BaseModel):
    object_type: str
    operator: str
    # NOT min_length=1 -- for a database-backed object_type (user,
    # user_group, device, device_group), the backend never reads this
    # field at all (see _validate_and_build_condition below: it
    # resolves the real display name fresh from the referenced row),
    # so the GUI legitimately sends an empty string for those --
    # exactly what the Multi-select condition builder does for every
    # entry. A min_length constraint here was rejecting that ordinary,
    # correct payload with a raw Pydantic error ("String should have
    # at least 1 character") instead of the backend's own clearer
    # messages. Still validated as genuinely required, but only for
    # the one object_type where it's actually used -- source_ip's
    # manual value -- via the model_validator below.
    value: str = Field(default="", max_length=500)
    referenced_object_id: str | None = None

    @field_validator("object_type")
    @classmethod
    def validate_object_type(cls, v: str) -> str:
        if v not in VALID_OBJECT_TYPES:
            raise ValueError(f"'{v}' is not a supported condition object type.")
        return v

    @model_validator(mode="after")
    def validate_value_required_for_manual_types(self) -> "ConditionInput":
        if self.object_type not in DATABASE_BACKED_OBJECT_TYPES and not self.value.strip():
            raise ValueError(f"A {self.object_type} condition needs a value.")
        return self


class ConditionGroupInput(BaseModel):
    logical_operator: str
    conditions: list[ConditionInput] = Field(default_factory=list)
    child_groups: list["ConditionGroupInput"] = Field(default_factory=list)

    @field_validator("logical_operator")
    @classmethod
    def validate_logical_operator(cls, v: str) -> str:
        if v not in VALID_LOGICAL_OPERATORS:
            raise ValueError(f"'{v}' is not a supported logical operator (must be AND, OR, or NOT).")
        return v


ConditionGroupInput.model_rebuild()


def _get_policy_or_404(db: Session, policy_id: str) -> Policy:
    try:
        parsed_id = uuid.UUID(policy_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Policy not found.")
    policy = db.query(Policy).filter(Policy.id == parsed_id).first()
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Policy not found.")
    return policy


def _group_to_dict(db: Session, group: PolicyConditionGroup) -> dict:
    conditions = (
        db.query(PolicyCondition).filter(PolicyCondition.group_id == group.id).order_by(PolicyCondition.order.asc()).all()
    )
    child_groups = (
        db.query(PolicyConditionGroup)
        .filter(PolicyConditionGroup.parent_group_id == group.id)
        .order_by(PolicyConditionGroup.order.asc())
        .all()
    )
    return {
        "id": str(group.id),
        "logical_operator": group.logical_operator,
        "conditions": [
            {
                "id": str(c.id),
                "object_type": c.object_type,
                "operator": c.operator,
                "value_type": c.value_type,
                "value": c.value,
                "referenced_object_id": str(c.referenced_object_id) if c.referenced_object_id else None,
            }
            for c in conditions
        ],
        "child_groups": [_group_to_dict(db, g) for g in child_groups],
    }


def _validate_and_build_condition(db: Session, group_id: uuid.UUID, order: int, payload: ConditionInput) -> PolicyCondition:
    valid_operators = VALID_OPERATORS_BY_OBJECT_TYPE.get(payload.object_type, ())
    if payload.operator not in valid_operators:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"Operator '{payload.operator}' is not valid for object type '{payload.object_type}' "
                   f"(valid: {', '.join(valid_operators)}).",
        )

    if payload.object_type in DATABASE_BACKED_OBJECT_TYPES:
        if not payload.referenced_object_id:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"A {payload.object_type} condition needs a selected value.")
        try:
            ref_id = uuid.UUID(payload.referenced_object_id)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid referenced object id.")
        model = _OBJECT_TYPE_TO_MODEL[payload.object_type]
        row = db.query(model).filter(model.id == ref_id).first()
        if not row:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"That {payload.object_type} no longer exists.")
        display_name = getattr(row, "username", None) or getattr(row, "name", None) or str(ref_id)
        return PolicyCondition(
            group_id=group_id, object_type=payload.object_type, operator=payload.operator,
            value_type="database_id", value=display_name, referenced_object_id=ref_id, order=order,
        )

    # source_ip -- manual value
    if payload.operator in ("is_in_cidr", "is_not_in_cidr"):
        try:
            ipaddress.ip_network(payload.value, strict=False)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"'{payload.value}' is not a valid IP network/CIDR.")
    elif payload.operator in ("equal", "not_equal"):
        try:
            ipaddress.ip_address(payload.value)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"'{payload.value}' is not a valid IP address.")

    return PolicyCondition(
        group_id=group_id, object_type=payload.object_type, operator=payload.operator,
        value_type="manual", value=payload.value, referenced_object_id=None, order=order,
    )


def _build_tree(db: Session, policy_id: uuid.UUID, parent_group_id: uuid.UUID | None, order: int, payload: ConditionGroupInput) -> PolicyConditionGroup:
    if not payload.conditions and not payload.child_groups:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Every condition group needs at least one condition or nested group.")

    group = PolicyConditionGroup(
        policy_id=policy_id, parent_group_id=parent_group_id, logical_operator=payload.logical_operator, order=order,
    )
    db.add(group)
    db.flush()  # need group.id for children

    for i, cond_payload in enumerate(payload.conditions):
        db.add(_validate_and_build_condition(db, group.id, i, cond_payload))
    for i, subgroup_payload in enumerate(payload.child_groups):
        _build_tree(db, policy_id, group.id, i, subgroup_payload)

    return group


@router.get("/{policy_id}/condition-tree")
def get_condition_tree(
    policy_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:view")),
):
    """Returns the policy's condition tree if it has one (has_migrated
    = true), or its legacy flat-field summary otherwise -- so the
    caller always gets a complete, honest picture of which evaluation
    path this policy currently uses, never a silent gap."""
    policy = _get_policy_or_404(db, policy_id)

    if condition_engine.has_condition_tree(db, policy):
        root = condition_engine.get_root_group(db, policy)
        return {"has_migrated": True, "tree": _group_to_dict(db, root)}

    return {
        "has_migrated": False,
        "legacy_conditions": {
            "condition_group_id": str(policy.condition_group_id) if policy.condition_group_id else None,
            "condition_device_id": str(policy.condition_device_id) if policy.condition_device_id else None,
            "condition_device_group_id": str(policy.condition_device_group_id) if policy.condition_device_group_id else None,
        },
    }


@router.put("/{policy_id}/condition-tree", dependencies=[Depends(verify_csrf)])
def replace_condition_tree(
    policy_id: str,
    payload: ConditionGroupInput,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:write")),
):
    """
    Atomically replaces this policy's entire condition tree with
    `payload` -- creating one for the first time (a brand-new policy,
    or one never migrated from the legacy model) works the same way as
    replacing an existing tree. Every node is validated as part of one
    whole-tree operation: an object_type/operator mismatch, a
    dangling database reference, or a malformed CIDR/IP anywhere in
    the submitted tree rejects the ENTIRE save with a clear 400 --
    never a partially-applied tree.
    """
    policy = _get_policy_or_404(db, policy_id)

    # Delete any existing tree first -- CASCADE on PolicyConditionGroup's
    # own FK handles subgroups and their conditions automatically, but
    # deleting only the ROOT row and relying on cascade requires the
    # root to be findable first.
    existing_root = condition_engine.get_root_group(db, policy)
    if existing_root is not None:
        db.delete(existing_root)
        db.flush()

    root = _build_tree(db, policy.id, None, 0, payload)
    db.commit()
    return {"has_migrated": True, "tree": _group_to_dict(db, root)}


@router.post("/{policy_id}/migrate-conditions", dependencies=[Depends(verify_csrf)])
def migrate_conditions(
    policy_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:write")),
):
    """Explicitly converts this policy's legacy conditions into an
    equivalent condition tree -- lossless, and refused with a clear
    400 rather than attempted incorrectly for the cases
    migrate_legacy_policy() itself refuses (already migrated, or no
    legacy conditions to convert -- see that function's docstring)."""
    policy = _get_policy_or_404(db, policy_id)
    try:
        root = condition_engine.migrate_legacy_policy(db, policy)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
    db.commit()
    return {"has_migrated": True, "tree": _group_to_dict(db, root)}
