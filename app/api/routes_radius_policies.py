"""
app.api.routes_radius_policies
=================================
CRUD for RADIUS authorization policies.

A RADIUS policy answers two questions and no more: does this request
get an Access-Accept, and which attributes come back. It deliberately
has no per-command rules -- RADIUS has no per-command authorization,
and offering it would let an operator configure something the protocol
cannot enforce.

Gated on the existing TACACS+ policy permissions rather than inventing
new ones: deciding who may authenticate where is the same class of
decision whichever protocol carries it.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..models.group import TacacsGroup
from ..models.radius_policy import RadiusPolicy, RadiusPolicyAttribute
from ..services import radius_dictionary
from .deps import require_permission, verify_csrf

router = APIRouter(prefix="/api/radius/policies", tags=["radius-policies"])


class RadiusAttributeIn(BaseModel):
    attribute: str = Field(min_length=1, max_length=128)
    value: str = Field(min_length=1, max_length=512)


class RadiusPolicyIn(BaseModel):
    name: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9][A-Za-z0-9_\-]*$")
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool = True
    priority: int = Field(default=100, ge=1, le=10000)
    condition_group_id: str | None = None
    condition_device_id: str | None = None
    condition_device_group_id: str | None = None
    condition_service_type: str | None = Field(default=None, max_length=64)
    action: str = Field(default="permit", pattern="^(permit|deny)$")
    attributes: list[RadiusAttributeIn] = Field(default_factory=list)


class RadiusAttributeOut(BaseModel):
    attribute: str
    value: str


class RadiusPolicyOut(BaseModel):
    id: str
    name: str
    description: str | None
    enabled: bool
    priority: int
    condition_group_id: str | None
    condition_group_name: str | None
    condition_device_id: str | None
    condition_device_name: str | None
    condition_device_group_id: str | None
    condition_device_group_name: str | None
    condition_service_type: str | None
    action: str
    attributes: list[RadiusAttributeOut]
    created_by: str | None
    created_at: datetime
    updated_at: datetime
    #: The exact profile text this policy will contribute to the
    #: generated configuration. Shown so an operator can review what
    #: will actually be sent, rather than trusting the form.
    generated_preview: str


def _name_maps(db: Session):
    return (
        {g.id: g.name for g in db.query(TacacsGroup).all()},
        {d.id: d.name for d in db.query(NetworkDevice).all()},
        {g.id: g.name for g in db.query(DeviceGroup).all()},
    )


def _preview(policy: RadiusPolicy, attributes: list) -> str:
    """Mirrors config_compiler._radius_policy_blocks for a single
    policy. Kept deliberately small and read-only -- the compiler
    remains the single source of truth for what is actually written."""
    lines = [f"profile rad_{policy.name} {{", "    script {", "        if (aaa.protocol == radius) {"]
    indent = "            "
    if policy.condition_service_type:
        lines.append(f"            if (radius[Service-Type] == {policy.condition_service_type}) {{")
        indent = "                "
    for a in attributes:
        escaped = a.value.replace("\\", "\\\\").replace('"', '\\"')
        lines.append(f'{indent}set radius[{a.attribute}] = "{escaped}"')
    lines.append(f"{indent}{'permit' if policy.action == 'permit' else 'deny'}")
    if policy.condition_service_type:
        lines.append("            }")
    lines.extend(["        }", "    }", "}"])
    return "\n".join(lines)


def _out(db: Session, policy: RadiusPolicy) -> RadiusPolicyOut:
    groups, devices, device_groups = _name_maps(db)
    attributes = (
        db.query(RadiusPolicyAttribute)
        .filter(RadiusPolicyAttribute.policy_id == policy.id)
        .order_by(RadiusPolicyAttribute.sort_order.asc())
        .all()
    )
    return RadiusPolicyOut(
        id=str(policy.id), name=policy.name, description=policy.description,
        enabled=policy.enabled, priority=policy.priority,
        condition_group_id=str(policy.condition_group_id) if policy.condition_group_id else None,
        condition_group_name=groups.get(policy.condition_group_id),
        condition_device_id=str(policy.condition_device_id) if policy.condition_device_id else None,
        condition_device_name=devices.get(policy.condition_device_id),
        condition_device_group_id=(
            str(policy.condition_device_group_id) if policy.condition_device_group_id else None
        ),
        condition_device_group_name=device_groups.get(policy.condition_device_group_id),
        condition_service_type=policy.condition_service_type,
        action=policy.action,
        attributes=[RadiusAttributeOut(attribute=a.attribute, value=a.value) for a in attributes],
        created_by=policy.created_by, created_at=policy.created_at, updated_at=policy.updated_at,
        generated_preview=_preview(policy, attributes),
    )


def _parse_uuid(value: str | None, field: str):
    if not value:
        return None
    import uuid as _uuid
    try:
        return _uuid.UUID(value)
    except (ValueError, AttributeError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Malformed {field}.")


def _validate_attributes(payload: RadiusPolicyIn) -> None:
    """
    Rejects an attribute the daemon's own dictionary does not define.

    Without this, a typo is only discovered when the generated
    configuration is applied -- at which point a bad directive can stop
    the daemon parsing the whole file, taking TACACS+ down with it.
    Checked against the shipped dictionary, and SKIPPED entirely when
    that dictionary cannot be read, because refusing every attribute
    would be worse than accepting an unverified one.
    """
    if not payload.attributes:
        return
    loaded = radius_dictionary.load_dictionary()
    if not loaded.available:
        return
    known = {a.qualified_name.lower() for a in loaded.attributes}
    unknown = [a.attribute for a in payload.attributes if a.attribute.lower() not in known]
    if unknown:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=(
                "These attributes are not in the RADIUS dictionary tac_plus-ng loads: "
                + ", ".join(unknown)
                + ". Use the exact name shown on the Attributes page, including the vendor "
                "prefix (for example MikroTik:MikroTik-Group)."
            ),
        )


def _apply(db: Session, policy: RadiusPolicy, payload: RadiusPolicyIn) -> None:
    policy.name = payload.name
    policy.description = payload.description
    policy.enabled = payload.enabled
    policy.priority = payload.priority
    policy.condition_group_id = _parse_uuid(payload.condition_group_id, "group id")
    policy.condition_device_id = _parse_uuid(payload.condition_device_id, "device id")
    policy.condition_device_group_id = _parse_uuid(payload.condition_device_group_id, "device group id")
    policy.condition_service_type = (payload.condition_service_type or "").strip() or None
    policy.action = payload.action


@router.get("", response_model=list[RadiusPolicyOut])
def list_policies(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:view")),
):
    rows = (
        db.query(RadiusPolicy)
        .order_by(RadiusPolicy.priority.asc(), RadiusPolicy.created_at.asc())
        .all()
    )
    return [_out(db, p) for p in rows]


@router.post("", response_model=RadiusPolicyOut, dependencies=[Depends(verify_csrf)])
def create_policy(
    payload: RadiusPolicyIn,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("policies:write")),
):
    if db.query(RadiusPolicy).filter(RadiusPolicy.name == payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A RADIUS policy with that name already exists.")
    _validate_attributes(payload)

    policy = RadiusPolicy(created_by=admin.username)
    _apply(db, policy, payload)
    db.add(policy)
    db.flush()
    for index, attribute in enumerate(payload.attributes):
        db.add(RadiusPolicyAttribute(
            policy_id=policy.id, attribute=attribute.attribute.strip(),
            value=attribute.value, sort_order=index,
        ))
    db.commit()
    db.refresh(policy)
    return _out(db, policy)


@router.put("/{policy_id}", response_model=RadiusPolicyOut, dependencies=[Depends(verify_csrf)])
def update_policy(
    policy_id: str,
    payload: RadiusPolicyIn,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:write")),
):
    policy = db.query(RadiusPolicy).filter(RadiusPolicy.id == _parse_uuid(policy_id, "policy id")).first()
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="RADIUS policy not found.")
    clash = db.query(RadiusPolicy).filter(
        RadiusPolicy.name == payload.name, RadiusPolicy.id != policy.id
    ).first()
    if clash:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A RADIUS policy with that name already exists.")
    _validate_attributes(payload)

    _apply(db, policy, payload)
    # Attributes are replaced wholesale rather than merged: the form
    # submits the complete intended list, so diffing would risk leaving
    # an attribute behind that the operator deleted.
    db.query(RadiusPolicyAttribute).filter(RadiusPolicyAttribute.policy_id == policy.id).delete()
    for index, attribute in enumerate(payload.attributes):
        db.add(RadiusPolicyAttribute(
            policy_id=policy.id, attribute=attribute.attribute.strip(),
            value=attribute.value, sort_order=index,
        ))
    db.commit()
    db.refresh(policy)
    return _out(db, policy)


@router.delete("/{policy_id}", status_code=status.HTTP_204_NO_CONTENT,
               dependencies=[Depends(verify_csrf)])
def delete_policy(
    policy_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("policies:write")),
):
    policy = db.query(RadiusPolicy).filter(RadiusPolicy.id == _parse_uuid(policy_id, "policy id")).first()
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="RADIUS policy not found.")
    db.delete(policy)
    db.commit()
    from fastapi import Response
    return Response(status_code=status.HTTP_204_NO_CONTENT)
