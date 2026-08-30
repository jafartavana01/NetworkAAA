"""
app.api.routes_device_groups
==============================
CRUD for device groups (spec section 19). Deleting a group does NOT
delete its member devices -- FK is ON DELETE SET NULL
(app.models.device.NetworkDevice.device_group_id).
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
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..schemas.device_group import DeviceGroupCreate, DeviceGroupOut, DeviceGroupUpdate
from .deps import require_permission, verify_csrf

router = APIRouter(prefix="/api/device-groups", tags=["device-groups"])


def _member_counts(db: Session) -> dict[uuid.UUID, int]:
    rows = (
        db.query(NetworkDevice.device_group_id, func.count(NetworkDevice.id))
        .filter(NetworkDevice.device_group_id.isnot(None))
        .group_by(NetworkDevice.device_group_id)
        .all()
    )
    return {group_id: count for group_id, count in rows}


def _to_out(group: DeviceGroup, member_count: int = 0) -> DeviceGroupOut:
    return DeviceGroupOut(
        id=str(group.id),
        name=group.name,
        description=group.description,
        member_count=member_count,
    )


@router.get("", response_model=list[DeviceGroupOut])
def list_device_groups(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:view")),
):
    groups = db.query(DeviceGroup).order_by(DeviceGroup.name.asc()).all()
    counts = _member_counts(db)
    return [_to_out(g, counts.get(g.id, 0)) for g in groups]


@router.post("", response_model=DeviceGroupOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_device_group(
    payload: DeviceGroupCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    group = DeviceGroup(name=payload.name, description=payload.description)
    db.add(group)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A device group named '{payload.name}' already exists.")
    db.refresh(group)
    return _to_out(group)


def _get_group_or_404(db: Session, group_id: str) -> DeviceGroup:
    try:
        parsed_id = uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device group not found.")
    group = db.query(DeviceGroup).filter(DeviceGroup.id == parsed_id).first()
    if not group:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device group not found.")
    return group


@router.get("/{group_id}", response_model=DeviceGroupOut)
def get_device_group(
    group_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:view")),
):
    group = _get_group_or_404(db, group_id)
    count = db.query(func.count(NetworkDevice.id)).filter(NetworkDevice.device_group_id == group.id).scalar()
    return _to_out(group, count or 0)


@router.put("/{group_id}", response_model=DeviceGroupOut, dependencies=[Depends(verify_csrf)])
def update_device_group(
    group_id: str,
    payload: DeviceGroupUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    group = _get_group_or_404(db, group_id)
    group.name = payload.name
    group.description = payload.description
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A device group named '{payload.name}' already exists.")
    db.refresh(group)
    count = db.query(func.count(NetworkDevice.id)).filter(NetworkDevice.device_group_id == group.id).scalar()
    return _to_out(group, count or 0)


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_device_group(
    group_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    group = _get_group_or_404(db, group_id)
    db.delete(group)
    db.commit()


@router.get("/{group_id}/members")
def list_members(
    group_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:view")),
):
    """The device-group counterpart to TacacsGroup's member management
    (app.api.routes_tacacs_groups) -- same gap, same fix: previously
    the only way to see or change a device group's membership was to
    edit each device's own record individually."""
    group = _get_group_or_404(db, group_id)
    members = db.query(NetworkDevice).filter(NetworkDevice.device_group_id == group.id).order_by(NetworkDevice.name.asc()).all()
    return [{"id": str(d.id), "name": d.name, "ip_address": d.ip_address, "enabled": d.enabled} for d in members]


class AddDeviceMemberRequest(BaseModel):
    device_id: str


@router.post("/{group_id}/members", dependencies=[Depends(verify_csrf)])
def add_member(
    group_id: str,
    payload: AddDeviceMemberRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    """A device has exactly one device_group_id -- adding a device
    already in a DIFFERENT group here reassigns it, the same
    single-membership behavior TacacsGroup's version already has, for
    the same reason (NetworkDevice.device_group_id is a single FK)."""
    group = _get_group_or_404(db, group_id)
    try:
        device_id = uuid.UUID(payload.device_id)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid device id.")
    device = db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first()
    if not device:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That device doesn't exist.")

    reassigned_from = None
    if device.device_group_id and device.device_group_id != group.id:
        previous = db.query(DeviceGroup).filter(DeviceGroup.id == device.device_group_id).first()
        reassigned_from = previous.name if previous else None

    device.device_group_id = group.id
    db.commit()
    return {"status": "ok", "reassigned_from": reassigned_from}


@router.delete("/{group_id}/members/{device_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def remove_member(
    group_id: str,
    device_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    """Ungroups the device -- does not delete it, matching how
    deleting the whole group itself already behaves."""
    group = _get_group_or_404(db, group_id)
    try:
        parsed_device_id = uuid.UUID(device_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")
    device = db.query(NetworkDevice).filter(NetworkDevice.id == parsed_device_id, NetworkDevice.device_group_id == group.id).first()
    if not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="That device is not a member of this group.")
    device.device_group_id = None
    db.commit()
