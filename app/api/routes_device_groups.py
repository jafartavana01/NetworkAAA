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
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..schemas.device_group import DeviceGroupCreate, DeviceGroupOut, DeviceGroupUpdate
from .deps import get_current_admin, verify_csrf

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
    _admin: AdminUser = Depends(get_current_admin),
):
    groups = db.query(DeviceGroup).order_by(DeviceGroup.name.asc()).all()
    counts = _member_counts(db)
    return [_to_out(g, counts.get(g.id, 0)) for g in groups]


@router.post("", response_model=DeviceGroupOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_device_group(
    payload: DeviceGroupCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
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
    _admin: AdminUser = Depends(get_current_admin),
):
    group = _get_group_or_404(db, group_id)
    count = db.query(func.count(NetworkDevice.id)).filter(NetworkDevice.device_group_id == group.id).scalar()
    return _to_out(group, count or 0)


@router.put("/{group_id}", response_model=DeviceGroupOut, dependencies=[Depends(verify_csrf)])
def update_device_group(
    group_id: str,
    payload: DeviceGroupUpdate,
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
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A device group named '{payload.name}' already exists.")
    db.refresh(group)
    count = db.query(func.count(NetworkDevice.id)).filter(NetworkDevice.device_group_id == group.id).scalar()
    return _to_out(group, count or 0)


@router.delete("/{group_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_device_group(
    group_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    group = _get_group_or_404(db, group_id)
    db.delete(group)
    db.commit()
