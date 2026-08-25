"""
app.api.routes_devices
========================
CRUD for network devices (spec section 18). Every mutation requires
CSRF verification; every route requires an authenticated admin. Shared
secrets are write-only: DeviceOut never includes the plaintext or
ciphertext, only `has_secret`. Changing DB state here does NOT touch
the live tac_plus-ng configuration by itself -- that only happens
through the explicit compile/diff/apply flow in routes_config.py
(spec section 14's "administrator confirms" step is a separate action,
not an implicit side effect of saving a device).

Phase 4 adds `device_group_id` -- validated against DeviceGroup
explicitly (rather than letting a bad ID surface as an opaque FK
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
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..schemas.device import DeviceCreate, DeviceOut, DeviceUpdate
from .deps import get_current_admin, verify_csrf

router = APIRouter(prefix="/api/devices", tags=["devices"])


def _parse_group_id(group_id: str | None) -> uuid.UUID | None:
    if not group_id:
        return None
    try:
        return uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid device group id.")


def _resolve_group(db: Session, group_id: str | None) -> DeviceGroup | None:
    parsed = _parse_group_id(group_id)
    if parsed is None:
        return None
    group = db.query(DeviceGroup).filter(DeviceGroup.id == parsed).first()
    if not group:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That device group doesn't exist.")
    return group


def _group_names(db: Session) -> dict[uuid.UUID, str]:
    return {g.id: g.name for g in db.query(DeviceGroup).all()}


def _to_out(device: NetworkDevice, group_name: str | None = None) -> DeviceOut:
    return DeviceOut(
        id=str(device.id),
        name=device.name,
        ip_address=device.ip_address,
        ipv6_address=device.ipv6_address,
        vendor=device.vendor,
        platform=device.platform,
        description=device.description,
        device_group_id=str(device.device_group_id) if device.device_group_id else None,
        device_group_name=group_name,
        enabled=device.enabled,
        has_secret=bool(device.shared_secret_encrypted),
    )


@router.get("", response_model=list[DeviceOut])
def list_devices(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    devices = db.query(NetworkDevice).order_by(NetworkDevice.name.asc()).all()
    names = _group_names(db)
    return [_to_out(d, names.get(d.device_group_id)) for d in devices]


@router.post("", response_model=DeviceOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_device(
    payload: DeviceCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    group = _resolve_group(db, payload.device_group_id)
    device = NetworkDevice(
        name=payload.name,
        ip_address=payload.ip_address,
        ipv6_address=payload.ipv6_address,
        vendor=payload.vendor,
        platform=payload.platform,
        description=payload.description,
        device_group_id=group.id if group else None,
        enabled=payload.enabled,
        shared_secret_encrypted=security.encrypt_secret(payload.shared_secret),
    )
    db.add(device)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A device named '{payload.name}' already exists.")
    db.refresh(device)
    return _to_out(device, group.name if group else None)


def _get_device_or_404(db: Session, device_id: str) -> NetworkDevice:
    try:
        parsed_id = uuid.UUID(device_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")
    device = db.query(NetworkDevice).filter(NetworkDevice.id == parsed_id).first()
    if not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")
    return device


@router.get("/{device_id}", response_model=DeviceOut)
def get_device(
    device_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    device = _get_device_or_404(db, device_id)
    names = _group_names(db)
    return _to_out(device, names.get(device.device_group_id))


@router.put("/{device_id}", response_model=DeviceOut, dependencies=[Depends(verify_csrf)])
def update_device(
    device_id: str,
    payload: DeviceUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    device = _get_device_or_404(db, device_id)
    group = _resolve_group(db, payload.device_group_id)

    device.name = payload.name
    device.ip_address = payload.ip_address
    device.ipv6_address = payload.ipv6_address
    device.vendor = payload.vendor
    device.platform = payload.platform
    device.description = payload.description
    device.device_group_id = group.id if group else None
    device.enabled = payload.enabled
    if payload.shared_secret:
        device.shared_secret_encrypted = security.encrypt_secret(payload.shared_secret)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A device named '{payload.name}' already exists.")
    db.refresh(device)
    return _to_out(device, group.name if group else None)


@router.delete("/{device_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_device(
    device_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    device = _get_device_or_404(db, device_id)
    db.delete(device)
    db.commit()
