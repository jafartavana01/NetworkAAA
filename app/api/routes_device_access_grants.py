"""
app.api.routes_device_access_grants
======================================
CRUD for device-level access overrides -- see
app.models.device_access_grant's docstring for the full design
reasoning (group-only targeting, precedence via emission order not
priority numbers). Create-and-delete only, no update: changing a
grant's target is deleting one and creating another, which is simpler
to reason about than an in-place target change for a record this
small and this security-relevant.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.device_access_grant import DeviceAccessGrant
from ..models.device_group import DeviceGroup
from ..models.group import TacacsGroup
from ..schemas.device_access_grant import DeviceAccessGrantCreate, DeviceAccessGrantOut
from .deps import get_current_admin, verify_csrf

router = APIRouter(prefix="/api/device-access-grants", tags=["device-access-grants"])


def _to_out(db: Session, grant: DeviceAccessGrant) -> DeviceAccessGrantOut:
    device_name = None
    device_group_name = None
    if grant.device_id:
        device = db.query(NetworkDevice).filter(NetworkDevice.id == grant.device_id).first()
        device_name = device.name if device else None
    if grant.device_group_id:
        dg = db.query(DeviceGroup).filter(DeviceGroup.id == grant.device_group_id).first()
        device_group_name = dg.name if dg else None
    user_group = db.query(TacacsGroup).filter(TacacsGroup.id == grant.user_group_id).first()

    return DeviceAccessGrantOut(
        id=str(grant.id),
        device_id=str(grant.device_id) if grant.device_id else None,
        device_group_id=str(grant.device_group_id) if grant.device_group_id else None,
        user_group_id=str(grant.user_group_id),
        device_name=device_name,
        device_group_name=device_group_name,
        user_group_name=user_group.name if user_group else None,
        created_by=grant.created_by,
        created_at=grant.created_at.isoformat(),
    )


@router.get("", response_model=list[DeviceAccessGrantOut])
def list_grants(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    grants = db.query(DeviceAccessGrant).order_by(DeviceAccessGrant.created_at.desc()).all()
    return [_to_out(db, g) for g in grants]


@router.post("", response_model=DeviceAccessGrantOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_grant(
    payload: DeviceAccessGrantCreate,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    try:
        user_group_id = uuid.UUID(payload.user_group_id)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid user group id.")
    user_group = db.query(TacacsGroup).filter(TacacsGroup.id == user_group_id).first()
    if not user_group:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That user group doesn't exist.")

    device_id = None
    device_group_id = None
    if payload.device_id:
        try:
            device_id = uuid.UUID(payload.device_id)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid device id.")
        if not db.query(NetworkDevice).filter(NetworkDevice.id == device_id).first():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That device doesn't exist.")
    else:
        try:
            device_group_id = uuid.UUID(payload.device_group_id)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid device group id.")
        if not db.query(DeviceGroup).filter(DeviceGroup.id == device_group_id).first():
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That device group doesn't exist.")

    # Avoid an exact duplicate (same target + same user group) --
    # harmless if compiled twice, but a clear rejection is more useful
    # than a silent no-op duplicate row.
    existing = (
        db.query(DeviceAccessGrant)
        .filter(
            DeviceAccessGrant.user_group_id == user_group_id,
            DeviceAccessGrant.device_id == device_id,
            DeviceAccessGrant.device_group_id == device_group_id,
        )
        .first()
    )
    if existing:
        raise HTTPException(status.HTTP_409_CONFLICT, detail="This exact grant already exists.")

    grant = DeviceAccessGrant(
        device_id=device_id, device_group_id=device_group_id, user_group_id=user_group_id,
        created_by=admin.username,
    )
    db.add(grant)
    db.commit()
    db.refresh(grant)
    return _to_out(db, grant)


@router.delete("/{grant_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_grant(
    grant_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    try:
        parsed_id = uuid.UUID(grant_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Grant not found.")
    grant = db.query(DeviceAccessGrant).filter(DeviceAccessGrant.id == parsed_id).first()
    if not grant:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Grant not found.")
    db.delete(grant)
    db.commit()
