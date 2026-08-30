"""
app.api.routes_monitoring
============================
See app.models.monitoring_settings and app.services.monitoring for
the full design reasoning. `devices:write` gates everything here --
enabling monitoring changes the generated config (a real, if
carefully-scoped, security-relevant change), and quick-adding a
device is exactly the same privileged action as adding one normally.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..models.monitoring_settings import MonitoringSettings
from ..schemas.monitoring import (
    MonitoringSettingsOut,
    MonitoringSettingsUpdate,
    QuickAddDeviceRequest,
    UnrecognizedConnectionOut,
)
from ..services import monitoring
from .deps import require_permission, verify_csrf

router = APIRouter(prefix="/api/monitoring", tags=["monitoring"])

MONITOR_GROUP_NAME = "monitor"


def ensure_monitor_group_seeded(db: Session) -> None:
    """Seeds the prebuilt "monitor" DeviceGroup on first boot -- same
    pattern as app.api.routes_command_categories.ensure_seeded. A
    no-op once it exists, so an admin renaming or deleting it is never
    silently undone."""
    if db.query(DeviceGroup).filter(DeviceGroup.name == MONITOR_GROUP_NAME).first():
        return
    db.add(DeviceGroup(
        name=MONITOR_GROUP_NAME,
        description="Devices discovered and added via Monitoring mode.",
    ))
    db.commit()


def _get_or_create_settings(db: Session) -> MonitoringSettings:
    settings = db.query(MonitoringSettings).first()
    if settings is None:
        settings = MonitoringSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@router.get("/settings", response_model=MonitoringSettingsOut)
def get_settings(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:view")),
):
    return _get_or_create_settings(db)


@router.put("/settings", response_model=MonitoringSettingsOut, dependencies=[Depends(verify_csrf)])
def update_settings(
    payload: MonitoringSettingsUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    settings = _get_or_create_settings(db)
    settings.enabled = payload.enabled
    db.commit()
    db.refresh(settings)
    return settings


@router.get("/unrecognized", response_model=list[UnrecognizedConnectionOut])
def list_unrecognized(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:view")),
):
    return monitoring.find_unrecognized_connections(db)


@router.post("/quick-add", dependencies=[Depends(verify_csrf)])
def quick_add_device(
    payload: QuickAddDeviceRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    """Creates the device (exactly like the normal Add Device flow)
    and assigns it to the seeded "monitor" DeviceGroup, per the
    original request. The admin still supplies a REAL shared secret
    here -- the catch-all's placeholder key only got the connection
    attempt logged, it was never a working credential for this or any
    device (see app.services.config_compiler's monitoring section)."""
    if db.query(NetworkDevice).filter(NetworkDevice.ip_address == payload.ip_address).first():
        raise HTTPException(status.HTTP_409_CONFLICT, detail="A device with this IP address already exists.")
    if db.query(NetworkDevice).filter(NetworkDevice.name == payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A device named '{payload.name}' already exists.")

    ensure_monitor_group_seeded(db)
    monitor_group = db.query(DeviceGroup).filter(DeviceGroup.name == MONITOR_GROUP_NAME).first()

    device = NetworkDevice(
        name=payload.name,
        ip_address=payload.ip_address,
        shared_secret_encrypted=security.encrypt_secret(payload.shared_secret),
        device_group_id=monitor_group.id if monitor_group else None,
        enabled=True,
    )
    db.add(device)
    db.commit()
    db.refresh(device)
    return {"id": str(device.id), "name": device.name}
