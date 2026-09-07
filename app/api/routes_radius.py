"""
app.api.routes_radius
========================
Platform-level RADIUS listener settings.

Superadmin-gated, matching how this project already treats network and
TLS settings: enabling RADIUS opens listeners on the daemon that the
operator did not previously have, which is a platform-level change
rather than day-to-day device administration.

Changes here do NOT take effect until the configuration is compiled
and applied through the existing Apply workflow -- the same as every
other change this platform makes to the daemon's configuration. The
response says so rather than implying the ports are already live.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.radius_settings import RadiusSettings
from ..schemas.radius import RadiusSettingsOut, RadiusSettingsUpdate
from .deps import get_current_superadmin, verify_csrf

router = APIRouter(prefix="/api/radius", tags=["radius"])


def _get_or_create(db: Session) -> RadiusSettings:
    settings = db.query(RadiusSettings).first()
    if settings is None:
        settings = RadiusSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def _count_radius_devices(db: Session) -> int:
    return db.query(func.count(NetworkDevice.id)).filter(NetworkDevice.radius_enabled.is_(True)).scalar() or 0


def _out(db: Session, s: RadiusSettings) -> RadiusSettingsOut:
    return RadiusSettingsOut(
        enabled=s.enabled, auth_port=s.auth_port, acct_port=s.acct_port,
        protocol=s.protocol, include_dictionaries=s.include_dictionaries,
        updated_by=s.updated_by, updated_at=s.updated_at,
        devices_with_radius=_count_radius_devices(db),
    )


@router.get("/settings", response_model=RadiusSettingsOut)
def get_radius_settings(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    return _out(db, _get_or_create(db))


@router.put("/settings", response_model=RadiusSettingsOut, dependencies=[Depends(verify_csrf)])
def update_radius_settings(
    payload: RadiusSettingsUpdate,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_superadmin),
):
    s = _get_or_create(db)
    s.enabled = payload.enabled
    s.auth_port = payload.auth_port
    s.acct_port = payload.acct_port
    s.include_dictionaries = payload.include_dictionaries
    # `protocol` is intentionally not settable: only UDP syntax was
    # confirmed. See app.schemas.radius for the reasoning.
    s.updated_by = admin.username
    db.commit()
    db.refresh(s)
    return _out(db, s)
