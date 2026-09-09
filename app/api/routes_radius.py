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

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.radius_settings import RadiusSettings
from ..schemas.radius import RadiusSettingsOut, RadiusSettingsUpdate
from ..services import radius_dictionary
from .deps import get_current_admin, get_current_superadmin, verify_csrf

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


# ------------------------------------------------------- attributes

class RadiusAttributeOut(BaseModel):
    name: str
    code: int
    value_type: str
    vendor: str | None
    vendor_id: int | None
    qualified_name: str
    #: Enumerated values when the dictionary defines them, so the GUI
    #: can offer a dropdown instead of a free-text box.
    values: dict


class RadiusAttributesOut(BaseModel):
    available: bool
    source_path: str | None
    note: str
    attributes: list[RadiusAttributeOut]
    vendors: list[str]


@router.get("/attributes", response_model=RadiusAttributesOut)
def list_radius_attributes(
    _admin: AdminUser = Depends(get_current_admin),
):
    """
    The RADIUS attribute dictionary tac_plus-ng itself loads.

    Read from the shipped `radius-dict.cfg` rather than a list
    maintained here, so what an operator can pick is exactly what the
    daemon accepts. When the file is missing the response is honestly
    empty with an explanatory note -- never an invented list.

    Read-only: the dictionary belongs to the daemon distribution, and
    editing it from the GUI would put the platform's idea of valid
    attributes out of step with the daemon's on the next upgrade.
    """
    result = radius_dictionary.load_dictionary()
    return RadiusAttributesOut(
        available=result.available, source_path=result.source_path, note=result.note,
        attributes=[
            RadiusAttributeOut(
                name=a.name, code=a.code, value_type=a.value_type,
                vendor=a.vendor, vendor_id=a.vendor_id,
                qualified_name=a.qualified_name, values=a.values,
            )
            for a in result.attributes
        ],
        vendors=sorted({a.vendor for a in result.attributes if a.vendor}),
    )


# ---------------------------------------------------------- clients

class RadiusClientOut(BaseModel):
    """A RADIUS client is an EXISTING device with RADIUS enabled -- not
    a separate inventory. `has_secret` is a presence flag; the secret
    itself is never returned."""
    device_id: str
    device_name: str
    ip_address: str
    vendor: str | None
    device_group_name: str | None
    enabled: bool
    radius_enabled: bool
    has_secret: bool


@router.get("/clients", response_model=list[RadiusClientOut])
def list_radius_clients(
    include_all: bool = False,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """
    Devices acting as RADIUS clients.

    `include_all=true` returns every device, so the GUI can offer
    existing inventory to enable rather than making an admin retype a
    device that already exists. This is why there is no separate RADIUS
    client table: a NAS is a device this platform already knows.
    """
    from ..models.device_group import DeviceGroup

    q = db.query(NetworkDevice)
    if not include_all:
        q = q.filter(NetworkDevice.radius_enabled.is_(True))
    devices = q.order_by(NetworkDevice.name.asc()).all()
    groups = {g.id: g.name for g in db.query(DeviceGroup).all()}

    return [
        RadiusClientOut(
            device_id=str(d.id), device_name=d.name, ip_address=d.ip_address,
            vendor=getattr(d, "vendor", None),
            device_group_name=groups.get(d.device_group_id),
            enabled=bool(d.enabled), radius_enabled=bool(d.radius_enabled),
            has_secret=bool(d.radius_secret_encrypted),
        )
        for d in devices
    ]


# ------------------------------------------------------------ probe

class RadiusProbeRequest(BaseModel):
    """
    Probe a device's own RADIUS client entry. The secret is NOT taken
    from the request: it is read from the stored, encrypted device
    record, so a caller can never use this endpoint to test a secret
    they do not already have, or to learn one by trial.
    """
    device_id: str
    username: str = Field(default="netopsguard-probe", max_length=64)
    password: str = Field(default="probe-only-not-a-real-credential", max_length=128)


class RadiusProbeOut(BaseModel):
    reachable: bool
    code_name: str
    round_trip_ms: int
    detail: str
    guidance: str
    target: str


@router.post("/probe", response_model=RadiusProbeOut, dependencies=[Depends(verify_csrf)])
def probe_radius(
    payload: RadiusProbeRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    """
    Sends a real Access-Request to this platform's RADIUS listener,
    using a device's stored shared secret, and reports whether the
    daemon answers.

    This exists because a NAS cannot tell these cases apart -- all of
    them look like "requests sent, zero responses":

      * the listener is not running
      * the device is not defined as a RADIUS client
      * the shared secret does not match
      * a firewall is dropping the reply

    The probe controls the secret and the source, so a timeout here
    means something quite different from a timeout at the NAS.

    Superadmin-only: it reads a stored device secret to build the
    packet, even though it never returns it.
    """
    import uuid as _uuid

    from ..services import radius_probe

    try:
        device_uuid = _uuid.UUID(payload.device_id)
    except (ValueError, AttributeError):
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Malformed device id.")

    device = db.query(NetworkDevice).filter(NetworkDevice.id == device_uuid).first()
    if not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")
    if not device.radius_enabled or not device.radius_secret_encrypted:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="That device has no RADIUS secret configured, so there is nothing to test with.",
        )

    settings = _get_or_create(db)
    if not settings.enabled:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="RADIUS is disabled, so no listener is running to probe.",
        )

    secret = security.decrypt_secret(device.radius_secret_encrypted)

    # Probes the LOCAL listener: the question is whether this platform's
    # RADIUS server answers, not whether the network path from the NAS
    # works. Those are different problems and conflating them is what
    # makes the NAS counter so hard to interpret.
    result = radius_probe.probe(
        "127.0.0.1", settings.auth_port, secret, payload.username, payload.password,
    )

    return RadiusProbeOut(
        reachable=result.reachable, code_name=result.code_name,
        round_trip_ms=result.round_trip_ms, detail=result.detail,
        guidance=result.guidance, target=f"127.0.0.1:{settings.auth_port}/udp",
    )
