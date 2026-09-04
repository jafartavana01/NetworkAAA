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

import ipaddress
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..schemas.device import (
    DeviceAaaApplyRequest,
    DeviceAaaApplyResult,
    DeviceAaaPreviewOut,
    DeviceAaaPreviewRequest,
    DeviceCreate,
    DeviceOut,
    DeviceUpdate,
)
from .deps import require_permission, verify_csrf


def _check_no_overlap(db: Session, ip_address: str, *, excluding_id: uuid.UUID | None = None) -> None:
    """
    Rejects a device whose network overlaps an already-configured
    device's network, in EITHER direction -- a new device falling
    inside an existing wider one (the requested example: an existing
    192.168.0.0/24 device blocks adding 192.168.0.32), or a new wider
    device that would swallow an existing narrower one. Two host
    blocks that could both match the same address is exactly the same
    precedence ambiguity flagged for monitoring mode's catch-all
    block (app.models.monitoring_settings) -- not independently
    confirmed which one tac_plus-ng would actually honor, so it's
    refused outright here rather than left to chance.
    """
    try:
        new_network = ipaddress.ip_network(ip_address, strict=False)
    except ValueError:
        return  # schema-level validation already rejects this; nothing to check here
    query = db.query(NetworkDevice)
    if excluding_id is not None:
        query = query.filter(NetworkDevice.id != excluding_id)
    for existing in query.all():
        try:
            existing_network = ipaddress.ip_network(existing.ip_address, strict=False)
        except ValueError:
            continue
        if new_network.version != existing_network.version:
            continue
        if new_network.overlaps(existing_network):
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail=f"'{ip_address}' overlaps the existing device '{existing.name}' ({existing.ip_address}).",
            )

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


def _secret_suffix(device: NetworkDevice) -> str | None:
    """
    The last 4 characters of the real secret, and nothing else --
    the same "confirmatory, not exposing" pattern widely used for API
    keys (AWS access keys, Stripe keys, etc.): enough for an admin to
    visually confirm a secret is genuinely set and spot-check it
    against what's actually configured on the device, without this
    platform ever displaying the secret in full. Decryption failures
    (a corrupted or otherwise unreadable ciphertext) return None
    rather than raising, so one bad row can't break the whole device
    list.
    """
    if not device.shared_secret_encrypted:
        return None
    try:
        plaintext = security.decrypt_secret(device.shared_secret_encrypted)
    except Exception:
        return None
    return plaintext[-4:] if len(plaintext) >= 4 else plaintext


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
        secret_suffix=_secret_suffix(device),
    )


@router.get("", response_model=list[DeviceOut])
def list_devices(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:view")),
):
    devices = db.query(NetworkDevice).order_by(NetworkDevice.name.asc()).all()
    names = _group_names(db)
    return [_to_out(d, names.get(d.device_group_id)) for d in devices]


@router.post("", response_model=DeviceOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_device(
    payload: DeviceCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    group = _resolve_group(db, payload.device_group_id)
    _check_no_overlap(db, payload.ip_address)
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
    _admin: AdminUser = Depends(require_permission("devices:view")),
):
    device = _get_device_or_404(db, device_id)
    names = _group_names(db)
    return _to_out(device, names.get(device.device_group_id))


@router.put("/{device_id}", response_model=DeviceOut, dependencies=[Depends(verify_csrf)])
def update_device(
    device_id: str,
    payload: DeviceUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    device = _get_device_or_404(db, device_id)
    group = _resolve_group(db, payload.device_group_id)
    _check_no_overlap(db, payload.ip_address, excluding_id=device.id)

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
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    device = _get_device_or_404(db, device_id)
    db.delete(device)
    db.commit()


# ---------- Apply AAA config to an already-existing device ----------
#
# Distinct from Network Scan & Provision's own apply flow
# (app.api.routes_network_scan): that flow CREATES a new device with a
# freshly-generated secret. This one pushes to a device that's
# ALREADY in the platform, with an ALREADY-stored secret -- the whole
# point is to make the device match what this platform already has on
# file, not to establish a new credential. The real secret is never
# sent to or displayed in the browser: the preview and the editable-
# commands flow both work with a clearly-fake placeholder string
# instead, which the backend substitutes for the real, decrypted
# secret only at the moment of the actual SSH push.
_EXISTING_SECRET_PLACEHOLDER = "__EXISTING_SECRET_NOT_SHOWN__"


def _bare_ip(device: NetworkDevice) -> str:
    return device.ip_address.split("/")[0].strip()


def _get_aaa_template_for_device(db: Session) -> list[str] | None:
    """Same lookup as app.api.routes_network_scan._get_aaa_template --
    duplicated rather than cross-imported (a private-by-convention
    helper reused across two route modules), matching this project's
    existing precedent for small, self-contained helpers (see e.g. the
    regex-escaping logic duplicated between accounting.html and
    command_sets.html)."""
    from ..models.aaa_template_settings import AaaTemplateSettings
    settings = db.query(AaaTemplateSettings).first()
    return settings.commands if settings else None


@router.post("/{device_id}/aaa-preview", response_model=DeviceAaaPreviewOut)
def preview_device_aaa_commands(
    device_id: str,
    payload: DeviceAaaPreviewRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    """Commands as they'd actually be sent, EXCEPT the real secret is
    replaced with a clearly-fake placeholder -- never sent to the
    browser. Editing the commands in the GUI and submitting them back
    to /apply-aaa is expected to still contain this exact placeholder
    string; the backend substitutes the real secret back in at that
    point (see apply_aaa_to_device below)."""
    from ..services import ssh_provision
    device = _get_device_or_404(db, device_id)
    template = _get_aaa_template_for_device(db)
    commands = ssh_provision.build_cisco_ios_aaa_commands(
        platform_ip=payload.platform_ip, shared_secret=_EXISTING_SECRET_PLACEHOLDER, templates=template,
    )
    return DeviceAaaPreviewOut(commands=commands)


def _apply_aaa_to_device_background(
    session_id: str, *, host: str, ssh_username: str, ssh_password: str, commands: list[str],
    connect_timeout: int, command_timeout: int,
) -> None:
    """
    The SSH push itself, run as a background task -- everything that
    needs the request-scoped DB session (device lookup, secret
    decryption, extracting/updating a stored secret from an edited
    command list) already happened synchronously in
    apply_aaa_to_device before this is scheduled, so this function
    itself needs no database access at all, unlike
    app.api.routes_network_scan's own background-task helpers.
    """
    from ..services import ssh_provision, apply_progress
    try:
        result = ssh_provision.apply_aaa_config(
            host, ssh_username, ssh_password, commands=commands,
            connect_timeout=connect_timeout, command_timeout=command_timeout,
        )
        apply_progress.increment_completed(session_id)
        apply_progress.finish_session(session_id, [DeviceAaaApplyResult(
            success=result.success, message=result.message, command_log=result.command_log,
        ).model_dump()])
    except Exception as exc:
        apply_progress.append_log(session_id, f"Unexpected error: {exc}")
        apply_progress.finish_session(session_id, [])


@router.post("/{device_id}/apply-aaa", dependencies=[Depends(verify_csrf)])
def apply_aaa_to_device(
    device_id: str,
    payload: DeviceAaaApplyRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    """
    Pushes AAA configuration to an already-existing device over SSH,
    using its own already-stored secret -- keeping the device and
    this platform's record of it consistent, rather than establishing
    a new credential the way Network Scan & Provision's apply does for
    a brand-new device.

    If `commands` (an admin edit of the preview) still contains the
    placeholder from /aaa-preview, the real secret is substituted in.
    If the admin removed or changed that line entirely, the actual key
    in what they submitted is extracted (same
    ssh_provision.extract_shared_secret used by the scan/apply flow)
    and the DEVICE'S STORED SECRET IS UPDATED TO MATCH -- the same
    "the stored secret is derived from what's actually sent, so it can
    never drift out of sync with a manual edit" principle already
    established and tested for the scan flow, applied here too.

    Runs the actual SSH push as a background task, returning a session
    id immediately -- same live-progress/"Continue in background"
    reasoning as app.api.routes_network_scan's own apply endpoints, and
    polled via the SAME GET .../apply-progress/{session_id} endpoint
    (app.services.apply_progress is shared, not per-route). Everything
    that needs the database (device lookup, secret handling) happens
    HERE, synchronously, before the background task is scheduled --
    only the SSH push itself is deferred.
    """
    from ..services import ssh_provision
    device = _get_device_or_404(db, device_id)
    real_secret = security.decrypt_secret(device.shared_secret_encrypted)

    from ..models.aaa_template_settings import AaaTemplateSettings
    stored_settings = db.query(AaaTemplateSettings).first()
    # Per-apply override -> admin's stored default -> ssh_provision's
    # own built-in default, in that order. See DeviceAaaApplyRequest's
    # own docstring for why this exists.
    connect_timeout = (
        payload.connect_timeout_seconds
        or (stored_settings.connect_timeout_seconds if stored_settings else None)
        or ssh_provision.DEFAULT_CONNECT_TIMEOUT_SECONDS
    )
    command_timeout = (
        payload.command_timeout_seconds
        or (stored_settings.command_timeout_seconds if stored_settings else None)
        or ssh_provision.DEFAULT_COMMAND_TIMEOUT_SECONDS
    )

    if payload.commands:
        if any(_EXISTING_SECRET_PLACEHOLDER in line for line in payload.commands):
            commands = [line.replace(_EXISTING_SECRET_PLACEHOLDER, real_secret) for line in payload.commands]
        else:
            extracted = ssh_provision.extract_shared_secret(payload.commands)
            if not extracted:
                raise HTTPException(
                    status.HTTP_400_BAD_REQUEST,
                    detail="Could not find a 'tacacs-server host ... key ...' line in the edited commands -- "
                           "add one back, or don't remove the generated line.",
                )
            commands = payload.commands
            if extracted != real_secret:
                device.shared_secret_encrypted = security.encrypt_secret(extracted)
                db.commit()
    else:
        template = _get_aaa_template_for_device(db)
        commands = ssh_provision.build_cisco_ios_aaa_commands(
            platform_ip=payload.platform_ip, shared_secret=real_secret, templates=template,
        )

    from ..services import apply_progress
    session_id = apply_progress.start_session(total=1, target_description=f"Applying AAA config to {device.name}")
    background_tasks.add_task(
        _apply_aaa_to_device_background, session_id,
        host=_bare_ip(device), ssh_username=payload.ssh_username, ssh_password=payload.ssh_password,
        commands=commands, connect_timeout=connect_timeout, command_timeout=command_timeout,
    )
    return {"session_id": session_id}
