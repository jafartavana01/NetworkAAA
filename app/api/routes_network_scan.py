"""
app.api.routes_network_scan
==============================
Scans a range for SSH-reachable hosts, then pushes Cisco IOS TACACS+
client configuration to selected hosts and creates the corresponding
Device record -- see app.services.network_scan and
app.services.ssh_provision for the full design reasoning (SSH-port
reachability as the discovery signal, credentials never persisted,
`local` fallback always included in the pushed AAA config).

Scanning is fast (just a TCP connect check); hostname detection and
AAA config push both happen together during Apply, per-host -- not
during the scan itself, which would mean an SSH login to every
reachable host just to list them.

`devices:write` gates everything here -- scanning reveals which IPs
in a range are live (a mild information action, but paired with
credentials), and applying pushes real configuration and creates
devices, exactly the same privileged actions as the normal Devices
flow.
"""
from __future__ import annotations

import secrets
import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..schemas.network_scan import (
    ApplyAaaAllRequest,
    ApplyAaaRequest,
    ApplyAaaResultOut,
    PreviewCommandsRequest,
    ScanRequest,
    ScanResultOut,
)
from ..services import apply_progress, network_scan, ssh_provision
from .deps import require_permission, verify_csrf
from .routes_devices import _check_no_overlap

router = APIRouter(prefix="/api/network-scan", tags=["network-scan"])


@router.post("/scan", response_model=list[ScanResultOut], dependencies=[Depends(verify_csrf)])
def scan(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    try:
        results = network_scan.scan_range(db, payload.cidr)
    except ValueError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))
    return results


@router.get("/platform-addresses")
def platform_addresses(
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    """This platform's own detected non-loopback IPv4 addresses --
    see app.services.network_scan.get_platform_addresses for why this
    is preferred over guessing from the admin's own browser address."""
    return {"addresses": network_scan.get_platform_addresses()}


@router.post("/preview-commands")
def preview_commands(
    payload: PreviewCommandsRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    """Generates the exact commands an Apply would send, WITHOUT
    connecting to anything -- backs the "Edit commands before
    applying" panel. Uses the admin's saved template
    (app.api.routes_aaa_template) if one has been customized, else the
    built-in default -- the exact same source _apply_one() itself
    reads from, so a preview never shows something different from what
    an unedited Apply would actually send. The generated secret shown
    here is only a preview value; the real apply generates its own
    secret at that time and uses THAT, not whatever was in this
    preview."""
    preview_secret = secrets.token_urlsafe(24)
    template = _get_aaa_template(db)
    commands = ssh_provision.build_cisco_ios_aaa_commands(platform_ip=payload.platform_ip, shared_secret=preview_secret, templates=template)
    return {"commands": commands}


def _generate_device_secret() -> str:
    return secrets.token_urlsafe(24)


def _get_aaa_template(db: Session) -> list[str] | None:
    """The admin's saved AAA command template (app.api.routes_aaa_template),
    if one has ever been created -- None otherwise, letting
    build_cisco_ios_aaa_commands fall back to its own built-in
    default. A thin lookup only -- never creates a row itself (unlike
    routes_aaa_template's own _get_or_create_settings), since a scan/
    apply happening before the admin has ever opened the template
    editor should just silently use the built-in default, not
    implicitly "customize" anything."""
    from ..models.aaa_template_settings import AaaTemplateSettings
    settings = db.query(AaaTemplateSettings).first()
    return settings.commands if settings else None


def _resolve_group(db: Session, group_id: str | None) -> DeviceGroup | None:
    if not group_id:
        return None
    try:
        parsed = uuid.UUID(group_id)
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid device group id.")
    group = db.query(DeviceGroup).filter(DeviceGroup.id == parsed).first()
    if not group:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That device group doesn't exist.")
    return group


def _apply_one(
    db: Session, *, ip_address: str, ssh_username: str, ssh_password: str, platform_ip: str,
    group: DeviceGroup | None, device_name: str | None, commands_override: list[str] | None,
    progress_session_id: str | None = None,
    connect_timeout: int | None = None, command_timeout: int | None = None,
) -> ApplyAaaResultOut:
    def log(line: str) -> None:
        if progress_session_id:
            apply_progress.append_log(progress_session_id, line)

    from ..models.aaa_template_settings import AaaTemplateSettings
    stored_settings = db.query(AaaTemplateSettings).first()
    # Per-apply override -> admin's stored default -> ssh_provision's
    # own built-in default. See ApplyAaaRequest's own docstring.
    resolved_connect_timeout = (
        connect_timeout
        or (stored_settings.connect_timeout_seconds if stored_settings else None)
        or ssh_provision.DEFAULT_CONNECT_TIMEOUT_SECONDS
    )
    resolved_command_timeout = (
        command_timeout
        or (stored_settings.command_timeout_seconds if stored_settings else None)
        or ssh_provision.DEFAULT_COMMAND_TIMEOUT_SECONDS
    )

    # Overlap check first -- refuse before ever touching the device
    # over SSH if this IP would conflict with an existing one (same
    # protection app.api.routes_devices.create_device already has).
    try:
        _check_no_overlap(db, ip_address)
    except HTTPException as exc:
        log(f"{ip_address}: skipped — {exc.detail}")
        return ApplyAaaResultOut(ip_address=ip_address, success=False, message=str(exc.detail))

    # Always gathered (not only when a name needs detecting) -- the
    # name might be explicitly provided, but platform/vendor/version
    # info is independently useful and the connection is one round-
    # trip either way (hostname prompt + `show version` in the same
    # SSH session, not two separate connections).
    log(f"{ip_address}: connecting to gather device information…")
    info = ssh_provision.gather_device_info(
        ip_address, ssh_username, ssh_password,
        connect_timeout=resolved_connect_timeout, command_timeout=resolved_command_timeout,
    )
    if not info.success:
        log(f"{ip_address}: FAIL — {info.message}")
        return ApplyAaaResultOut(ip_address=ip_address, success=False, message=info.message)

    name = device_name or info.hostname or ip_address.replace(".", "-")

    if db.query(NetworkDevice).filter(NetworkDevice.name == name).first():
        # A real, if unlikely, collision (e.g. two devices with the
        # same detected hostname) -- disambiguate rather than fail
        # the whole apply outright.
        name = f"{name}-{ip_address.split('.')[-1]}"

    if commands_override:
        # Admin-edited commands -- the stored secret is extracted
        # DIRECTLY from what's actually being sent, never tracked as a
        # separate value that could drift out of sync with an edit
        # (see app.services.ssh_provision.extract_shared_secret).
        secret = ssh_provision.extract_shared_secret(commands_override)
        if not secret:
            msg = ("Could not find a 'tacacs-server host ... key ...' line in the edited commands -- "
                   "add one back, or don't remove the generated line, so the stored device secret matches what's actually sent.")
            log(f"{ip_address}: FAIL — {msg}")
            return ApplyAaaResultOut(ip_address=ip_address, success=False, message=msg)
        commands = commands_override
    else:
        secret = _generate_device_secret()
        template = _get_aaa_template(db)
        commands = ssh_provision.build_cisco_ios_aaa_commands(platform_ip=platform_ip, shared_secret=secret, templates=template)

    log(f"{name} ({ip_address}): applying {len(commands)} command(s)…")
    result = ssh_provision.apply_aaa_config(
        ip_address, ssh_username, ssh_password, commands=commands,
        connect_timeout=resolved_connect_timeout, command_timeout=resolved_command_timeout,
    )

    if not result.success:
        log(f"{name} ({ip_address}): FAIL — {result.message}")
        return ApplyAaaResultOut(ip_address=ip_address, success=False, message=result.message, command_log=result.command_log)

    description = None
    if info.raw_version_output:
        description = f"Discovered via Network Scan & Provision.\n\n{info.raw_version_output}"

    device = NetworkDevice(
        name=name,
        ip_address=ip_address,
        shared_secret_encrypted=security.encrypt_secret(secret),
        device_group_id=group.id if group else None,
        vendor=info.vendor,
        platform=info.platform,
        description=description,
        enabled=True,
    )
    db.add(device)
    db.commit()
    db.refresh(device)

    log(f"{name} ({ip_address}): Pass")
    return ApplyAaaResultOut(
        ip_address=ip_address, success=True, message="Configuration applied and device added.",
        command_log=result.command_log, device_id=str(device.id),
    )


def _apply_single_background(session_id: str, payload: ApplyAaaRequest) -> None:
    """Same background-task pattern as _apply_all_background, applied
    to a single target -- see that function's own docstring for why a
    dedicated database session is needed here. Every apply (single or
    bulk) now runs this way, so the GUI can offer "Continue in
    background" uniformly rather than only for a bulk apply."""
    from ..database import get_sessionmaker
    session_local = get_sessionmaker()
    db = session_local()
    try:
        group = _resolve_group(db, payload.device_group_id)
        result = _apply_one(
            db, ip_address=payload.ip_address, ssh_username=payload.ssh_username, ssh_password=payload.ssh_password,
            platform_ip=payload.platform_ip, group=group, device_name=payload.device_name,
            commands_override=payload.commands, progress_session_id=session_id,
            connect_timeout=payload.connect_timeout_seconds, command_timeout=payload.command_timeout_seconds,
        )
        apply_progress.increment_completed(session_id)
        apply_progress.finish_session(session_id, [result.model_dump()])
    except Exception as exc:
        apply_progress.append_log(session_id, f"Unexpected error: {exc}")
        apply_progress.finish_session(session_id, [])
    finally:
        db.close()


@router.post("/apply", dependencies=[Depends(verify_csrf)])
def apply_aaa(
    payload: ApplyAaaRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    """Runs as a background task and returns a session id immediately
    -- same reasoning and the same GET .../apply-progress/{session_id}
    polling endpoint as apply_aaa_all, now applied to a single target
    too, so a slow single-device push can also offer live progress and
    "Continue in background" rather than holding the request open with
    no visibility until it finishes."""
    _resolve_group(db, payload.device_group_id)  # validate early; the background task re-resolves its own copy
    session_id = apply_progress.start_session(
        total=1, target_description=f"Applying AAA config to {payload.device_name or payload.ip_address}",
    )
    background_tasks.add_task(_apply_single_background, session_id, payload)
    return {"session_id": session_id}


def _apply_all_background(session_id: str, payload: ApplyAaaAllRequest) -> None:
    """Runs OUTSIDE the request's own lifecycle (called via
    BackgroundTasks -- see apply_aaa_all below), so it needs its OWN
    database session rather than the request-scoped one FastAPI's
    Depends(get_db) provides, which is already closed by the time a
    background task actually executes. Same sessionmaker-direct
    pattern app.main's own boot-time seeding functions already use."""
    from ..database import get_sessionmaker
    session_local = get_sessionmaker()
    db = session_local()
    try:
        group = _resolve_group(db, payload.device_group_id)
        results = []
        for ip in payload.ip_addresses:
            results.append(_apply_one(
                db, ip_address=ip, ssh_username=payload.ssh_username, ssh_password=payload.ssh_password,
                platform_ip=payload.platform_ip, group=group, device_name=None,
                commands_override=payload.commands, progress_session_id=session_id,
                connect_timeout=payload.connect_timeout_seconds, command_timeout=payload.command_timeout_seconds,
            ))
            apply_progress.increment_completed(session_id)
        apply_progress.finish_session(session_id, [r.model_dump() for r in results])
    except Exception as exc:
        apply_progress.append_log(session_id, f"Unexpected error: {exc}")
        apply_progress.finish_session(session_id, [])
    finally:
        db.close()


@router.post("/apply-all", dependencies=[Depends(verify_csrf)])
def apply_aaa_all(
    payload: ApplyAaaAllRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    """Applies sequentially, not in parallel -- a bulk SSH push to
    many devices at once is exactly the kind of operation worth
    keeping simple and traceable (one clear per-host result in order)
    over fast, given the admin needs to review what happened on each
    device afterward, not just how quickly it finished. One host
    failing does not stop the rest -- every requested IP gets its own
    attempt and its own result.

    Runs as a background task, returning a session id immediately, so
    the GUI can poll GET .../apply-progress/{session_id} for a live
    "which device, which step" view WHILE the batch is still running
    -- a single blocking request/response has no way to report partial
    progress before the whole thing finishes. The device-group id is
    still validated synchronously here, before returning, so a bad
    group id fails immediately with a clear error rather than only
    surfacing once the background task gets around to it.

    NOTE on `commands` here specifically: since the SAME edited
    command list is used for every target, an edited command list
    means every device in this batch gets the SAME shared secret
    (extracted once, reused for each) -- less isolated than the
    default (a fresh random secret generated per device when no
    override is given). The GUI warns about this specifically for
    bulk apply; still allowed, since a shared secret across a batch
    is a legitimate deliberate choice in some environments, not
    always a mistake."""
    _resolve_group(db, payload.device_group_id)  # validate early; the background task re-resolves its own copy
    session_id = apply_progress.start_session(
        total=len(payload.ip_addresses),
        target_description=f"Applying AAA config to {len(payload.ip_addresses)} device(s)",
    )
    background_tasks.add_task(_apply_all_background, session_id, payload)
    return {"session_id": session_id}


@router.get("/apply-progress/{session_id}")
def get_apply_progress(
    session_id: str,
    _admin: AdminUser = Depends(require_permission("devices:view")),
):
    session = apply_progress.get_session(session_id)
    if session is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Unknown or expired progress session.")
    return session
