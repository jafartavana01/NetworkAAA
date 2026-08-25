"""
app.api.routes_platform_settings
==================================
Network/TLS settings for the platform itself -- superadmin-only.
Saving a setting here does NOT take effect until the management
service restarts (app/run.py reads these once, at process start --
see its own docstring for why a systemd unit can't just be rewritten
on every settings change). This API deliberately does NOT restart the
service automatically as a side effect of saving: the HTTP response
confirming the save needs to actually reach the admin's browser before
the process that's sending it dies, and if the port or protocol
itself changed, the admin needs a moment to know where to reconnect.
Restarting is a separate, explicit action the admin takes after
reviewing what changed.
"""
from __future__ import annotations

import grp
import pwd

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field, field_validator

from .. import platform_settings
from ..models.admin import AdminUser
from ..services import service_control, tls_certs
from .deps import get_current_superadmin, verify_csrf

router = APIRouter(prefix="/api/platform-settings", tags=["platform-settings"])

_SERVICE_USER = "aaa-platform"
_SERVICE_GROUP = "aaa-platform"


class NetworkSettingsUpdate(BaseModel):
    web_host: str = Field(min_length=1, max_length=64)
    web_port: int = Field(ge=1, le=65535)
    https_enabled: bool
    tacacs_port: int = Field(ge=1, le=65535)

    @field_validator("web_port", "tacacs_port")
    @classmethod
    def ports_differ_warning_not_enforced(cls, v: int) -> int:
        # Deliberately not rejecting web_port == tacacs_port here --
        # they're different protocols/sockets and a collision would
        # simply fail to bind at restart with a clear OS-level error,
        # which is a perfectly adequate signal; adding a duplicate
        # cross-field check here would just be redundant validation.
        return v


class RegenerateCertRequest(BaseModel):
    common_name: str = Field(min_length=1, max_length=253)
    organization: str | None = Field(default=None, max_length=128)
    organizational_unit: str | None = Field(default=None, max_length=128)
    validity_days: int = Field(default=tls_certs.DEFAULT_VALIDITY_DAYS, ge=1, le=3650)
    key_size: int = Field(default=tls_certs.DEFAULT_KEY_SIZE)
    subject_alt_names: list[str] = Field(default_factory=list)


class UploadCertRequest(BaseModel):
    certificate_pem: str
    private_key_pem: str


def _service_account_ids() -> tuple[int, int]:
    return pwd.getpwnam(_SERVICE_USER).pw_uid, grp.getgrnam(_SERVICE_GROUP).gr_gid


@router.get("")
def get_platform_settings(
    _admin: AdminUser = Depends(get_current_superadmin),
):
    settings = platform_settings.load_settings()
    return {
        **settings,
        "certificate": tls_certs.describe_active_certificate(),
    }


@router.put("/network", dependencies=[Depends(verify_csrf)])
def update_network_settings(
    payload: NetworkSettingsUpdate,
    _admin: AdminUser = Depends(get_current_superadmin),
):
    current = platform_settings.load_settings()
    current.update({
        "web_host": payload.web_host,
        "web_port": payload.web_port,
        "https_enabled": payload.https_enabled,
        "tacacs_port": payload.tacacs_port,
    })

    if payload.https_enabled:
        cert = tls_certs.describe_active_certificate()
        if cert is None or cert.get("error"):
            raise HTTPException(
                status.HTTP_400_BAD_REQUEST,
                detail="No valid TLS certificate is installed -- generate or upload one before enabling HTTPS.",
            )

    platform_settings.save_settings(current)
    return {"status": "ok", "settings": current, "restart_required": True}


@router.post("/tls/regenerate", dependencies=[Depends(verify_csrf)])
def regenerate_self_signed(
    payload: RegenerateCertRequest,
    _admin: AdminUser = Depends(get_current_superadmin),
):
    try:
        cert_pem, key_pem = tls_certs.generate_self_signed(
            common_name=payload.common_name,
            organization=payload.organization,
            organizational_unit=payload.organizational_unit,
            validity_days=payload.validity_days,
            key_size=payload.key_size,
            subject_alt_names=payload.subject_alt_names or None,
        )
        uid, gid = _service_account_ids()
        tls_certs.write_active_certificate(cert_pem, key_pem, uid=uid, gid=gid)
    except tls_certs.CertificateError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return {"status": "ok", "certificate": tls_certs.describe_active_certificate(), "restart_required": True}


@router.post("/tls/upload", dependencies=[Depends(verify_csrf)])
def upload_custom_certificate(
    payload: UploadCertRequest,
    _admin: AdminUser = Depends(get_current_superadmin),
):
    try:
        uid, gid = _service_account_ids()
        tls_certs.write_active_certificate(
            payload.certificate_pem.encode("utf-8"),
            payload.private_key_pem.encode("utf-8"),
            uid=uid,
            gid=gid,
        )
    except tls_certs.CertificateError as exc:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=str(exc))

    return {"status": "ok", "certificate": tls_certs.describe_active_certificate(), "restart_required": True}


@router.post("/restart-management-service", dependencies=[Depends(verify_csrf)])
def restart_management_service(
    _admin: AdminUser = Depends(get_current_superadmin),
):
    """
    The one place this project deliberately restarts the very service
    handling the current request. FastAPI/uvicorn finish sending this
    response before the process receives the restart signal from
    systemd (the subprocess call returns once `systemctl restart` has
    been issued, not once the old process has actually exited), so the
    confirmation below does reliably reach the browser first -- but the
    admin's NEXT request may briefly fail while the new process starts,
    or need to go to a different port/protocol entirely if that's what
    changed.
    """
    try:
        service_control.restart(service_control.MANAGEMENT_UNIT)
    except service_control.ServiceControlError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=str(exc))
    return {"status": "restarting"}
