"""
app.api.routes_aaa_template
==============================
Get/update the admin-customizable default AAA command template (see
app.models.aaa_template_settings). `devices:write` gated -- this
changes what real configuration gets pushed to real devices on every
future Apply, exactly as privileged as the Devices flow itself.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.aaa_template_settings import AaaTemplateSettings
from ..services import ssh_provision
from .deps import require_permission, verify_csrf

router = APIRouter(prefix="/api/aaa-template", tags=["aaa-template"])


class AaaTemplateUpdate(BaseModel):
    commands: list[str] = Field(min_length=1)
    connect_timeout_seconds: int | None = Field(default=None, ge=1, le=120)
    command_timeout_seconds: int | None = Field(default=None, ge=1, le=300)


class AaaTemplateOut(BaseModel):
    commands: list[str]
    is_default: bool  # true when no admin customization has been saved yet
    connect_timeout_seconds: int | None
    command_timeout_seconds: int | None
    default_connect_timeout_seconds: int
    default_command_timeout_seconds: int


def _get_or_create_settings(db: Session) -> AaaTemplateSettings:
    settings = db.query(AaaTemplateSettings).first()
    if settings is None:
        settings = AaaTemplateSettings(commands=ssh_provision.default_command_templates())
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def _to_out(settings: AaaTemplateSettings) -> AaaTemplateOut:
    return AaaTemplateOut(
        commands=settings.commands,
        is_default=(settings.commands == ssh_provision.default_command_templates()),
        connect_timeout_seconds=settings.connect_timeout_seconds,
        command_timeout_seconds=settings.command_timeout_seconds,
        default_connect_timeout_seconds=ssh_provision.DEFAULT_CONNECT_TIMEOUT_SECONDS,
        default_command_timeout_seconds=ssh_provision.DEFAULT_COMMAND_TIMEOUT_SECONDS,
    )


@router.get("", response_model=AaaTemplateOut)
def get_template(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:view")),
):
    settings = _get_or_create_settings(db)
    return _to_out(settings)


@router.put("", response_model=AaaTemplateOut, dependencies=[Depends(verify_csrf)])
def update_template(
    payload: AaaTemplateUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    settings = _get_or_create_settings(db)
    settings.commands = payload.commands
    settings.connect_timeout_seconds = payload.connect_timeout_seconds
    settings.command_timeout_seconds = payload.command_timeout_seconds
    db.commit()
    db.refresh(settings)
    return _to_out(settings)


@router.post("/reset-to-default", response_model=AaaTemplateOut, dependencies=[Depends(verify_csrf)])
def reset_template(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    settings = _get_or_create_settings(db)
    settings.commands = ssh_provision.default_command_templates()
    # Deliberately NOT resetting the timeout fields here -- "reset to
    # default" is documented and understood (see the GUI's own button)
    # as being about the COMMAND TEMPLATE specifically, not every
    # setting on this page; an admin's timeout customization
    # shouldn't silently vanish because they reset an unrelated field.
    db.commit()
    db.refresh(settings)
    return _to_out(settings)
