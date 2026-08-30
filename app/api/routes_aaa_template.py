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


class AaaTemplateOut(BaseModel):
    commands: list[str]
    is_default: bool  # true when no admin customization has been saved yet


def _get_or_create_settings(db: Session) -> AaaTemplateSettings:
    settings = db.query(AaaTemplateSettings).first()
    if settings is None:
        settings = AaaTemplateSettings(commands=ssh_provision.default_command_templates())
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@router.get("", response_model=AaaTemplateOut)
def get_template(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:view")),
):
    settings = _get_or_create_settings(db)
    return AaaTemplateOut(commands=settings.commands, is_default=(settings.commands == ssh_provision.default_command_templates()))


@router.put("", response_model=AaaTemplateOut, dependencies=[Depends(verify_csrf)])
def update_template(
    payload: AaaTemplateUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    settings = _get_or_create_settings(db)
    settings.commands = payload.commands
    db.commit()
    db.refresh(settings)
    return AaaTemplateOut(commands=settings.commands, is_default=(settings.commands == ssh_provision.default_command_templates()))


@router.post("/reset-to-default", response_model=AaaTemplateOut, dependencies=[Depends(verify_csrf)])
def reset_template(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("devices:write")),
):
    settings = _get_or_create_settings(db)
    settings.commands = ssh_provision.default_command_templates()
    db.commit()
    db.refresh(settings)
    return AaaTemplateOut(commands=settings.commands, is_default=True)
