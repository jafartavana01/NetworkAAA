"""
app.api.routes_modules
=========================
Module management: which optional subsystems are installed and enabled.

Superadmin-gated. Toggling a module changes which API routers this
application mounts at startup (see app.main), which is a
platform-level decision rather than day-to-day administration.

A disabled module's routes are NOT mounted on the next boot, so its
pages and API return 404 -- its DATA is untouched. Disabling is
therefore reversible and never destructive, and the API says so rather
than leaving an admin to guess whether they are about to lose
anything.
"""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.module_state import ModuleState
from ..modules import registry
from .deps import get_current_superadmin, verify_csrf

router = APIRouter(prefix="/api/modules", tags=["modules"])


class ModuleOut(BaseModel):
    key: str
    name: str
    description: str
    enabled: bool
    #: Mandatory modules cannot be disabled -- the platform could not
    #: function without them (authentication, the shell itself).
    mandatory: bool
    nav_paths: list[str]
    route_count: int
    updated_at: datetime | None


class ModuleToggleRequest(BaseModel):
    enabled: bool


def _nav_paths(module) -> list[str]:
    paths = []
    for entry in module.nav_entries or []:
        if entry.children:
            paths.extend(c.path for c in entry.children)
        else:
            paths.append(entry.path)
    return paths


def _route_count(module) -> int:
    return len(getattr(module.router, "routes", []) or []) if module.router else 0


@router.get("", response_model=list[ModuleOut])
def list_modules(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    state = {row.key: row for row in db.query(ModuleState).all()}
    out = []
    for module in registry.all_modules():
        row = state.get(module.key)
        out.append(ModuleOut(
            key=module.key, name=module.name, description=module.description,
            # A mandatory module reports enabled regardless of any stored
            # row, because that is what app.main actually does when
            # mounting -- reporting otherwise would be a lie the UI then
            # repeats.
            enabled=bool(module.mandatory or (row.enabled if row else True)),
            mandatory=module.mandatory,
            nav_paths=_nav_paths(module), route_count=_route_count(module),
            updated_at=row.updated_at if row else None,
        ))
    return out


@router.put("/{module_key}", response_model=ModuleOut, dependencies=[Depends(verify_csrf)])
def set_module_enabled(
    module_key: str,
    payload: ModuleToggleRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    module = registry.get_module(module_key)
    if module is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Module not found.")
    if module.mandatory and not payload.enabled:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail=f"'{module.name}' is required for the platform to function and cannot be disabled.",
        )

    row = db.query(ModuleState).filter(ModuleState.key == module_key).first()
    if row is None:
        row = ModuleState(key=module_key, enabled=payload.enabled)
        db.add(row)
    else:
        row.enabled = payload.enabled
    db.commit()
    db.refresh(row)

    return ModuleOut(
        key=module.key, name=module.name, description=module.description,
        enabled=bool(module.mandatory or row.enabled), mandatory=module.mandatory,
        nav_paths=_nav_paths(module), route_count=_route_count(module),
        updated_at=row.updated_at,
    )
