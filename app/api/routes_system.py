"""
app.api.routes_system
=======================
System status endpoints backing the Phase 1 dashboard (spec section
50): Ubuntu info, tac_plus-ng build info, service status, database
status. All routes require an authenticated admin.
"""
from __future__ import annotations

import platform
from datetime import datetime, timezone

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..services import build_info_service, service_control
from .deps import get_current_admin

router = APIRouter(prefix="/api/system", tags=["system"])


@router.get("/status")
def system_status(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    db_status = "connected"
    try:
        db.execute(text("SELECT 1"))
    except Exception as exc:  # pragma: no cover - defensive
        db_status = f"error: {exc}"

    services = {}
    for unit in (service_control.MANAGEMENT_UNIT, service_control.TAC_PLUS_NG_UNIT):
        try:
            status = service_control.get_status(unit)
            services[unit] = {
                "active_state": status.active_state,
                "sub_state": status.sub_state,
                "enabled": status.enabled,
            }
        except service_control.ServiceControlError as exc:
            services[unit] = {"error": str(exc)}

    return {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "os": platform.platform(),
        "database": db_status,
        "services": services,
        "build_info": build_info_service.get_build_info(),
    }
