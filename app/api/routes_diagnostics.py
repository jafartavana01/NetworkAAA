"""
app.api.routes_diagnostics
============================
Spec section 56 (Phase 7): server status, recent requests, auth/authz
failures, configuration validation, service logs, build information --
consolidated into one page. Deliberately does NOT duplicate logic:
every endpoint here either reuses an existing service module
(build_info_service, service_control, config_compiler) or reads the
audit trail (InstallEvent) that earlier phases were already writing to
but never had a GUI to show. Diagnostics surfaces what the platform
already tracks; it doesn't introduce new tracking.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.system_info import InstallEvent
from ..services import build_info_service, config_compiler, service_control
from .deps import get_current_admin

router = APIRouter(prefix="/api/diagnostics", tags=["diagnostics"])

_ALLOWED_UNITS = {service_control.MANAGEMENT_UNIT, service_control.TAC_PLUS_NG_UNIT}


@router.get("/overview")
def diagnostics_overview(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """Server status + build information in one call -- the two spec
    section 56 items that were already fully implemented (Phase 1),
    just re-exposed here so Diagnostics doesn't require a trip back to
    the Dashboard to see them alongside everything else."""
    services = {}
    for unit in (service_control.MANAGEMENT_UNIT, service_control.TAC_PLUS_NG_UNIT):
        try:
            s = service_control.get_status(unit)
            services[unit] = {"active_state": s.active_state, "sub_state": s.sub_state, "enabled": s.enabled}
        except service_control.ServiceControlError as exc:
            services[unit] = {"error": str(exc)}

    return {
        "services": services,
        "build_info": build_info_service.get_build_info(),
    }


@router.get("/service-log/{unit}")
def service_log(
    unit: str,
    _admin: AdminUser = Depends(get_current_admin),
):
    if unit not in _ALLOWED_UNITS:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Unknown service unit.")
    try:
        return {"unit": unit, "content": service_control.recent_logs(unit)}
    except service_control.ServiceControlError as exc:
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=str(exc))


@router.get("/audit-events")
def audit_events(
    limit: int = 100,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """
    The configuration-apply/validation/rollback trail this platform has
    been writing to InstallEvent since Phase 2 (config_apply_succeeded,
    config_auto_rollback, config_validation_inconclusive) and since
    Phase 1 (initial_install, reinstall) -- recorded all along, but
    never given a GUI to actually look at until now.
    """
    limit = max(1, min(limit, 500))
    events = (
        db.query(InstallEvent)
        .order_by(InstallEvent.occurred_at.desc())
        .limit(limit)
        .all()
    )
    return {
        "events": [
            {
                "id": str(e.id),
                "event_type": e.event_type,
                "commit_hash": e.commit_hash,
                "detail": e.detail,
                "occurred_at": e.occurred_at.isoformat(),
            }
            for e in events
        ]
    }


@router.post("/validate-config")
def validate_config_now(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """
    On-demand syntax check of what the candidate config would be RIGHT
    NOW if applied -- reuses config_compiler.compile_candidate() and
    .validate_candidate() exactly as the real Apply flow does, so this
    is a genuine pre-flight check, not a separate, potentially-diverging
    code path. A definitive failure here means the real Apply flow
    would refuse to apply this candidate at all (see
    config_compiler.validate_candidate's docstring for what "definitive"
    means and why it's now trusted enough to block on).
    """
    candidate = config_compiler.compile_candidate(db)
    active = config_compiler.get_active_config()
    validation = config_compiler.validate_candidate(candidate)
    return {
        "would_change": candidate != active,
        "validated": validation.validated,
        "definitively_failed": validation.definitively_failed,
        "output": validation.output,
    }
