"""
app.api.routes_effective_access
=================================
PAM Expansion Plan §8. Both queries run app.services.policy_engine.evaluate()
across every device or every user in the database, with no command
supplied (a session-establishment-only evaluation -- "can this user
even reach this device, and at what privilege," not "can they run
this specific command"). Same single-engine principle as the Policy
Simulator: this is bulk application of the exact same function, not a
separately-maintained access-computation path.

Pure database analysis, per §8/§23's explicit constraint -- no device
is contacted for either query.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.user import TacacsUser
from ..services import policy_engine
from .deps import get_current_admin

router = APIRouter(prefix="/api/effective-access", tags=["effective-access"])


def _result_summary(db: Session, result: policy_engine.EvaluationResult) -> dict | None:
    """None means no policy matched -- not reachable at all."""
    if result.matched_policy is None:
        return None
    command_sets = [cs.name for cs in policy_engine.get_command_sets_for_policy(db, result.matched_policy)]
    return {
        "matched_policy_name": result.matched_policy.name,
        "priv_lvl": result.priv_lvl,
        "command_sets": command_sets,
    }


@router.get("/user/{user_id}")
def effective_access_for_user(
    user_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """"What can user X access?" -- every device this user can reach,
    grouped by the privilege level each grants."""
    try:
        parsed_id = uuid.UUID(user_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found.")
    user = db.query(TacacsUser).filter(TacacsUser.id == parsed_id).first()
    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User not found.")

    devices = db.query(NetworkDevice).order_by(NetworkDevice.name.asc()).all()

    reachable = []
    by_privilege: dict[int, int] = {}
    for device in devices:
        result = policy_engine.evaluate(db, user=user, device=device, command=None)
        summary = _result_summary(db, result)
        if summary is not None:
            reachable.append({"device_id": str(device.id), "device_name": device.name, **summary})
            by_privilege[summary["priv_lvl"]] = by_privilege.get(summary["priv_lvl"], 0) + 1

    return {
        "subject_type": "user",
        "subject_id": str(user.id),
        "subject_name": user.username,
        "total_devices_checked": len(devices),
        "total_reachable": len(reachable),
        "by_privilege": by_privilege,
        "devices": reachable,
    }


@router.get("/device/{device_id}")
def effective_access_for_device(
    device_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """"Who can access device X?" -- every user who can reach this
    device, and at what privilege."""
    try:
        parsed_id = uuid.UUID(device_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")
    device = db.query(NetworkDevice).filter(NetworkDevice.id == parsed_id).first()
    if not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")

    users = db.query(TacacsUser).filter(TacacsUser.enabled.is_(True)).order_by(TacacsUser.username.asc()).all()

    reachable = []
    by_privilege: dict[int, int] = {}
    for user in users:
        result = policy_engine.evaluate(db, user=user, device=device, command=None)
        summary = _result_summary(db, result)
        if summary is not None:
            reachable.append({"user_id": str(user.id), "username": user.username, **summary})
            by_privilege[summary["priv_lvl"]] = by_privilege.get(summary["priv_lvl"], 0) + 1

    return {
        "subject_type": "device",
        "subject_id": str(device.id),
        "subject_name": device.name,
        "total_users_checked": len(users),
        "total_reachable": len(reachable),
        "by_privilege": by_privilege,
        "users": reachable,
    }


@router.get("/why")
def why_can_access(
    user_id: str,
    device_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """"Why can this user access this device?" -- the single
    evaluation with its full trace, the same explanatory mechanism the
    Policy Simulator uses (app.services.policy_engine's trace is one
    mechanism serving both features, not two)."""
    try:
        parsed_user_id = uuid.UUID(user_id)
        parsed_device_id = uuid.UUID(device_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User or device not found.")

    user = db.query(TacacsUser).filter(TacacsUser.id == parsed_user_id).first()
    device = db.query(NetworkDevice).filter(NetworkDevice.id == parsed_device_id).first()
    if not user or not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="User or device not found.")

    result = policy_engine.evaluate(db, user=user, device=device, command=None)
    return {
        "user_name": user.username,
        "device_name": device.name,
        "result": _result_summary(db, result),
        "trace": [s.to_dict() for s in result.trace],
    }
