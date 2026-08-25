"""
app.api.routes_policy_simulator
=================================
PAM Expansion Plan §7. Calls app.services.policy_engine.evaluate()
directly -- the exact same function app.services.config_compiler uses
to decide what tac_plus-ng actually does -- so the Simulator's answer
is provably what production would do, not a best-effort
approximation maintained separately. Never contacts a device (§7's
explicit constraint): every lookup here is a database read against
this platform's own TacacsUser/NetworkDevice/TacacsGroup/DeviceGroup
rows.

Source IP, protocol, service, and privilege are accepted as input
fields (matching §7's requested form fields) but are NOT yet evaluated
against any policy condition -- app.models.policy only implements
group/device/device-group conditions so far (see that model's
docstring for exactly what's implemented vs. deferred, and why:
source-IP/CIDR matching has confirmed tac_plus-ng syntax but isn't
wired into the Policy model yet; time-of-day conditions have no
confirmed syntax at all). Accepting the fields without using them is
honest about current scope -- the alternative would be a form that
silently ignores what the admin typed into it with no explanation,
which is worse.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..models.group import TacacsGroup
from ..models.user import TacacsUser
from ..services import policy_engine
from .deps import get_current_admin, verify_csrf

router = APIRouter(prefix="/api/policy-simulator", tags=["policy-simulator"])


class SimulationRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str | None = None
    device_name: str | None = None
    source_ip: str | None = None
    protocol: str = "tacacs+"
    service: str = "shell"
    command: str | None = None


@router.post("/evaluate", dependencies=[Depends(verify_csrf)])
def simulate(
    payload: SimulationRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    user = db.query(TacacsUser).filter(TacacsUser.username == payload.username).first()
    device = None
    if payload.device_name:
        device = db.query(NetworkDevice).filter(NetworkDevice.name == payload.device_name).first()

    authentication = {"result": "NOT_CHECKED", "detail": "No password supplied -- authentication was not evaluated."}
    if user is None:
        authentication = {"result": "FAILURE", "detail": f"No TACACS+ user named '{payload.username}' exists."}
    elif not user.enabled:
        authentication = {"result": "FAILURE", "detail": "This user account is disabled."}
    elif payload.password is not None:
        ok = security.verify_password(payload.password, user.password_hash)
        authentication = (
            {"result": "SUCCESS", "detail": "Password matches the stored hash."}
            if ok
            else {"result": "FAILURE", "detail": "Password does not match the stored hash."}
        )

    group_name = None
    if user and user.group_id:
        group = db.query(TacacsGroup).filter(TacacsGroup.id == user.group_id).first()
        group_name = group.name if group else None

    device_group_name = None
    if device and device.device_group_id:
        from ..models.device_group import DeviceGroup
        dg = db.query(DeviceGroup).filter(DeviceGroup.id == device.device_group_id).first()
        device_group_name = dg.name if dg else None

    result = policy_engine.evaluate(db, user=user, device=device, command=payload.command)

    command_sets_granted = []
    if result.matched_policy is not None:
        command_sets_granted = [
            cs.name for cs in policy_engine.get_command_sets_for_policy(db, result.matched_policy)
        ]

    return {
        "authentication": authentication,
        "identity": {
            "username": payload.username,
            "found": user is not None,
            "group_name": group_name,
        },
        "device": {
            "name": payload.device_name,
            "found": device is not None if payload.device_name else None,
            "device_group_name": device_group_name,
        },
        "unevaluated_inputs": {
            "source_ip": payload.source_ip,
            "protocol": payload.protocol,
            "service": payload.service,
            "note": "Accepted but not yet evaluated against any policy condition -- see this route's docstring.",
        },
        "authorization": {
            "matched_policy_name": result.matched_policy.name if result.matched_policy else None,
            "priv_lvl": result.priv_lvl,
            "command_decision": result.command_decision,
            "command_sets_granted": command_sets_granted,
        },
        "trace": [s.to_dict() for s in result.trace],
    }
