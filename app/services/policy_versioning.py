"""
app.services.policy_versioning
================================
PAM Expansion Plan §22. Snapshot/restore logic shared by
app.api.routes_policies (creates a version on every save) and
app.api.routes_policy_versions (list/diff/restore). Snapshots capture
NAMES, not raw ids, for referenced group/device/device-group/command-
sets -- so a version stays meaningful to read even if the thing it
referenced was later renamed or deleted. Restoring an old snapshot
re-resolves those names back to CURRENT ids; a name that no longer
exists is reported back to the caller as a warning and that one field
is left unset, rather than the whole restore silently pointing at
nothing or failing outright.
"""
from __future__ import annotations

import json

from sqlalchemy.orm import Session

from ..models.command_set import CommandSet
from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..models.group import TacacsGroup
from ..models.policy import Policy
from ..models.policy_command_set import PolicyCommandSet
from ..models.policy_version import PolicyVersion


def build_snapshot(db: Session, policy: Policy) -> dict:
    group = db.query(TacacsGroup).filter(TacacsGroup.id == policy.condition_group_id).first() if policy.condition_group_id else None
    device = db.query(NetworkDevice).filter(NetworkDevice.id == policy.condition_device_id).first() if policy.condition_device_id else None
    device_group = db.query(DeviceGroup).filter(DeviceGroup.id == policy.condition_device_group_id).first() if policy.condition_device_group_id else None

    joins = (
        db.query(PolicyCommandSet)
        .filter(PolicyCommandSet.policy_id == policy.id)
        .order_by(PolicyCommandSet.order.asc())
        .all()
    )
    command_set_names = []
    for j in joins:
        cs = db.query(CommandSet).filter(CommandSet.id == j.command_set_id).first()
        if cs:
            command_set_names.append(cs.name)

    return {
        "name": policy.name,
        "description": policy.description,
        "enabled": policy.enabled,
        "priority": policy.priority,
        "condition_group_name": group.name if group else None,
        "condition_device_name": device.name if device else None,
        "condition_device_group_name": device_group.name if device_group else None,
        "default_priv_lvl": policy.default_priv_lvl,
        "default_action": policy.default_action,
        "command_set_names": command_set_names,
    }


def record_version(
    db: Session,
    policy: Policy,
    *,
    created_by: str | None,
    change_description: str | None = None,
) -> PolicyVersion:
    """
    Called after `policy` has an id (post-flush) and its
    PolicyCommandSet rows are already written for this save. Flushes
    but does NOT commit -- the caller's own commit() covers this row
    too, so a version and the policy state it describes are always
    persisted atomically together, never one without the other.
    """
    last = (
        db.query(PolicyVersion)
        .filter(PolicyVersion.policy_id == policy.id)
        .order_by(PolicyVersion.version_number.desc())
        .first()
    )
    next_number = (last.version_number + 1) if last else 1

    version = PolicyVersion(
        policy_id=policy.id,
        version_number=next_number,
        snapshot=json.dumps(build_snapshot(db, policy)),
        change_description=change_description,
        created_by=created_by,
    )
    db.add(version)
    db.flush()
    return version


def resolve_snapshot_for_restore(db: Session, snapshot: dict) -> tuple[dict, list[str]]:
    """Re-resolves a snapshot's names back to CURRENT ids for a
    restore. Returns (resolved_fields, warnings)."""
    warnings: list[str] = []
    resolved: dict = {
        "condition_group_id": None,
        "condition_device_id": None,
        "condition_device_group_id": None,
        "command_set_ids": [],
    }

    if snapshot.get("condition_group_name"):
        g = db.query(TacacsGroup).filter(TacacsGroup.name == snapshot["condition_group_name"]).first()
        if g:
            resolved["condition_group_id"] = str(g.id)
        else:
            warnings.append(f"Group '{snapshot['condition_group_name']}' no longer exists -- that condition was dropped.")

    if snapshot.get("condition_device_name"):
        d = db.query(NetworkDevice).filter(NetworkDevice.name == snapshot["condition_device_name"]).first()
        if d:
            resolved["condition_device_id"] = str(d.id)
        else:
            warnings.append(f"Device '{snapshot['condition_device_name']}' no longer exists -- that condition was dropped.")

    if snapshot.get("condition_device_group_name"):
        dg = db.query(DeviceGroup).filter(DeviceGroup.name == snapshot["condition_device_group_name"]).first()
        if dg:
            resolved["condition_device_group_id"] = str(dg.id)
        else:
            warnings.append(f"Device group '{snapshot['condition_device_group_name']}' no longer exists -- that condition was dropped.")

    for name in snapshot.get("command_set_names", []):
        cs = db.query(CommandSet).filter(CommandSet.name == name).first()
        if cs:
            resolved["command_set_ids"].append(str(cs.id))
        else:
            warnings.append(f"Command set '{name}' no longer exists -- it was dropped from the restored policy.")

    return resolved, warnings
