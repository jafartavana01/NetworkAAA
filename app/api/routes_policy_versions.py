"""
app.api.routes_policy_versions
================================
PAM Expansion Plan §22: list a policy's version history, diff any
version against its policy's current live state, and restore an old
version. Restore follows the same established pattern as Config
restore (spec section 15): re-applying an old version's values
creates a NEW version rather than deleting anything after it, so
history only ever grows, never gets rewritten.
"""
from __future__ import annotations

import json
import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.policy import Policy
from ..models.policy_command_set import PolicyCommandSet
from ..models.policy_version import PolicyVersion
from ..services import policy_versioning
from .deps import get_current_admin, verify_csrf
from .routes_policies import policy_to_out

router = APIRouter(prefix="/api/policies", tags=["policy-versions"])


def _version_to_dict(v: PolicyVersion) -> dict:
    return {
        "id": str(v.id),
        "version_number": v.version_number,
        "snapshot": json.loads(v.snapshot),
        "change_description": v.change_description,
        "created_by": v.created_by,
        "created_at": v.created_at.isoformat(),
    }


def _get_policy_or_404(db: Session, policy_id: str) -> Policy:
    try:
        parsed_id = uuid.UUID(policy_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Policy not found.")
    policy = db.query(Policy).filter(Policy.id == parsed_id).first()
    if not policy:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Policy not found.")
    return policy


@router.get("/{policy_id}/versions")
def list_policy_versions(
    policy_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    policy = _get_policy_or_404(db, policy_id)
    versions = (
        db.query(PolicyVersion)
        .filter(PolicyVersion.policy_id == policy.id)
        .order_by(PolicyVersion.version_number.desc())
        .all()
    )
    return {"versions": [_version_to_dict(v) for v in versions]}


@router.get("/{policy_id}/versions/{version_id}/diff")
def diff_policy_version(
    policy_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    """Diffs one version's snapshot against the policy's CURRENT live
    state (built fresh via the same build_snapshot() the version
    itself was created from, so the two sides are always comparable
    field-for-field)."""
    policy = _get_policy_or_404(db, policy_id)
    try:
        parsed_version_id = uuid.UUID(version_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Version not found.")
    version = db.query(PolicyVersion).filter(PolicyVersion.id == parsed_version_id, PolicyVersion.policy_id == policy.id).first()
    if not version:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Version not found.")

    old_snapshot = json.loads(version.snapshot)
    current_snapshot = policy_versioning.build_snapshot(db, policy)

    all_keys = sorted(set(old_snapshot) | set(current_snapshot))
    changes = []
    for key in all_keys:
        old_val = old_snapshot.get(key)
        new_val = current_snapshot.get(key)
        if old_val != new_val:
            changes.append({"field": key, "from": old_val, "to": new_val})

    return {
        "version_number": version.version_number,
        "changed": changes,
        "identical": len(changes) == 0,
    }


@router.post("/{policy_id}/versions/{version_id}/restore", dependencies=[Depends(verify_csrf)])
def restore_policy_version(
    policy_id: str,
    version_id: str,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_admin),
):
    """Applies an old version's snapshot onto the live policy, then
    records that as a brand-new version -- history only grows, per
    §22's explicit "do not destroy historical versions." A name in
    the snapshot (group/device/device-group/command-set) that no
    longer exists is dropped from the restored policy with a warning
    returned to the caller, rather than failing the whole restore."""
    policy = _get_policy_or_404(db, policy_id)
    try:
        parsed_version_id = uuid.UUID(version_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Version not found.")
    version = db.query(PolicyVersion).filter(PolicyVersion.id == parsed_version_id, PolicyVersion.policy_id == policy.id).first()
    if not version:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Version not found.")

    snapshot = json.loads(version.snapshot)
    resolved, warnings = policy_versioning.resolve_snapshot_for_restore(db, snapshot)

    policy.description = snapshot.get("description")
    policy.enabled = snapshot.get("enabled", True)
    policy.priority = snapshot.get("priority", 100)
    policy.condition_group_id = uuid.UUID(resolved["condition_group_id"]) if resolved["condition_group_id"] else None
    policy.condition_device_id = uuid.UUID(resolved["condition_device_id"]) if resolved["condition_device_id"] else None
    policy.condition_device_group_id = uuid.UUID(resolved["condition_device_group_id"]) if resolved["condition_device_group_id"] else None
    policy.default_priv_lvl = snapshot.get("default_priv_lvl", 1)
    policy.default_action = snapshot.get("default_action", "deny")
    # NOTE: policy.name is deliberately NOT restored -- the name is
    # this policy's own stable identifier (and the tac_plus-ng profile
    # identifier the compiler emits); restoring old field VALUES onto
    # the current, still-named policy is the useful "undo a mistake"
    # operation. Renaming as a side effect of restoring an unrelated
    # field would be surprising.

    db.query(PolicyCommandSet).filter(PolicyCommandSet.policy_id == policy.id).delete()
    for order, cs_id in enumerate(resolved["command_set_ids"]):
        db.add(PolicyCommandSet(policy_id=policy.id, command_set_id=uuid.UUID(cs_id), order=order))

    db.flush()
    policy_versioning.record_version(
        db, policy, created_by=admin.username,
        change_description=f"Restored from version {version.version_number}",
    )
    db.commit()
    db.refresh(policy)

    return {"policy": policy_to_out(db, policy), "warnings": warnings}
