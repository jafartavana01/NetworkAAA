"""
app.services.condition_engine
================================
The evaluator for the new condition-tree model (pasted spec §6, §13).
Coexists with the legacy flat-field model (Policy.condition_group_id /
condition_device_id / condition_device_group_id, implicitly AND'd) --
NEVER both for the same policy. `has_condition_tree()` is the single
switch: a policy with a root PolicyConditionGroup uses this engine
exclusively; a policy without one uses the legacy fields exclusively,
via app.services.policy_engine.policy_matches() exactly as it already
did before this module existed. Per the pasted spec's explicit
backward-compatibility requirement ("never silently change an
existing policy's authorization behavior"), migrating a policy to the
tree model is a deliberate, explicit action (see migrate_legacy_policy
below) -- nothing here runs automatically or changes what an
un-migrated policy does.

FAIL-CLOSED THROUGHOUT: a condition whose database-backed reference
no longer resolves to a real row, a request context missing the field
a condition needs (e.g. evaluating a device_group condition with no
device supplied at all), or a malformed CIDR/IP value all evaluate to
"does not match" -- never "matches everything" and never a crash. An
empty group (no children -- should not be reachable via valid API
input, since the API requires at least one child per group) also
evaluates to "does not match", the same conservative default, rather
than debating a logical convention for a case that should not occur
in valid data.

Every function returns a trace alongside its boolean result, sharing
policy_engine.TraceStep's exact shape -- so a condition-tree
evaluation and a legacy evaluation produce interchangeable trace
output for the Simulator, regardless of which path a given policy
took.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass

from sqlalchemy.orm import Session

from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup
from ..models.group import TacacsGroup
from ..models.policy import Policy
from ..models.policy_condition import PolicyCondition
from ..models.policy_condition_group import PolicyConditionGroup
from ..models.user import TacacsUser
from .policy_engine import TraceStep


@dataclass
class RequestContext:
    """Everything the condition tree can evaluate against. `source_ip`
    is new -- the legacy flat-field model has no equivalent, since it
    predates ACL/nac-based matching being wired into the Policy model
    at all."""
    user: TacacsUser | None = None
    device: NetworkDevice | None = None
    source_ip: str | None = None


def has_condition_tree(db: Session, policy: Policy) -> bool:
    """The single switch between the new tree engine and the legacy
    flat-field engine for a given policy -- see module docstring."""
    return (
        db.query(PolicyConditionGroup)
        .filter(PolicyConditionGroup.policy_id == policy.id, PolicyConditionGroup.parent_group_id.is_(None))
        .first()
        is not None
    )


def get_root_group(db: Session, policy: Policy) -> PolicyConditionGroup | None:
    return (
        db.query(PolicyConditionGroup)
        .filter(PolicyConditionGroup.policy_id == policy.id, PolicyConditionGroup.parent_group_id.is_(None))
        .first()
    )


def _object_display_name(db: Session, condition: PolicyCondition) -> str:
    """For trace messages only -- falls back to the cached `value` if
    the referenced row is gone (see module docstring on fail-closed
    behavior; this is purely cosmetic, not the actual match logic)."""
    return condition.value


def evaluate_condition(db: Session, condition: PolicyCondition, context: RequestContext) -> tuple[bool, TraceStep]:
    """
    Evaluates ONE leaf condition. Database-backed object types
    (user/user_group/device/device_group) compare by
    `referenced_object_id` -- the real, authoritative reference, not
    the cached display name -- against the corresponding id on the
    request context. `source_ip` compares the request's own source_ip
    string against the condition's manual value, either as an exact
    match or CIDR membership.

    A request context missing the relevant field entirely (e.g. no
    device supplied while evaluating a `device` condition) makes BOTH
    `equal` and `not_equal` evaluate to False -- a deliberately
    conservative choice (see module docstring's FAIL-CLOSED note):
    "not equal to something absent" is not treated as trivially true,
    since that could let a negated condition match more broadly than
    intended whenever context is incomplete.
    """
    obj_type = condition.object_type
    op = condition.operator
    label = _object_display_name(db, condition)

    def make_step(matched: bool, actual_desc: str) -> TraceStep:
        return TraceStep(
            "condition",
            f"{obj_type} {op} '{label}' -- actual: {actual_desc} -- {'PASS' if matched else 'FAIL'}",
            matched,
        )

    if obj_type in ("user", "user_group", "device", "device_group"):
        if obj_type == "user":
            actual_id = context.user.id if context.user else None
            actual_desc = context.user.username if context.user else "(none)"
        elif obj_type == "user_group":
            actual_id = context.user.group_id if context.user else None
            actual_desc = str(actual_id) if actual_id else "(none)"
        elif obj_type == "device":
            actual_id = context.device.id if context.device else None
            actual_desc = context.device.name if context.device else "(none)"
        else:  # device_group
            actual_id = context.device.device_group_id if context.device else None
            actual_desc = str(actual_id) if actual_id else "(none)"

        target_id = condition.referenced_object_id
        is_equal = actual_id is not None and target_id is not None and actual_id == target_id

        if op == "equal":
            return is_equal, make_step(is_equal, actual_desc)
        elif op == "not_equal":
            # Conservative: only a genuine, resolvable mismatch counts
            # as "not equal" -- an absent actual value does not.
            not_equal = actual_id is not None and target_id is not None and actual_id != target_id
            return not_equal, make_step(not_equal, actual_desc)
        else:
            return False, TraceStep("condition", f"Unsupported operator '{op}' for {obj_type} -- treated as no match.", False)

    elif obj_type == "source_ip":
        actual_ip = context.source_ip
        actual_desc = actual_ip or "(none)"

        if op in ("equal", "not_equal"):
            is_equal = actual_ip is not None and actual_ip == condition.value
            matched = is_equal if op == "equal" else (actual_ip is not None and not is_equal)
            return matched, make_step(matched, actual_desc)

        elif op in ("is_in_cidr", "is_not_in_cidr"):
            try:
                network = ipaddress.ip_network(condition.value, strict=False)
                is_in = actual_ip is not None and ipaddress.ip_address(actual_ip) in network
            except ValueError:
                # Malformed CIDR/IP -- fails closed (never matches),
                # per module docstring.
                is_in = False
            matched = is_in if op == "is_in_cidr" else (actual_ip is not None and not is_in)
            return matched, make_step(matched, actual_desc)
        else:
            return False, TraceStep("condition", f"Unsupported operator '{op}' for source_ip -- treated as no match.", False)

    return False, TraceStep("condition", f"Unknown object type '{obj_type}' -- treated as no match.", False)


def evaluate_group(db: Session, group: PolicyConditionGroup, context: RequestContext) -> tuple[bool, list[TraceStep]]:
    """
    Recursively evaluates a group: every direct child condition AND
    every direct child group are evaluated, then combined per this
    group's own logical_operator. NOT negates the AND-combination of
    its children (see app.models.policy_condition_group's docstring
    for why NOT is defined this way rather than requiring exactly one
    child).
    """
    trace: list[TraceStep] = []
    trace.append(TraceStep("group", f"Evaluating {group.logical_operator} group.", None))

    child_conditions = (
        db.query(PolicyCondition).filter(PolicyCondition.group_id == group.id).order_by(PolicyCondition.order.asc()).all()
    )
    child_groups = (
        db.query(PolicyConditionGroup)
        .filter(PolicyConditionGroup.parent_group_id == group.id)
        .order_by(PolicyConditionGroup.order.asc())
        .all()
    )

    results: list[bool] = []
    for cond in child_conditions:
        matched, step = evaluate_condition(db, cond, context)
        trace.append(step)
        results.append(matched)
    for child_group in child_groups:
        matched, child_trace = evaluate_group(db, child_group, context)
        trace.extend(child_trace)
        results.append(matched)

    if not results:
        # Should not be reachable via valid API input (a group must
        # have at least one child to be saved) -- fails closed if it
        # somehow occurs rather than debating a logical convention for
        # invalid data.
        group_result = False
    elif group.logical_operator == "AND":
        group_result = all(results)
    elif group.logical_operator == "OR":
        group_result = any(results)
    elif group.logical_operator == "NOT":
        group_result = not all(results)
    else:
        group_result = False

    trace.append(TraceStep(
        "group_result", f"{group.logical_operator} group ({len(results)} child result(s)) -> {group_result}.", group_result
    ))
    return group_result, trace


def evaluate_policy_condition_tree(db: Session, policy: Policy, context: RequestContext) -> tuple[bool, list[TraceStep]]:
    """Entry point for a policy that HAS a condition tree
    (has_condition_tree() must be checked by the caller first --
    app.services.policy_engine.evaluate() does this and falls back to
    the legacy evaluator otherwise)."""
    root = get_root_group(db, policy)
    if root is None:
        return False, [TraceStep("no_tree", "No condition tree found for this policy.", False)]
    return evaluate_group(db, root, context)


def migrate_legacy_policy(db: Session, policy: Policy) -> PolicyConditionGroup:
    """
    Converts a policy's existing legacy fields (condition_group_id /
    condition_device_id / condition_device_group_id -- implicitly
    AND'd, exactly matching a root AND group with one leaf condition
    per non-null field) into an equivalent new-model tree. Lossless
    and exact: the resulting tree evaluates identically to what
    policy_matches() already did for this policy, for every possible
    request -- this is a pure representation change, not a behavior
    change, which is exactly what the pasted spec's backward-
    compatibility requirement calls for ("automatically migrated
    correctly" as one of its two explicitly acceptable outcomes).

    A policy with NO legacy conditions at all (matches unconditionally
    -- see app/models/policy.py) migrates to an empty-bodied AND group.
    Per this module's fail-closed default for an empty group, that
    would incorrectly turn an unconditional policy into one that never
    matches -- so this specific case is handled separately: an
    "always true" placeholder isn't representable as zero children
    under the current fail-closed-on-empty design, so migrating a
    genuinely unconditional policy is refused with a clear error
    instead of silently producing wrong behavior. (A future increment
    could add an explicit "always match" leaf condition type for this
    case; not added speculatively here.)

    Raises ValueError if the policy already has a condition tree (call
    has_condition_tree() first) or has no legacy conditions to migrate.
    Does NOT delete the legacy fields -- they simply stop being read
    once has_condition_tree() returns True for this policy, so nothing
    is destroyed and the migration is inspectable/reversible by simply
    deleting the new tree rows.
    """
    if has_condition_tree(db, policy):
        raise ValueError(f"Policy '{policy.name}' already has a condition tree -- nothing to migrate.")

    if policy.condition_group_id is None and policy.condition_device_id is None and policy.condition_device_group_id is None:
        raise ValueError(
            f"Policy '{policy.name}' has no legacy conditions (it matches unconditionally) -- "
            "there is nothing meaningful to migrate yet; an 'always match' condition type "
            "would be needed to represent this in the new model, and doesn't exist yet."
        )

    root = PolicyConditionGroup(policy_id=policy.id, parent_group_id=None, logical_operator="AND", order=0)
    db.add(root)
    db.flush()

    order = 0
    if policy.condition_group_id is not None:
        group = db.query(TacacsGroup).filter(TacacsGroup.id == policy.condition_group_id).first()
        db.add(PolicyCondition(
            group_id=root.id, object_type="user_group", operator="equal", value_type="database_id",
            value=group.name if group else "(deleted group)", referenced_object_id=policy.condition_group_id, order=order,
        ))
        order += 1
    if policy.condition_device_id is not None:
        device = db.query(NetworkDevice).filter(NetworkDevice.id == policy.condition_device_id).first()
        db.add(PolicyCondition(
            group_id=root.id, object_type="device", operator="equal", value_type="database_id",
            value=device.name if device else "(deleted device)", referenced_object_id=policy.condition_device_id, order=order,
        ))
        order += 1
    if policy.condition_device_group_id is not None:
        device_group = db.query(DeviceGroup).filter(DeviceGroup.id == policy.condition_device_group_id).first()
        db.add(PolicyCondition(
            group_id=root.id, object_type="device_group", operator="equal", value_type="database_id",
            value=device_group.name if device_group else "(deleted device group)",
            referenced_object_id=policy.condition_device_group_id, order=order,
        ))
        order += 1

    return root
