"""
app.services.identity_resolver
=================================
Resolves a username to the group the policy engine should evaluate
against -- whether that user is local or comes from Active Directory.

Why this exists: the Policy Simulator and Effective Access both looked
the username up in `TacacsUser` only. An AD-authenticated user has no
row in that table, so both tools reported "user not found" for exactly
the people whose access an administrator most needs to check. The
authorization path itself has always handled AD users correctly, which
made the discrepancy worse: the tools disagreed with the thing they
were meant to predict.

Resolution order mirrors what actually happens at authentication time:

  1. A local `TacacsUser` row, if one exists. Local users take
     precedence in the daemon's own configuration, so they take
     precedence here.
  2. Otherwise an LDAP lookup of the user's group memberships, mapped
     onto this platform's groups by `ad_group_name` (falling back to
     the group name, since a group may be named after its AD
     counterpart without the field being set).

An AD user in several mapped groups is reported with ALL of them, and
the first is used for evaluation. Silently picking one and not saying
so would hide the ambiguity that caused the surprise in the first
place.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from ..models.ad_settings import AdSettings
from ..models.group import TacacsGroup
from ..models.user import TacacsUser


@dataclass
class ResolvedIdentity:
    found: bool
    username: str
    source: str = "none"                 # local | active_directory | none
    user: object | None = None           # TacacsUser, when local
    group: object | None = None          # TacacsGroup used for evaluation
    #: Every mapped group, when AD reports membership of more than one.
    all_groups: list = field(default_factory=list)
    #: Group names AD reported that this platform has no group for --
    #: shown so an unmapped AD group is visible rather than silently
    #: ignored.
    unmapped_ad_groups: list = field(default_factory=list)
    detail: str = ""


def _map_ad_groups(db: Session, reported: list) -> tuple[list, list]:
    """Maps AD group names onto TacacsGroups by `ad_group_name` first,
    then by plain name. Returns (matched groups, unmatched names)."""
    if not reported:
        return [], []

    groups = db.query(TacacsGroup).all()
    by_ad_name = {g.ad_group_name.strip().lower(): g for g in groups if g.ad_group_name}
    by_name = {g.name.strip().lower(): g for g in groups}

    matched, unmatched = [], []
    for name in reported:
        key = (name or "").strip().lower()
        if not key:
            continue
        group = by_ad_name.get(key) or by_name.get(key)
        if group is not None:
            if group not in matched:
                matched.append(group)
        else:
            unmatched.append(name)
    return matched, unmatched


def resolve_username(db: Session, username: str) -> ResolvedIdentity:
    username = (username or "").strip()
    if not username:
        return ResolvedIdentity(found=False, username="", detail="No username supplied.")

    local = db.query(TacacsUser).filter(TacacsUser.username == username).first()
    if local is not None:
        group = (
            db.query(TacacsGroup).filter(TacacsGroup.id == local.group_id).first()
            if local.group_id else None
        )
        return ResolvedIdentity(
            found=True, username=username, source="local", user=local, group=group,
            all_groups=[group] if group else [],
            detail="Local user." + ("" if group else " This user is not in any group."),
        )

    settings = db.query(AdSettings).first()
    if not settings or not settings.enabled:
        return ResolvedIdentity(
            found=False, username=username,
            detail="No local user with that name, and Active Directory is not enabled.",
        )

    try:
        from . import ad_directory
        memberships = ad_directory.get_user_group_memberships(settings, username)
    except Exception as exc:  # noqa: BLE001 - an LDAP failure must not 500 the page
        return ResolvedIdentity(
            found=False, username=username,
            detail=f"Active Directory lookup failed: {exc}",
        )

    if not memberships:
        return ResolvedIdentity(
            found=False, username=username,
            detail="No local user with that name, and Active Directory returned no match.",
        )

    reported = memberships.get("reported_groups") or []
    matched, unmatched = _map_ad_groups(db, reported)

    if not matched:
        return ResolvedIdentity(
            found=True, username=username, source="active_directory",
            unmapped_ad_groups=unmatched,
            detail=(
                "Found in Active Directory, but none of its groups map to a group on this "
                "platform, so no policy will match on group membership."
            ),
        )

    note = ""
    if len(matched) > 1:
        # Stated rather than silently resolved: which group wins changes
        # the answer, so the operator needs to see the ambiguity.
        note = (
            f" This user maps to {len(matched)} groups "
            f"({', '.join(g.name for g in matched)}); the first is used for evaluation."
        )

    return ResolvedIdentity(
        found=True, username=username, source="active_directory",
        group=matched[0], all_groups=matched, unmapped_ad_groups=unmatched,
        detail="Resolved through Active Directory." + note,
    )


@dataclass
class EvaluationSubject:
    """
    The minimum the policy engine reads from a user: `username` and
    `group_id`. An AD-authenticated user has no `TacacsUser` row, so
    rather than fabricate one -- which would risk it being persisted,
    counted, or shown as a local account -- this stand-in supplies
    exactly those two attributes and nothing else.

    Verified against policy_engine.evaluate and condition_engine: they
    read `username`, `group_id` and `id`, and nothing else.

    `id` is deliberately None. It is used only to match a policy
    condition that names one SPECIFIC local user, and an AD-backed
    identity is not that user -- so such a condition should not match,
    and None is the correct answer rather than a missing attribute or
    a borrowed id.
    """
    username: str
    group_id: object | None
    id: object | None = None


def evaluation_subject(identity: ResolvedIdentity):
    """The object to hand to `policy_engine.evaluate(user=...)`.

    Returns the real TacacsUser for a local account, a stand-in for an
    AD account, or None when nothing resolved -- which the engine
    already treats as "no user", its established unmatched-means-denied
    path.
    """
    if identity.user is not None:
        return identity.user
    if not identity.found:
        return None
    return EvaluationSubject(
        username=identity.username,
        group_id=identity.group.id if identity.group else None,
    )
