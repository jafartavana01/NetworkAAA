"""
app.services.entitlements
============================
The single place the rest of the application asks "are we allowed to
do this".

    license file -> verify signature -> Entitlements -> limits/features

No module reads a license, and no module asks "are we Community?". They
ask for a limit or a feature by key. That keeps the commercial model in
`editions.py` and out of the application, which is what makes it
changeable later without a hunt through the codebase.

Two design points worth stating:

**Limits come from the SIGNED payload, not from the edition table.**
The edition is a label; the numbers are what was signed. A customer who
bought "Professional, 25 devices" keeps 25 even if a later release
redefines Professional, because their license says 25.

**Grandfathering.** An existing installation that upgrades into
licensing may already hold more devices than Community allows. Deleting
them would be indefensible, so devices that already exist keep working
and the excess is recorded once. New additions are blocked until the
count is back within the limit or a license is imported. The License
page states this rather than leaving the operator to infer it.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from ..models.device import NetworkDevice
from ..models.license import PlatformLicense
from . import editions, license_verify, machine_fingerprint


@dataclass
class Entitlements:
    edition_key: str
    edition_name: str
    device_limit: int | None            # None = unlimited
    admin_limit: int | None
    features: frozenset
    licensed: bool                      # a verified license is installed
    customer: str | None = None
    expires_at: datetime | None = None
    license_id: str | None = None
    fingerprint: str = ""
    development_key: bool = False
    #: Populated when a license is present but NOT usable, so the UI can
    #: explain why the installation fell back to Community instead of
    #: silently appearing unlicensed.
    problem: str = ""
    grandfathered_device_count: int = 0

    def has_feature(self, key: str) -> bool:
        return key in self.features

    def feature_list(self) -> list:
        """Every known feature with its availability, for display."""
        return [
            {
                "key": f.key, "name": f.name, "description": f.description,
                "included": f.key in self.features, "module_key": f.module_key,
            }
            for f in editions.FEATURES
        ]


def _get_or_create_row(db: Session) -> PlatformLicense:
    row = db.query(PlatformLicense).first()
    if row is None:
        row = PlatformLicense()
        db.add(row)
        db.commit()
        db.refresh(row)
    return row


def _effective_now(db: Session, row: PlatformLicense) -> datetime:
    """
    The time expiry is judged against.

    Only ever moves forward. If the system clock is behind the highest
    time this installation has ever seen, the stored high-water mark is
    used instead -- so winding the clock back does not revive an expired
    license. It does not stop someone moving the clock FORWARD (which
    only harms them) and it cannot survive a database restore, which is
    noted in the security review rather than papered over.
    """
    now = datetime.now(timezone.utc)
    highest = row.highest_seen_utc
    if highest is not None and highest.tzinfo is None:
        highest = highest.replace(tzinfo=timezone.utc)

    if highest is None or now > highest:
        row.highest_seen_utc = now
        try:
            db.commit()
        except Exception:
            db.rollback()
        return now
    return highest


def _community(problem: str = "", grandfathered: int = 0) -> Entitlements:
    edition = editions.DEFAULT_EDITION
    return Entitlements(
        edition_key=edition.key, edition_name=edition.name,
        device_limit=edition.device_limit, admin_limit=edition.admin_limit,
        features=edition.features, licensed=False, problem=problem,
        grandfathered_device_count=grandfathered,
    )


def current(db: Session) -> Entitlements:
    """
    The installation's entitlements right now.

    Re-verifies the stored license on every call rather than trusting a
    cached row. That is deliberate: it means editing the cached columns
    in the database achieves nothing, and it costs one Ed25519
    verification, which is microseconds.
    """
    row = _get_or_create_row(db)
    grandfathered = row.grandfathered_device_count or 0

    if not row.license_text:
        return _community(grandfathered=grandfathered)

    status = license_verify.verify(row.license_text, now=_effective_now(db, row))
    if not status.valid:
        # A bad license does NOT disable the platform -- it falls back
        # to Community and says why. Taking a running installation
        # offline because a license expired would be a hostile way to
        # treat a paying customer whose renewal is in the post.
        return _community(problem=status.reason, grandfathered=grandfathered)

    payload = status.payload

    # Machine binding. A licence issued for one machine must not work
    # on another, but a hardware change on the SAME machine must not
    # lock a paying customer out -- see machine_fingerprint for the
    # tolerance rule. A mismatch falls back to Community with an
    # explanation rather than disabling the platform, exactly as an
    # expired licence does.
    binding = machine_fingerprint.check_binding(payload.get("machine"))
    if not binding.ok:
        return _community(problem=binding.reason, grandfathered=grandfathered)

    edition = editions.get_edition(payload.get("edition"))

    expires = None
    if payload.get("expires_at"):
        try:
            expires = datetime.fromisoformat(payload["expires_at"])
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        except ValueError:
            expires = None

    # Signed values win; the edition table is only a fallback for a
    # license that omitted a field.
    device_limit = payload.get("device_limit", edition.device_limit)
    admin_limit = payload.get("admin_limit", edition.admin_limit)
    features = frozenset(payload.get("features") or edition.features)

    return Entitlements(
        edition_key=edition.key, edition_name=edition.name,
        device_limit=device_limit, admin_limit=admin_limit,
        features=features, licensed=True,
        customer=payload.get("customer"), expires_at=expires,
        license_id=payload.get("license_id"),
        fingerprint=license_verify.fingerprint(row.license_text),
        development_key=status.development_key,
        grandfathered_device_count=grandfathered,
    )


# ---------------------------------------------------------------- devices

def device_count(db: Session) -> int:
    """
    What counts as a licensed device: every row in the inventory,
    INCLUDING disabled ones.

    Counting only enabled devices would make "disable to free a slot" a
    one-click bypass. Counting existing rows (rather than a high-water
    mark of every device ever created) means replacing a failed switch
    costs nothing, which is the behaviour an operator expects -- the
    trade-off is that someone can cycle WHICH devices they manage, but
    never how many at once, which is what the license actually sells.
    """
    return db.query(NetworkDevice).count()


@dataclass
class LimitCheck:
    allowed: bool
    reason: str = ""
    current: int = 0
    limit: int | None = None


def check_can_add_device(db: Session, *, adding: int = 1) -> LimitCheck:
    ent = current(db)
    count = device_count(db)

    if ent.device_limit is None:
        return LimitCheck(allowed=True, current=count, limit=None)

    # Grandfathered headroom: an installation that already exceeded the
    # limit before licensing applied is not blocked from getting back to
    # normal, but cannot grow.
    effective_limit = max(ent.device_limit, ent.grandfathered_device_count)

    if count + adding <= effective_limit:
        return LimitCheck(allowed=True, current=count, limit=ent.device_limit)

    if ent.grandfathered_device_count > ent.device_limit and count >= ent.device_limit:
        reason = (
            f"This installation has {count} devices, above the {ent.edition_name} limit of "
            f"{ent.device_limit}. Existing devices keep working, but new ones cannot be added "
            f"until the count is back within the limit or a larger license is imported."
        )
    elif adding > 1:
        reason = (
            f"Adding {adding} devices would exceed the {ent.edition_name} limit of "
            f"{ent.device_limit} ({count} in use). Import a license to raise it."
        )
    else:
        reason = (
            f"The {ent.edition_name} limit of {ent.device_limit} devices has been reached. "
            f"Remove a device, or import a license to raise the limit."
        )
    return LimitCheck(allowed=False, reason=reason, current=count, limit=ent.device_limit)


# ----------------------------------------------------------------- admins

def admin_count(db: Session) -> int:
    from ..models.admin import AdminUser

    return db.query(AdminUser).count()


def check_can_add_admin(db: Session) -> LimitCheck:
    ent = current(db)
    count = admin_count(db)
    if ent.admin_limit is None:
        return LimitCheck(allowed=True, current=count, limit=None)
    if count + 1 <= ent.admin_limit:
        return LimitCheck(allowed=True, current=count, limit=ent.admin_limit)
    return LimitCheck(
        allowed=False, current=count, limit=ent.admin_limit,
        reason=(
            f"The {ent.edition_name} edition allows {ent.admin_limit} administrator"
            f"{'' if ent.admin_limit == 1 else 's'}. Import a license to add more."
        ),
    )


# ---------------------------------------------------------------- features

def has_feature(db: Session, key: str) -> bool:
    return current(db).has_feature(key)


def enabled_module_keys(db: Session) -> set:
    """
    Module keys the current entitlements allow.

    Used alongside the existing Module Management setting, not instead
    of it: a module is mounted when it is BOTH licensed and enabled.
    Licensing removes a module from the product; Module Management is
    the operator's own choice about what they run.
    """
    ent = current(db)
    allowed = set()
    for feature in editions.FEATURES:
        if feature.module_key and ent.has_feature(feature.key):
            allowed.add(feature.module_key)
    return allowed


def licence_limit_for_connection(connection) -> int | None:
    """
    The effective device limit, read through a raw SQLAlchemy
    connection rather than an ORM Session.

    Used only by the `before_insert` backstop in models.device, which
    runs during flush where opening a second Session would deadlock
    against the transaction already in progress.

    Returns None -- meaning "do not enforce" -- whenever the limit
    cannot be established: no licence row yet, an unreadable licence, or
    any error. That direction is deliberate. This hook is a backstop
    against a forgotten check in new code, not the primary control, and
    a backstop that fails CLOSED would take a working installation
    offline over a transient database condition. The explicit checks in
    the request handlers remain the real enforcement.
    """
    try:
        from sqlalchemy import select

        from ..models.license import PlatformLicense

        row = connection.execute(
            select(
                PlatformLicense.__table__.c.license_text,
                PlatformLicense.__table__.c.grandfathered_device_count,
            )
        ).first()

        if row is None:
            edition = editions.DEFAULT_EDITION
            return edition.device_limit

        license_text, grandfathered = row[0], row[1] or 0

        if not license_text:
            limit = editions.DEFAULT_EDITION.device_limit
        else:
            status = license_verify.verify(license_text)
            if not status.valid:
                limit = editions.DEFAULT_EDITION.device_limit
            else:
                limit = status.payload.get(
                    "device_limit", editions.get_edition(status.payload.get("edition")).device_limit
                )

        if limit is None:
            return None
        return max(int(limit), int(grandfathered))
    except Exception:
        return None
