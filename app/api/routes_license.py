"""
app.api.routes_license
=========================
Licence status and import.

Superadmin-only: entitlements govern the whole installation, so this is
platform administration rather than day-to-day work.

Nothing here returns key material, the raw licence text, or anything
that would help forge a licence. The fingerprint shown is a truncated
hash of a public signature -- useful for support ("which licence is
installed?") and useless for anything else.
"""
from __future__ import annotations

from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.license import PlatformLicense
from ..services import editions, entitlements, license_verify, machine_fingerprint
from .deps import get_current_superadmin, verify_csrf

router = APIRouter(prefix="/api/license", tags=["license"])


class FeatureOut(BaseModel):
    key: str
    name: str
    description: str
    included: bool


class LicenseStatusOut(BaseModel):
    edition_key: str
    edition_name: str
    edition_description: str
    licensed: bool
    customer: str | None
    license_id: str | None
    fingerprint: str
    expires_at: datetime | None
    days_remaining: int | None
    development_key: bool
    #: Set when a licence is installed but unusable, so the UI explains
    #: the fallback instead of appearing merely unlicensed.
    problem: str

    machine_short_id: str
    machine_bound: bool

    device_limit: int | None
    device_count: int
    admin_limit: int | None
    admin_count: int
    grandfathered_device_count: int
    at_device_limit: bool
    device_limit_message: str

    features: list[FeatureOut]
    editions_available: list


class LicenseImportRequest(BaseModel):
    license_text: str = Field(min_length=1, max_length=20000)


def _is_bound(db: Session) -> bool:
    """Whether the INSTALLED licence is tied to this machine. Read from
    the verified payload, never from a cached column."""
    row = db.query(PlatformLicense).first()
    if row is None or not row.license_text:
        return False
    result = license_verify.verify(row.license_text)
    return bool(result.valid and result.payload.get("machine"))


def _status_payload(db: Session) -> LicenseStatusOut:
    ent = entitlements.current(db)
    edition = editions.get_edition(ent.edition_key)
    device_check = entitlements.check_can_add_device(db)

    days = None
    if ent.expires_at:
        delta = ent.expires_at - datetime.now(timezone.utc)
        days = max(0, delta.days)

    return LicenseStatusOut(
        edition_key=ent.edition_key, edition_name=ent.edition_name,
        edition_description=edition.description,
        licensed=ent.licensed, customer=ent.customer, license_id=ent.license_id,
        fingerprint=ent.fingerprint, expires_at=ent.expires_at, days_remaining=days,
        development_key=ent.development_key, problem=ent.problem,
        machine_short_id=machine_fingerprint.collect().short_id(),
        machine_bound=_is_bound(db),
        device_limit=ent.device_limit, device_count=entitlements.device_count(db),
        admin_limit=ent.admin_limit, admin_count=entitlements.admin_count(db),
        grandfathered_device_count=ent.grandfathered_device_count,
        at_device_limit=not device_check.allowed,
        device_limit_message=device_check.reason,
        features=[FeatureOut(**{k: v for k, v in f.items() if k != "module_key"})
                  for f in ent.feature_list()],
        editions_available=[
            {
                "key": e.key, "name": e.name, "description": e.description,
                "device_limit": e.device_limit, "admin_limit": e.admin_limit,
                "features": sorted(e.features),
                "current": e.key == ent.edition_key,
            }
            for e in (editions.COMMUNITY, editions.PROFESSIONAL, editions.BUSINESS, editions.ENTERPRISE)
        ],
    )


@router.get("", response_model=LicenseStatusOut)
def license_status(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    return _status_payload(db)


@router.post("/import", response_model=LicenseStatusOut, dependencies=[Depends(verify_csrf)])
def import_license(
    payload: LicenseImportRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(get_current_superadmin),
):
    """
    Verifies a licence and installs it.

    Verified BEFORE being stored, so an invalid licence never replaces a
    working one. An operator pasting the wrong file should get an error,
    not a downgrade to Community with their real licence overwritten.
    """
    text = payload.license_text.strip()
    result = license_verify.verify(text)
    if not result.valid:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=result.reason)

    row = db.query(PlatformLicense).first()
    if row is None:
        row = PlatformLicense()
        db.add(row)

    verified = result.payload
    row.license_text = text
    # Cached for display only; every enforcement decision re-verifies
    # the stored text, so editing these columns changes nothing.
    row.cached_edition = verified.get("edition")
    row.cached_customer = verified.get("customer")
    row.cached_device_limit = verified.get("device_limit")
    row.imported_by = admin.username
    row.imported_at = datetime.now(timezone.utc)

    expires = verified.get("expires_at")
    if expires:
        try:
            parsed = datetime.fromisoformat(expires)
            row.cached_expires_at = parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            row.cached_expires_at = None
    else:
        row.cached_expires_at = None

    db.commit()
    return _status_payload(db)


@router.post("/remove", response_model=LicenseStatusOut, dependencies=[Depends(verify_csrf)])
def remove_license(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    """
    Returns the installation to Community.

    Devices and data are untouched -- only entitlements change. An
    installation left above the Community device limit keeps its
    devices and is blocked from adding more, exactly as an upgraded
    installation would be.
    """
    row = db.query(PlatformLicense).first()
    if row is not None and row.license_text:
        # The excess is recorded so existing devices keep working rather
        # than becoming unusable the moment a licence is removed.
        count = entitlements.device_count(db)
        community_limit = editions.COMMUNITY.device_limit or 0
        if count > community_limit:
            row.grandfathered_device_count = max(row.grandfathered_device_count or 0, count)
        row.license_text = None
        row.cached_edition = None
        row.cached_customer = None
        row.cached_device_limit = None
        row.cached_expires_at = None
        db.commit()
    return _status_payload(db)


@router.get("/request")
def download_license_request(
    contact: str = "",
    note: str = "",
    _admin: AdminUser = Depends(get_current_superadmin),
):
    """
    Generates this machine's licence request and returns it as a
    download.

    Saves the operator from finding a shell, locating the installation
    directory and running a script -- the three steps most likely to
    end in "how do I buy this?" going unanswered.

    One honest limitation is reported in the response rather than
    hidden: the service account cannot read the DMI system UUID, which
    needs root. A request generated here therefore carries one fewer
    identifying component than one produced by
    `sudo python3 collect_fingerprint.py`. Two components are enough to
    bind a licence, so this is usually fine -- but when it is NOT, the
    caller is told to use the script instead of discovering later that
    their licence will not verify.
    """
    import base64
    import hashlib
    import json
    import platform

    from ..services import machine_fingerprint

    fingerprint = machine_fingerprint.collect()
    body = {
        "format": 1,
        "kind": "netopsguard-license-request",
        "generated_at": datetime.now(timezone.utc).replace(microsecond=0).isoformat(),
        "short_id": fingerprint.short_id(),
        # Hashes only -- no raw hardware identifiers leave the machine.
        "machine": fingerprint.to_claim(),
        "components_available": fingerprint.available,
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "contact": contact.strip()[:200],
        "note": note.strip()[:500],
        "generated_by": "web-ui",
    }

    payload = json.dumps(body, separators=(",", ":"), sort_keys=True).encode("utf-8")
    checksum = hashlib.sha256(payload).hexdigest()[:16]
    encoded = base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")
    text = f"NETOPSGUARD-REQUEST-1.{checksum}.{encoded}\n"

    from fastapi.responses import Response

    return Response(
        content=text,
        media_type="text/plain",
        headers={
            "Content-Disposition": f'attachment; filename="netopsguard-{body["short_id"]}.request"',
            # Surfaced as a header so the page can warn without parsing
            # the file it just downloaded.
            "X-Components-Available": str(len(fingerprint.available)),
        },
    )
