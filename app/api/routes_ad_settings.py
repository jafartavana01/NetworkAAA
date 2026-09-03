"""
app.api.routes_ad_settings
=============================
Singleton-style settings resource (matching how platform network/TLS
settings already work) plus two DISTINCT connectivity checks -- see
app.services.ad_directory's docstring for exactly why they're kept
separate:

- POST /test: tests whatever is in the submitted form right now
  (including a password the admin just typed but hasn't saved),
  falling back to the stored encrypted password only when the form
  didn't include one -- so editing existing settings and clicking
  "Test" without retyping the password still works.
- GET /health: tests the currently SAVED settings specifically --
  the AD Health monitoring endpoint, callable on demand with no
  request body, using only what's already persisted.

Only a superadmin can view or change these settings -- an AD bind
account's credentials are exactly as sensitive as a device's shared
secret or another admin's account, all of which are already
superadmin-gated.
"""
from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..models.ad_settings import AdSettings
from ..schemas.ad_settings import AdSettingsOut, AdSettingsUpdate, AdTestRequest
from ..services import ad_directory
from .deps import get_current_superadmin, require_permission, verify_csrf

router = APIRouter(prefix="/api/ad-settings", tags=["ad-settings"])


def _get_or_create_settings(db: Session) -> AdSettings:
    settings = db.query(AdSettings).first()
    if settings is None:
        settings = AdSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


def _to_out(settings: AdSettings) -> AdSettingsOut:
    return AdSettingsOut(
        enabled=settings.enabled,
        host=settings.host,
        port=settings.port,
        use_tls=settings.use_tls,
        use_starttls=settings.use_starttls,
        bind_dn=settings.bind_dn,
        has_password=bool(settings.bind_password_encrypted),
        search_base=settings.search_base,
        user_filter_template=settings.user_filter_template,
        group_prefix=settings.group_prefix,
        use_memberof=settings.use_memberof,
        updated_at=settings.updated_at.isoformat() if settings.updated_at else None,
    )


@router.get("", response_model=AdSettingsOut)
def get_settings(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    return _to_out(_get_or_create_settings(db))


@router.put("", response_model=AdSettingsOut, dependencies=[Depends(verify_csrf)])
def update_settings(
    payload: AdSettingsUpdate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    settings = _get_or_create_settings(db)
    settings.enabled = payload.enabled
    settings.host = payload.host
    settings.port = payload.port
    settings.use_tls = payload.use_tls
    settings.use_starttls = payload.use_starttls
    settings.bind_dn = payload.bind_dn
    settings.search_base = payload.search_base
    settings.user_filter_template = payload.user_filter_template
    settings.group_prefix = payload.group_prefix
    settings.use_memberof = payload.use_memberof
    if payload.bind_password:
        settings.bind_password_encrypted = security.encrypt_secret(payload.bind_password)
    db.commit()
    db.refresh(settings)
    return _to_out(settings)


@router.post("/test", dependencies=[Depends(verify_csrf)])
def test_settings(
    payload: AdTestRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    """Tests exactly what's in the submitted form. If no password was
    typed, falls back to the stored one (if any settings are already
    saved) -- so testing an edit doesn't require retyping a password
    that hasn't changed."""
    saved = db.query(AdSettings).first()

    probe = AdSettings(
        host=payload.host, port=payload.port, use_tls=payload.use_tls, use_starttls=payload.use_starttls,
        bind_dn=payload.bind_dn, search_base=payload.search_base,
        bind_password_encrypted=(saved.bind_password_encrypted if (not payload.bind_password and saved) else None),
    )
    result = ad_directory.test_connection(probe, bind_password=payload.bind_password or None)
    return {"success": result.success, "message": result.message, "detail": result.detail}


@router.get("/health")
def health_check(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    """Tests the currently SAVED settings -- the AD Health check,
    using only what's already persisted, no form input needed."""
    settings = db.query(AdSettings).first()
    if settings is None or not settings.enabled:
        return {"success": False, "message": "AD integration is not configured or not enabled.", "detail": {}}
    result = ad_directory.test_connection(settings)
    return {"success": result.success, "message": result.message, "detail": result.detail}


@router.get("/search-groups")
def search_ad_groups(
    query: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("groups:write")),
):
    """Real LDAP search backing the "browse AD" picker on the Groups
    page -- gated on groups:write (not superadmin-only, unlike the
    settings themselves) since this only reveals AD directory data
    already reachable via the configured service account, not the
    account's own credentials. Requires the SAVED settings to have a
    host configured; works whether or not AD integration is currently
    "enabled" (a false start on browsing shouldn't require flipping
    that switch first). Returns {"results": [...], "error": str|None}
    -- a real search failure is now distinguishable from a genuinely
    empty result, confirmed necessary by a real report where a group
    name a user's own memberOf named correctly still showed as "no
    matches" here with no way to tell why."""
    settings = db.query(AdSettings).first()
    if not settings or not settings.host or len(query.strip()) < 2:
        return {"results": [], "error": None}
    result = ad_directory.search_groups(settings, query.strip())
    return {"results": result.results, "error": result.error}


@router.get("/search-users")
def search_ad_users(
    query: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("tacacs_users:write")),
):
    """The same picker mechanism as search_ad_groups, for the Users
    page's AD-identity picker -- gated on tacacs_users:write."""
    settings = db.query(AdSettings).first()
    if not settings or not settings.host or len(query.strip()) < 2:
        return {"results": [], "error": None}
    result = ad_directory.search_users(settings, query.strip())
    return {"results": result.results, "error": result.error}


@router.get("/user-group-memberships")
def get_user_group_memberships(
    identity: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("tacacs_users:write")),
):
    """
    Shows exactly what group membership `tac_plus-ng` itself would see
    for `identity` (a sAMAccountName or UPN) -- built specifically to
    answer "why did this AD user get denied by ACL" directly, without
    needing external LDAP tools. Returns {"found": False} when the
    user isn't found or the lookup itself fails (bad credentials,
    unreachable server) -- distinguishable in the response from a
    successful lookup that simply found zero group memberships.
    """
    settings = db.query(AdSettings).first()
    if not settings or not settings.host or not identity.strip():
        return {"found": False}
    result = ad_directory.get_user_group_memberships(settings, identity.strip())
    if result is None:
        return {"found": False}
    return {"found": True, **result}


@router.get("/group-members")
def get_ad_group_members(
    group_name: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("groups:write")),
):
    """
    Read-only, live-fetched list of a real AD group's actual current
    members -- backs the Groups page's Members view for an AD-linked
    group. Gated on groups:write, matching search_ad_groups, since
    this is Groups-page functionality specifically.

    Deliberately NOT an add/remove/edit endpoint: this platform's own
    local membership assignment has zero effect on an AD group's real
    authorization-relevant membership (confirmed earlier this
    session), so the only thing worth exposing here is a live,
    accurate view of what AD itself actually says -- not a local copy
    that could silently drift from reality.
    """
    settings = db.query(AdSettings).first()
    if not settings or not settings.host or not group_name.strip():
        return {"results": [], "error": None}
    result = ad_directory.get_ad_group_members(settings, group_name.strip())
    return {"results": result.results, "error": result.error}
