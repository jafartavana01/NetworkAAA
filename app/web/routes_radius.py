"""
app.web.routes_radius
========================
Server-rendered pages for the RADIUS module.

Only pages backed by confirmed engine capability are routed. There is
no CoA page: Change-of-Authorization is not supported by the current
tac_plus-ng build (confirmed on a real installation), and routing a
page for it would be fake functionality.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import security
from ..modules.registry import all_modules
from ..modules.sidebar import build_sidebar_sections
from .auth_helpers import current_admin_or_none, redirect_to_login

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()

def _licensed_module_keys() -> set | None:
    """Module keys the licence allows, for sidebar filtering.

    Returns None on any failure, which means "do not filter". A licence
    lookup problem must never blank the navigation of a working
    installation -- the API gate is the real control, and this is only
    presentation."""
    try:
        from ..database import get_sessionmaker
        from ..services import entitlements

        db = get_sessionmaker()()
        try:
            return entitlements.enabled_module_keys(db)
        finally:
            db.close()
    except Exception:
        return None



def _render(request: Request, session_token: str | None, template_name: str, *, require_superadmin: bool = False):
    admin = current_admin_or_none(session_token)
    if not admin:
        return redirect_to_login(session_token)
    if require_superadmin and not admin.is_superadmin:
        return RedirectResponse(url="/radius/overview", status_code=302)

    dashboard_item, nav_sections = build_sidebar_sections(
        all_modules(), is_superadmin=admin.is_superadmin,
        licensed_module_keys=_licensed_module_keys(),
    )
    return templates.TemplateResponse(
        request,
        template_name,
        {
            "admin_username": admin.username,
            "dashboard_item": dashboard_item,
            "nav_sections": nav_sections,
            "is_superadmin": admin.is_superadmin,
        },
    )


@router.get("/radius/overview", response_class=HTMLResponse)
def radius_overview_page(request: Request, session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME)):
    return _render(request, session_token, "radius_overview.html")


@router.get("/radius/server", response_class=HTMLResponse)
def radius_server_page(request: Request, session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME)):
    return _render(request, session_token, "radius_settings.html", require_superadmin=True)


@router.get("/radius/clients", response_class=HTMLResponse)
def radius_clients_page(request: Request, session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME)):
    return _render(request, session_token, "radius_clients.html")


@router.get("/radius/policies", response_class=HTMLResponse)
def radius_policies_page(request: Request, session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME)):
    return _render(request, session_token, "radius_policies.html")


@router.get("/radius/attributes", response_class=HTMLResponse)
def radius_attributes_page(request: Request, session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME)):
    return _render(request, session_token, "radius_attributes.html")


