"""
app.web.routes
================
Server-rendered HTML pages (Jinja2, no build step, no CDN -- spec
section 25). This is the "shell" (section 26): base layout, sidebar,
header. Phase 1 supplies the login page and the dashboard; later
phases add pages by registering more nav entries and templates, not by
touching this shell.
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



@router.get("/", response_class=HTMLResponse)
def root(request: Request, session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME)):
    if current_admin_or_none(session_token):
        return RedirectResponse(url="/dashboard", status_code=302)
    return RedirectResponse(url="/login", status_code=302)


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse(request, "login.html", {})


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    admin = current_admin_or_none(session_token)
    if not admin:
        # Clears a stale/invalid session cookie so the browser can't
        # loop on a token the server will never accept.
        return redirect_to_login(session_token)

    dashboard_item, nav_sections = build_sidebar_sections(
        all_modules(), is_superadmin=admin.is_superadmin,
        licensed_module_keys=_licensed_module_keys(),
    )
    return templates.TemplateResponse(
        request,
        "dashboard.html",
        {"admin_username": admin.username, "dashboard_item": dashboard_item, "nav_sections": nav_sections, "is_superadmin": admin.is_superadmin},
    )
