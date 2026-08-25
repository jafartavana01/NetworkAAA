"""
app.web.routes_platform
=========================
Server-rendered pages for platform self-management: who can log into
this GUI (Admin Users) and how it's reachable (Network/TLS Settings).
Distinct from app.web.routes_tacacs, which covers the TACACS+ data the
platform manages, not the platform itself. Mounted by
app.modules.core_module.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import security
from ..modules.registry import all_modules
from .auth_helpers import current_admin_or_none

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


def _render(request: Request, session_token: str | None, template_name: str, *, require_superadmin: bool = False):
    admin = current_admin_or_none(session_token)
    if not admin:
        return RedirectResponse(url="/login", status_code=302)
    if require_superadmin and not admin.is_superadmin:
        return RedirectResponse(url="/dashboard", status_code=302)

    nav = [entry for module in all_modules() for entry in module.nav_entries]
    return templates.TemplateResponse(
        request,
        template_name,
        {"admin_username": admin.username, "nav": nav, "is_superadmin": admin.is_superadmin},
    )


@router.get("/platform/admin-users", response_class=HTMLResponse)
def admin_users_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "admin_users.html", require_superadmin=True)


@router.get("/platform/settings", response_class=HTMLResponse)
def platform_settings_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "platform_settings.html", require_superadmin=True)
