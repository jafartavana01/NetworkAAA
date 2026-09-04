"""
app.web.routes_tacacs
=======================
Server-rendered pages for the TACACS+ module (spec section 51: Network
Devices, end-to-end through to the running daemon). Mounted by
app.modules.tacacs_module alongside its API router.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Cookie, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import security
from ..modules.registry import all_modules
from ..modules.sidebar import build_sidebar_sections
from .auth_helpers import current_admin_or_none

TEMPLATES_DIR = Path(__file__).resolve().parent.parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATES_DIR))

router = APIRouter()


def _require_admin(session_token: str | None):
    return current_admin_or_none(session_token)


def _render(request: Request, session_token: str | None, template_name: str):
    admin = _require_admin(session_token)
    if not admin:
        return RedirectResponse(url="/login", status_code=302)

    dashboard_item, nav_sections = build_sidebar_sections(all_modules(), is_superadmin=admin.is_superadmin)
    return templates.TemplateResponse(
        request,
        template_name,
        {"admin_username": admin.username, "dashboard_item": dashboard_item, "nav_sections": nav_sections, "is_superadmin": admin.is_superadmin},
    )


@router.get("/tacacs/devices", response_class=HTMLResponse)
def devices_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "devices.html")


@router.get("/tacacs/device-groups", response_class=HTMLResponse)
def device_groups_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "device_groups.html")


@router.get("/tacacs/users", response_class=HTMLResponse)
def users_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "users.html")


@router.get("/tacacs/groups", response_class=HTMLResponse)
def groups_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "groups.html")


@router.get("/tacacs/policies", response_class=HTMLResponse)
def policies_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "policies.html")


@router.get("/tacacs/command-sets", response_class=HTMLResponse)
def command_sets_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "command_sets.html")


@router.get("/tacacs/command-categories", response_class=HTMLResponse)
def command_categories_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "command_categories.html")


@router.get("/tacacs/policy-simulator", response_class=HTMLResponse)
def policy_simulator_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "policy_simulator.html")


@router.get("/tacacs/effective-access", response_class=HTMLResponse)
def effective_access_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "effective_access.html")


@router.get("/tacacs/accounting", response_class=HTMLResponse)
def accounting_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "accounting.html")


@router.get("/tacacs/sessions", response_class=HTMLResponse)
def sessions_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "sessions.html")


@router.get("/tacacs/aaa-health", response_class=HTMLResponse)
def aaa_health_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "aaa_health.html")


@router.get("/tacacs/diagnostics", response_class=HTMLResponse)
def diagnostics_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "diagnostics.html")


@router.get("/tacacs/config", response_class=HTMLResponse)
def config_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "config.html")
