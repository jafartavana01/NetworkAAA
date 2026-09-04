"""
app.web.routes_security
==========================
Server-rendered pages for the Security Center module. Same pattern as
app.web.routes_network_ops -- mounted by app.modules.security_module
alongside its API router.

Overview, the device list, and per-device detail are built. Interfaces,
Findings (as a fleet-wide filterable view), Compliance (as its own
page), Remediation, Security Builder, and Audit History comparison are
each their own deliberate follow-up, not stubbed here as placeholder
pages that would look finished but aren't.
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


def _render(request: Request, session_token: str | None, template_name: str):
    admin = current_admin_or_none(session_token)
    if not admin:
        return RedirectResponse(url="/login", status_code=302)

    dashboard_item, nav_sections = build_sidebar_sections(all_modules(), is_superadmin=admin.is_superadmin)
    return templates.TemplateResponse(
        request,
        template_name,
        {"admin_username": admin.username, "dashboard_item": dashboard_item, "nav_sections": nav_sections, "is_superadmin": admin.is_superadmin},
    )


@router.get("/security/overview", response_class=HTMLResponse)
def overview_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "security_overview.html")


@router.get("/security/devices", response_class=HTMLResponse)
def devices_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "security_devices.html")


@router.get("/security/findings", response_class=HTMLResponse)
def findings_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "security_findings.html")


@router.get("/security/devices/{device_id}", response_class=HTMLResponse)
def device_detail_page(
    device_id: str,
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "security_device_detail.html")
