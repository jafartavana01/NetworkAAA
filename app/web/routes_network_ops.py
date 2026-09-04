"""
app.web.routes_network_ops
=============================
Server-rendered pages for the Network Operations module. Mounted by
app.modules.network_ops_module alongside its API router -- same
pattern as app.web.routes_tacacs.
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


@router.get("/network-ops/jobs", response_class=HTMLResponse)
def jobs_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "network_ops_jobs.html")


@router.get("/network-ops/jobs/{job_id}", response_class=HTMLResponse)
def job_detail_page(
    job_id: str,
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "network_ops_job_detail.html")


@router.get("/network-ops/templates", response_class=HTMLResponse)
def templates_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "network_ops_templates.html")


@router.get("/network-ops/checks", response_class=HTMLResponse)
def checks_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "network_ops_checks.html")


@router.get("/network-ops/audits", response_class=HTMLResponse)
def audits_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "network_ops_audits.html")
