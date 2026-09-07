"""
app.web.routes_ncm
=====================
Server-rendered pages for the NCM module. Same pattern as
app.web.routes_security -- mounted by app.modules.ncm_module alongside
its API router.

Only the pages the spec designates as usable in this implementation
are routed: Overview, Configuration Archive, Backup Jobs, and
Configuration Diff (plus Schedules, which Phase 3 makes real).
Templates and Compliance are deliberately NOT routed -- the spec is
explicit that unfinished future functionality should not be exposed,
and a nav entry leading to an empty page is exactly the fake UI it
rules out.
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


def _render(request: Request, session_token: str | None, template_name: str):
    admin = current_admin_or_none(session_token)
    if not admin:
        # Clears a stale/invalid session cookie so the browser can't
        # loop on a token the server will never accept.
        return redirect_to_login(session_token)

    dashboard_item, nav_sections = build_sidebar_sections(all_modules(), is_superadmin=admin.is_superadmin)
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


@router.get("/ncm/overview", response_class=HTMLResponse)
def ncm_overview_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "ncm_overview.html")


@router.get("/ncm/archive", response_class=HTMLResponse)
def ncm_archive_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "ncm_archive.html")


@router.get("/ncm/drift", response_class=HTMLResponse)
def ncm_drift_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "ncm_drift.html")


@router.get("/ncm/jobs", response_class=HTMLResponse)
def ncm_jobs_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "ncm_jobs.html")


@router.get("/ncm/compare", response_class=HTMLResponse)
def ncm_compare_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "ncm_compare.html")


@router.get("/ncm/diff", response_class=HTMLResponse)
def ncm_diff_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "ncm_diff.html")


@router.get("/ncm/schedules", response_class=HTMLResponse)
def ncm_schedules_page(
    request: Request,
    session_token: str | None = Cookie(default=None, alias=security.SESSION_COOKIE_NAME),
):
    return _render(request, session_token, "ncm_schedules.html")
