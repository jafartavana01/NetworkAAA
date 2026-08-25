"""
app.modules.core_module
=========================
The platform-level module: system status/dashboard (Phase 1), plus
platform self-management -- Admin Users and Network/TLS Settings.
Always enabled, mandatory=True (spec section 29 makes the platform
itself non-optional). Distinct from the `tacacs` module, which covers
the TACACS+ data the platform manages (devices, users, policies...),
not the platform's own configuration.

Admin Users and Settings pages/routes are superadmin-gated at three
independent layers: the API routes themselves (Depends(get_current_superadmin)),
the page routes (app.web.routes_platform redirects non-superadmins away),
and the GUI (nav entries and page content only render for
is_superadmin -- see the templates). Belt-and-suspenders is deliberate
here, not redundant: a bug in any single layer still leaves the other
two enforcing the real restriction.
"""
from __future__ import annotations

from fastapi import APIRouter

from ..api.routes_admin_users import router as admin_users_router
from ..api.routes_platform_settings import router as platform_settings_router
from ..api.routes_system import router as system_router
from . import registry
from .registry import Module, NavEntry

_core_router = APIRouter()
_core_router.include_router(system_router)
_core_router.include_router(admin_users_router)
_core_router.include_router(platform_settings_router)


def _build_core_module() -> Module:
    from ..web.routes_platform import router as platform_web_router
    combined_router = APIRouter()
    combined_router.include_router(_core_router)
    combined_router.include_router(platform_web_router)

    return Module(
        key="core",
        name="Core",
        description="System dashboard, build information, service status, admin accounts, and network/TLS settings.",
        router=combined_router,
        nav_entries=[
            NavEntry(label="Dashboard", path="/dashboard", icon="layout-dashboard"),
            NavEntry(
                label="Platform",
                path="/platform/admin-users",
                icon="settings",
                requires_superadmin=True,
                children=[
                    NavEntry(label="Admin Users", path="/platform/admin-users"),
                    NavEntry(label="Settings", path="/platform/settings"),
                ],
            ),
        ],
        mandatory=True,
    )


CORE_MODULE = _build_core_module()


def register_core_module() -> None:
    if registry.get_module("core") is None:
        registry.register(CORE_MODULE)
