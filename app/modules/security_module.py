"""
app.modules.security_module
==============================
Security Center. A new, non-mandatory module -- same enable/disable
mechanism as app.modules.network_ops_module (see that file's own
docstring for the reasoning, identical here).

Overview, the device list, per-device detail, the fleet-wide findings
view, and scheduled-audit settings are now wired into navigation --
see app.web.routes_security's own docstring for why the rest of the
planned navigation (Interfaces, Compliance as its own page,
Remediation, Security Builder) isn't stubbed in here as dead links.
"""
from __future__ import annotations

from fastapi import APIRouter

from ..api.routes_security import router as security_api_router
from .registry import Module, NavEntry, get_module, register


def _build_module() -> Module:
    from ..web.routes_security import router as security_web_router
    combined_router = APIRouter()
    combined_router.include_router(security_api_router)
    combined_router.include_router(security_web_router)

    return Module(
        key="security",
        name="Security Center",
        description="Cisco IOS/IOS-XE device and interface security auditing: ~230 device-level checks across "
                     "9 domains, correlation, compliance mapping, and scoring -- migrated from this project's own "
                     "cisco-ios-security-auditor and cisco-interface-security-audit source.",
        router=combined_router,
        nav_entries=[
            NavEntry(
                label="Security Center",
                path="/security/overview",
                icon="shield",
                children=[
                    NavEntry(label="Overview", path="/security/overview"),
                    NavEntry(label="Devices", path="/security/devices"),
                    NavEntry(label="Findings", path="/security/findings"),
                    NavEntry(label="Scheduled Audits", path="/security/schedule", requires_superadmin=True),
                ],
            ),
        ],
        mandatory=False,
    )


def register_security_module() -> None:
    if get_module("security") is None:
        register(_build_module())
