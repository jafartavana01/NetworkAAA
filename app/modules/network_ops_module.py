"""
app.modules.network_ops_module
=================================
Network Operations & Assurance Engine (Phase 1: Command Jobs). A new,
NON-mandatory module -- unlike the TACACS+ core, this is genuinely
optional capability, so it participates in the existing module
enable/disable mechanism (app.modules.registry, app.main's
_sync_module_states/_enabled_module_keys) exactly like any other
non-core module: seeded as enabled by default on first boot, toggle-
able off without affecting TACACS+, AD, monitoring, or anything else
this project already does.
"""
from __future__ import annotations

from fastapi import APIRouter

from ..api.routes_network_ops import router as network_ops_api_router
from ..api.routes_network_ops_audits import router as network_ops_audits_api_router
from ..api.routes_network_ops_checks import router as network_ops_checks_api_router
from .registry import Module, NavEntry, get_module, register


def _build_module() -> Module:
    from ..web.routes_network_ops import router as network_ops_web_router
    combined_router = APIRouter()
    combined_router.include_router(network_ops_api_router)
    combined_router.include_router(network_ops_checks_api_router)
    combined_router.include_router(network_ops_audits_api_router)
    combined_router.include_router(network_ops_web_router)

    return Module(
        key="network_ops",
        name="Network Operations",
        description="Command jobs against network devices and device groups: reusable command templates, target resolution, live execution progress, and full raw-output history.",
        router=combined_router,
        nav_entries=[
            NavEntry(
                label="Network Operations",
                path="/network-ops/jobs",
                icon="terminal",
                children=[
                    NavEntry(label="Command Jobs", path="/network-ops/jobs"),
                    NavEntry(label="Templates", path="/network-ops/templates"),
                    NavEntry(label="Checks", path="/network-ops/checks"),
                    NavEntry(label="Audits", path="/network-ops/audits"),
                ],
            ),
        ],
        mandatory=False,
    )


def register_network_ops_module() -> None:
    if get_module("network_ops") is None:
        register(_build_module())
