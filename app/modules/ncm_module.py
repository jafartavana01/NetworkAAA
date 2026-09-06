"""
app.modules.ncm_module
=========================
Registers Network Configuration Management as a first-class module,
the same way TACACS+, Network Operations and Security Center are
registered -- so NCM appears in navigation, module state and RBAC
through the existing machinery rather than as a bolted-on section.

Only the pages that genuinely work are given nav entries. The spec's
suggested "Templates" and "Compliance" entries are deliberately
omitted: exposing nav that leads nowhere is the fake UI the brief
rules out, and they can be added when the phases behind them exist.
"""
from fastapi import APIRouter

from ..api.routes_ncm import router as ncm_api_router
from .registry import Module, NavEntry, register


def _build_module() -> Module:
    from ..web.routes_ncm import router as ncm_web_router

    combined_router = APIRouter()
    combined_router.include_router(ncm_api_router)
    combined_router.include_router(ncm_web_router)

    return Module(
        key="ncm",
        name="NCM",
        description="Network Configuration Management: configuration backup, immutable versioned archive, "
                    "unified diff, and scheduled backups over the platform's existing SSH infrastructure.",
        router=combined_router,
        nav_entries=[
            NavEntry(
                label="NCM",
                path="/ncm/overview",
                icon="database",
                children=[
                    NavEntry(label="Overview", path="/ncm/overview"),
                    NavEntry(label="Configuration Compare", path="/ncm/compare"),
                    NavEntry(label="Configuration Archive", path="/ncm/archive"),
                    NavEntry(label="Configuration Diff", path="/ncm/diff"),
                    NavEntry(label="Backup Jobs", path="/ncm/jobs"),
                    NavEntry(label="Backup Schedules", path="/ncm/schedules"),
                ],
            ),
        ],
    )


def register_ncm_module() -> None:
    register(_build_module())
