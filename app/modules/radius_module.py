"""
app.modules.radius_module
============================
Registers RADIUS as a first-class module with its own navigation
section, rather than a single "RADIUS Settings" entry buried under
TACACS+.

Pages registered here are only those backed by real, confirmed
capability. In particular there is deliberately NO CoA entry: the
current engine does not support Change-of-Authorization (confirmed on
a real installation), and a nav entry leading to controls that cannot
work is the fake functionality this project rules out. See
docs/RADIUS_FINDINGS.md for the audit.
"""
from fastapi import APIRouter

from ..api.routes_radius import router as radius_api_router
from .registry import Module, NavEntry, register


def _build_module() -> Module:
    from ..web.routes_radius import router as radius_web_router

    combined = APIRouter()
    combined.include_router(radius_api_router)
    combined.include_router(radius_web_router)

    return Module(
        key="radius",
        name="RADIUS",
        description="RADIUS authentication, authorization and accounting for devices that do not "
                    "speak TACACS+ — clients, policies, attribute assignment and accounting, served "
                    "by the same tac_plus-ng daemon and the same users, groups and devices.",
        router=combined,
        nav_entries=[
            NavEntry(
                label="RADIUS",
                path="/radius/clients",
                icon="shield",
                # Only pages that exist are listed. Overview, Policies
                # and Accounting are registered here as each is built --
                # a nav entry that 500s is worse than one not yet
                # present.
                children=[
                    NavEntry(label="Server", path="/radius/server", requires_superadmin=True),
                    NavEntry(label="Clients", path="/radius/clients"),
                    NavEntry(label="Attributes", path="/radius/attributes"),
                ],
            ),
        ],
    )


def register_radius_module() -> None:
    register(_build_module())
