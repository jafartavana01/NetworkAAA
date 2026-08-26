"""
app.modules.tacacs_module
===========================
The mandatory TACACS+ functional area (spec section 26's example grouping:
Server / Devices / Users / Authentication / Authorization / Accounting /
Diagnostics, all under one "TACACS+" nav item). Distinct from the `core`
module (platform-level: dashboard, and in Phase 8, module management)
registered in Phase 1.

Phase 2 added Devices and Configuration. Phase 3 added Users. Phase 4
added Groups and Device Groups. Phase 5 added Policies (authorization).
Phase 6 added Accounting. Phase 7 added Diagnostics. PAM Expansion Plan
Increment 1 adds Command Sets and Command Categories, and reworks
Policies into the conditions + referenced-Command-Sets model (see
app.services.policy_engine, app.api.routes_policies).
"""
from __future__ import annotations

from fastapi import APIRouter

from ..api.routes_accounting import router as accounting_router
from ..api.routes_command_categories import router as command_categories_router
from ..api.routes_command_sets import router as command_sets_router
from ..api.routes_config import router as config_router
from ..api.routes_device_access_grants import router as device_access_grants_router
from ..api.routes_device_groups import router as device_groups_router
from ..api.routes_devices import router as devices_router
from ..api.routes_diagnostics import router as diagnostics_router
from ..api.routes_effective_access import router as effective_access_router
from ..api.routes_policies import router as policies_router
from ..api.routes_policy_conditions import router as policy_conditions_router
from ..api.routes_policy_simulator import router as policy_simulator_router
from ..api.routes_policy_versions import router as policy_versions_router
from ..api.routes_tacacs_groups import router as tacacs_groups_router
from ..api.routes_tacacs_logs import router as tacacs_logs_router
from ..api.routes_tacacs_users import router as tacacs_users_router
from .registry import Module, NavEntry, register, get_module

_tacacs_api_router = APIRouter()
_tacacs_api_router.include_router(devices_router)
_tacacs_api_router.include_router(device_access_grants_router)
_tacacs_api_router.include_router(device_groups_router)
_tacacs_api_router.include_router(config_router)
_tacacs_api_router.include_router(tacacs_users_router)
_tacacs_api_router.include_router(tacacs_groups_router)
_tacacs_api_router.include_router(policies_router)
_tacacs_api_router.include_router(policy_versions_router)
_tacacs_api_router.include_router(policy_conditions_router)
_tacacs_api_router.include_router(command_sets_router)
_tacacs_api_router.include_router(command_categories_router)
_tacacs_api_router.include_router(policy_simulator_router)
_tacacs_api_router.include_router(effective_access_router)
_tacacs_api_router.include_router(accounting_router)
_tacacs_api_router.include_router(tacacs_logs_router)
_tacacs_api_router.include_router(diagnostics_router)


def _build_module() -> Module:
    from ..web.routes_tacacs import router as tacacs_web_router
    combined_router = APIRouter()
    combined_router.include_router(_tacacs_api_router)
    combined_router.include_router(tacacs_web_router)

    return Module(
        key="tacacs",
        name="TACACS+",
        description="Network devices, TACACS+ users/groups, authorization policies, command sets, accounting, diagnostics, and the tac_plus-ng configuration compiler.",
        router=combined_router,
        nav_entries=[
            NavEntry(
                label="TACACS+",
                path="/tacacs/devices",
                icon="server",
                children=[
                    NavEntry(label="Devices", path="/tacacs/devices"),
                    NavEntry(label="Device Groups", path="/tacacs/device-groups"),
                    NavEntry(label="Users", path="/tacacs/users"),
                    NavEntry(label="Groups", path="/tacacs/groups"),
                    NavEntry(label="Policies", path="/tacacs/policies"),
                    NavEntry(label="Command Sets", path="/tacacs/command-sets"),
                    NavEntry(label="Command Categories", path="/tacacs/command-categories"),
                    NavEntry(label="Policy Simulator", path="/tacacs/policy-simulator"),
                    NavEntry(label="Effective Access", path="/tacacs/effective-access"),
                    NavEntry(label="Accounting", path="/tacacs/accounting"),
                    NavEntry(label="Sessions", path="/tacacs/sessions"),
                    NavEntry(label="AAA Health", path="/tacacs/aaa-health"),
                    NavEntry(label="Diagnostics", path="/tacacs/diagnostics"),
                    NavEntry(label="Configuration", path="/tacacs/config"),
                ],
            ),
        ],
        mandatory=True,
    )


def register_tacacs_module() -> None:
    if get_module("tacacs") is None:
        register(_build_module())
