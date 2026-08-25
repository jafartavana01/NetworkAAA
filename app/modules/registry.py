"""
app.modules.registry
======================
Module lifecycle system (spec sections 27-29). A Module bundles:
  - a unique key
  - a FastAPI router (REST API endpoints)
  - navigation entries for the GUI sidebar
  - a `mandatory` flag (the TACACS+ core cannot be disabled, per
    section 29 -- everything else can be)

Enabled/disabled state is persisted in PostgreSQL (ModuleState) so it
survives restarts, and is enforced at router-mount time in app.main:
a disabled module's router is never included in the FastAPI app, its
nav entries never appear, and no background tasks it might register
are started. This is real isolation (section 28: "not merely hide the
menu"), not a cosmetic toggle -- taking effect on the next application
restart/reload, which is documented rather than silently assumed to be
instant.

Phase 1 registers only the built-in `core` module (system dashboard /
auth / status). Devices, Users, Policies, Accounting etc. register
their own Module instances here in later phases without this file, or
app.main's mount loop, needing to change.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from fastapi import APIRouter


@dataclass
class NavEntry:
    label: str
    path: str
    icon: str = "circle"
    children: list["NavEntry"] = field(default_factory=list)
    # Hidden from the sidebar entirely for non-superadmins (not just
    # blocked after clicking) -- set on the "Platform" entry, since
    # admin-account management and network/TLS settings are
    # superadmin-only at the API and page-route layers already; a
    # visible-but-forbidden nav item would just be a confusing dead
    # end for a standard admin. See app/templates/partials/sidebar.html.
    requires_superadmin: bool = False


@dataclass
class Module:
    key: str
    name: str
    description: str
    router: APIRouter | None
    nav_entries: list[NavEntry]
    mandatory: bool = False


_REGISTRY: dict[str, Module] = {}


def register(module: Module) -> None:
    if module.key in _REGISTRY:
        raise ValueError(f"Module '{module.key}' is already registered.")
    _REGISTRY[module.key] = module


def all_modules() -> list[Module]:
    return list(_REGISTRY.values())


def get_module(key: str) -> Module | None:
    return _REGISTRY.get(key)
