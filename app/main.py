"""
app.main
=========
FastAPI application entrypoint (`uvicorn app.main:app`, per the
systemd unit installer.systemd_setup writes). Wires together: static
assets (local only -- no CDN, spec section 25), the auth API, the
module registry (spec sections 27-28), and the server-rendered GUI
shell.
"""
from __future__ import annotations

import asyncio
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .api.routes_auth import router as auth_router
from .database import get_sessionmaker
from .modules import registry
from .modules.core_module import register_core_module
from .modules.network_ops_module import register_network_ops_module
from .modules.security_module import register_security_module
from .modules.tacacs_module import register_tacacs_module
from .models.module_state import ModuleState
from .web.routes import router as web_router

STATIC_DIR = Path(__file__).resolve().parent / "static"


def _sync_module_states() -> None:
    """
    Ensures every registered module has a row in module_state (spec
    section 28's persisted enabled/disabled flag), seeding new modules
    as enabled by default and never overwriting an admin's existing
    choice for a module they've already seen.
    """
    session_local = get_sessionmaker()
    db: Session = session_local()
    try:
        existing = {row.key for row in db.query(ModuleState).all()}
        for module in registry.all_modules():
            if module.key not in existing:
                db.add(ModuleState(key=module.key, enabled=True))
        db.commit()
    finally:
        db.close()


def _enabled_module_keys() -> set[str]:
    session_local = get_sessionmaker()
    db: Session = session_local()
    try:
        return {row.key for row in db.query(ModuleState).filter(ModuleState.enabled.is_(True)).all()}
    finally:
        db.close()


def _seed_command_categories() -> None:
    """Seeds the starting Cisco IOS command-category taxonomy (PAM
    Expansion Plan §6) on first boot -- a no-op on every subsequent
    boot once any category row exists, so it never overwrites admin
    edits or additions. See app.api.routes_command_categories.ensure_seeded."""
    from .api.routes_command_categories import ensure_seeded

    session_local = get_sessionmaker()
    db: Session = session_local()
    try:
        ensure_seeded(db)
    finally:
        db.close()


def _seed_admin_role_templates() -> None:
    """Seeds the starting RBAC role templates (PAM Expansion Plan §29)
    on first boot -- a no-op on every subsequent boot once any role
    row exists, so it never overwrites admin edits, deletions, or
    additions. See app.api.routes_admin_roles.ensure_seeded."""
    from .api.routes_admin_roles import ensure_seeded

    session_local = get_sessionmaker()
    db: Session = session_local()
    try:
        ensure_seeded(db)
    finally:
        db.close()


def _seed_monitor_group() -> None:
    """Seeds the prebuilt "monitor" DeviceGroup on first boot -- a
    no-op once it exists, so an admin renaming or deleting it is never
    silently undone. See app.api.routes_monitoring.ensure_monitor_group_seeded."""
    from .api.routes_monitoring import ensure_monitor_group_seeded

    session_local = get_sessionmaker()
    db: Session = session_local()
    try:
        ensure_monitor_group_seeded(db)
    finally:
        db.close()


def _seed_network_ops_checks() -> None:
    """Seeds the starter Check catalog on first boot -- a no-op on
    every subsequent boot once any Check row exists. See
    app.api.routes_network_ops_checks.ensure_seeded."""
    from .api.routes_network_ops_checks import ensure_seeded

    session_local = get_sessionmaker()
    db: Session = session_local()
    try:
        ensure_seeded(db)
    finally:
        db.close()


def _seed_network_ops_audits() -> None:
    """Seeds the starter Audit on first boot -- must run AFTER
    _seed_network_ops_checks (the starter Audit references check_keys
    that need to already exist as real Check rows). See
    app.api.routes_network_ops_audits.ensure_seeded."""
    from .api.routes_network_ops_audits import ensure_seeded

    session_local = get_sessionmaker()
    db: Session = session_local()
    try:
        ensure_seeded(db)
    finally:
        db.close()


def create_app() -> FastAPI:
    app = FastAPI(title="AAA Management Platform", docs_url="/api/docs", redoc_url=None)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Always-on infrastructure routes (auth is not itself a toggleable
    # module -- you need it to reach the module toggle screen at all).
    app.include_router(auth_router)
    app.include_router(web_router)

    register_core_module()
    register_tacacs_module()
    register_network_ops_module()
    register_security_module()

    @app.on_event("startup")
    def _on_startup() -> None:
        _sync_module_states()
        _seed_command_categories()
        _seed_admin_role_templates()
        _seed_monitor_group()
        _seed_network_ops_checks()
        _seed_network_ops_audits()
        enabled = _enabled_module_keys()
        for module in registry.all_modules():
            # Mandatory modules (core / future TACACS+ core) are always
            # mounted regardless of their stored state -- spec section
            # 29 makes the core platform non-optional at the registry
            # level, not just by convention.
            if module.router and (module.mandatory or module.key in enabled):
                app.include_router(module.router)

    @app.on_event("startup")
    async def _start_scheduled_audit_loop() -> None:
        # A separate startup handler, deliberately -- _on_startup above
        # is sync and does one-time setup; this one is async and starts
        # a task that runs for the entire lifetime of the process.
        # Folding this into the sync handler would require it to
        # schedule the task itself in a way that isn't the normal,
        # straightforward `asyncio.create_task` an async handler gets
        # for free.
        from .services.scheduled_audit import scheduler_loop
        asyncio.create_task(scheduler_loop())

    return app


app = create_app()
