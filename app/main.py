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

from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy.orm import Session

from .api.routes_auth import router as auth_router
from .database import get_sessionmaker
from .modules import registry
from .modules.core_module import register_core_module
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


def create_app() -> FastAPI:
    app = FastAPI(title="AAA Management Platform", docs_url="/api/docs", redoc_url=None)

    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

    # Always-on infrastructure routes (auth is not itself a toggleable
    # module -- you need it to reach the module toggle screen at all).
    app.include_router(auth_router)
    app.include_router(web_router)

    register_core_module()
    register_tacacs_module()

    @app.on_event("startup")
    def _on_startup() -> None:
        _sync_module_states()
        _seed_command_categories()
        enabled = _enabled_module_keys()
        for module in registry.all_modules():
            # Mandatory modules (core / future TACACS+ core) are always
            # mounted regardless of their stored state -- spec section
            # 29 makes the core platform non-optional at the registry
            # level, not just by convention.
            if module.router and (module.mandatory or module.key in enabled):
                app.include_router(module.router)

    return app


app = create_app()
