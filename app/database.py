"""
app.database
=============
SQLAlchemy engine/session wiring. PostgreSQL is the source of truth
(spec section 16) for every management-plane model; the generated
tac_plus-ng configuration file is a derived artifact, never the other
way around.

CLEAN INSTALL ONLY -- no upgrade-from-existing-database path is
supported (explicit product decision: every install targets a fresh
VM, never an in-place upgrade of a populated database). This is a
deliberate simplification, not an oversight: earlier drafts of this
file carried real ALTER TABLE / data-migration logic (adding columns
to already-existing tables, wrapping legacy CommandRule rows into
auto-created CommandSets, backfilling new condition columns from old
direct links) specifically to support upgrading an existing
installation. That entire category of code -- genuinely the
highest-risk code in this project, since it transforms real data and
could not be tested against a live PostgreSQL instance in the
development sandbox at all -- is unnecessary for a clean-install-only
tool and has been removed rather than kept "just in case." A fresh,
empty database only ever needs `Base.metadata.create_all()`: it
creates every table, every column, and every foreign-key constraint
directly from the current model definitions, with no legacy schema to
reconcile.

If an upgrade-in-place path becomes a real requirement again later,
reintroduce migrations at that point using a real framework (Alembic)
rather than hand-written ALTER TABLE lists -- see the git history for
this file's previous, more complex version if a migration ever does
need to be re-derived from what changed between two schema versions.
"""
from __future__ import annotations

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from .config import get_settings


class Base(DeclarativeBase):
    pass


_engine = None
_SessionLocal = None


def get_engine():
    global _engine
    if _engine is None:
        _engine = create_engine(get_settings().database_url, pool_pre_ping=True)
    return _engine


def get_sessionmaker():
    global _SessionLocal
    if _SessionLocal is None:
        _SessionLocal = sessionmaker(bind=get_engine(), autoflush=False, autocommit=False)
    return _SessionLocal


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency: yields a session, always closed after the request."""
    session_local = get_sessionmaker()
    db = session_local()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """
    Creates every table from the current model definitions. Clean
    installs only -- see this module's docstring for why there is
    deliberately no migration logic here.
    """
    # Import models so they're registered on Base.metadata before create_all.
    from .models import (  # noqa: F401
        admin, system_info, module_state, device, config_version, user, group,
        device_group, policy, command_rule, command_category, command_set,
        policy_command_set, policy_version,
    )

    Base.metadata.create_all(bind=get_engine())
