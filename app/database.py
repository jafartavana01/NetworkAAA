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
        admin, admin_role, system_info, module_state, device, config_version, user, group,
        device_group, policy, command_rule, command_category, command_set,
        policy_command_set, policy_version, policy_condition_group, policy_condition,
        device_access_grant, ad_settings, monitoring_settings, aaa_template_settings,
        command_template, command_job, network_ops_check, network_ops_audit, audit_run,
        audit_schedule_settings, audit_batch, ncm, radius_settings, radius_policy,
    )

    Base.metadata.create_all(bind=get_engine())
    _apply_additive_column_migrations()


def _apply_additive_column_migrations() -> None:
    """
    Adds columns that exist in the models but not yet in the database.

    `create_all()` creates missing TABLES but never alters existing
    ones, so a column added to an existing table in a newer version is
    silently skipped -- and the application then fails at runtime with
    "column ... does not exist" deep inside an unrelated query. That is
    exactly what happened when `radius_enabled` and
    `radius_secret_encrypted` were added to `network_devices`: a clean
    install worked, an upgrade broke every device query.

    Scope is deliberately narrow, because this runs unattended at
    startup against production data:

      * ADD COLUMN only. Never drop, never alter a type, never rename.
        A column in the database that is no longer in the models is
        left exactly where it is -- removing it would destroy data
        nobody asked to lose.
      * A NOT NULL column is only added when the model supplies a
        scalar default, since adding NOT NULL to a table with existing
        rows fails without one. Without a default the column is added
        as NULLABLE and a warning is logged, rather than the migration
        failing and taking startup down with it.
      * Every statement is `IF NOT EXISTS`, so re-running is a no-op.

    Anything this cannot do safely is reported, not guessed at --
    `installer.install_state.check_schema_drift` remains the full
    report for an operator.
    """
    import logging

    from sqlalchemy import inspect, text

    logger = logging.getLogger(__name__)
    engine = get_engine()

    try:
        inspector = inspect(engine)
        existing_tables = set(inspector.get_table_names())
    except Exception as exc:  # noqa: BLE001 - never block startup on introspection
        logger.warning("Could not inspect the database schema (%s); skipping column migration.", exc)
        return

    for table_name, table in Base.metadata.tables.items():
        if table_name not in existing_tables:
            continue  # create_all just made it; nothing to add
        try:
            actual = {c["name"] for c in inspector.get_columns(table_name)}
        except Exception as exc:  # noqa: BLE001
            logger.warning("Could not read columns of %s (%s); skipping.", table_name, exc)
            continue

        for column in table.columns:
            if column.name in actual:
                continue
            try:
                type_sql = column.type.compile(dialect=engine.dialect)
            except Exception:
                logger.warning(
                    "Cannot render a SQL type for %s.%s; add it manually.", table_name, column.name
                )
                continue

            clause = f"ADD COLUMN IF NOT EXISTS {column.name} {type_sql}"
            default = getattr(column, "default", None)
            default_value = getattr(default, "arg", None) if default is not None else None

            if not column.nullable:
                if isinstance(default_value, bool):
                    clause += f" NOT NULL DEFAULT {'true' if default_value else 'false'}"
                elif isinstance(default_value, (int, float)):
                    clause += f" NOT NULL DEFAULT {default_value}"
                elif isinstance(default_value, str):
                    escaped = default_value.replace("'", "''")
                    clause += f" NOT NULL DEFAULT '{escaped}'"
                else:
                    # No usable default: adding NOT NULL would fail on a
                    # populated table. Add it nullable and say so, rather
                    # than aborting startup.
                    logger.warning(
                        "Adding %s.%s as NULLABLE: the model declares it NOT NULL but supplies "
                        "no scalar default, and a NOT NULL column cannot be added to a table "
                        "with existing rows without one.",
                        table_name, column.name,
                    )

            statement = f"ALTER TABLE {table_name} {clause}"
            try:
                with engine.begin() as conn:
                    conn.execute(text(statement))
                logger.info("Schema migration: added %s.%s", table_name, column.name)
            except Exception as exc:  # noqa: BLE001
                logger.error("Schema migration failed for %s.%s (%s).", table_name, column.name, exc)

        # Relax a NOT NULL that the models no longer impose.
        #
        # Adding columns is not enough on its own: making an EXISTING
        # column nullable is a schema change too, and without it an
        # upgraded install still rejects rows the current code considers
        # valid. That is exactly what happened when the TACACS+ shared
        # secret became optional for RADIUS-only devices.
        #
        # Only ever DROPs NOT NULL, never adds one. Widening a
        # constraint cannot fail on existing data and cannot lose any;
        # tightening one can do both, so it is deliberately not done
        # here.
        try:
            actual_meta = {c["name"]: c for c in inspector.get_columns(table_name)}
        except Exception:
            continue
        for column in table.columns:
            meta = actual_meta.get(column.name)
            if meta is None:
                continue
            db_not_null = not meta.get("nullable", True)
            if column.nullable and db_not_null and not column.primary_key:
                try:
                    with engine.begin() as conn:
                        conn.execute(text(
                            f"ALTER TABLE {table_name} ALTER COLUMN {column.name} DROP NOT NULL"
                        ))
                    logger.info("Schema migration: %s.%s is now nullable", table_name, column.name)
                except Exception as exc:  # noqa: BLE001
                    logger.error(
                        "Could not relax NOT NULL on %s.%s (%s).", table_name, column.name, exc
                    )
