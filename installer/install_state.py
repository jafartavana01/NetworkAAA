"""
installer.install_state
==========================
Detects whether this machine already has a NetworkAAA installation, and
checks the live database schema against the current models.

Why this exists
---------------
`setup.py` was already largely re-runnable: PostgreSQL provisioning
checks whether the role exists, the admin phase skips creation when
accounts are present (and records a `reinstall` InstallEvent), and the
TLS and platform-settings phases both guard on file existence. What was
missing was (a) telling the operator which mode they are in, and (b)
catching the one schema change `create_all()` genuinely cannot make.

The `create_all()` limitation, precisely
----------------------------------------
`Base.metadata.create_all()` creates tables that do not exist. It does
NOT alter tables that do. So on an upgrade:

  * a brand-new table (e.g. the NCM tables) is created correctly;
  * a NEW COLUMN on an EXISTING table is silently skipped.

The second case is the dangerous one: nothing fails during install, and
the application then errors at runtime with a confusing
"column does not exist" deep inside an unrelated query. `check_schema_drift`
turns that into a clear, up-front report naming the exact tables and
columns, so an operator knows what happened instead of debugging it.

This module deliberately only REPORTS drift. It does not ALTER
anything: silently mutating a production schema during what the
operator asked to be an install is a bigger risk than telling them
plainly what needs to change. Applying migrations is its own,
separately-reviewed step.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

#: Files whose presence indicates a prior install. The database
#: credentials file is the strongest signal: it is written once, during
#: provisioning, and its absence means no database was ever set up.
CREDENTIALS_PATH = Path("/etc/aaa-platform/db_credentials.json")
INSTALL_ROOT = Path("/opt/aaa-platform")
GENERATED_CONF_PATH = Path("/etc/aaa-platform/tac_plus_generated.cfg")


@dataclass
class InstallState:
    is_installed: bool
    has_credentials: bool
    has_install_root: bool
    has_generated_config: bool
    admin_count: int | None = None       # None = could not be queried
    previous_install_at: str | None = None
    detail: str = ""

    @property
    def mode(self) -> str:
        return "upgrade" if self.is_installed else "fresh install"


def detect_install_state() -> InstallState:
    """
    Filesystem-only detection, deliberately: this runs BEFORE the
    application's dependencies are guaranteed to be installed, so it
    cannot import SQLAlchemy or the app package. Database-derived
    detail (admin count, previous install time) is filled in later by
    `enrich_from_database`, once those imports are safe.
    """
    has_credentials = CREDENTIALS_PATH.exists()
    has_root = INSTALL_ROOT.exists()
    has_config = GENERATED_CONF_PATH.exists()

    # Credentials are the deciding signal. An install root without
    # credentials means a copy that never completed provisioning --
    # treated as a fresh install, which is the safe reading: it will
    # provision what is missing rather than assume state it cannot see.
    is_installed = has_credentials

    return InstallState(
        is_installed=is_installed,
        has_credentials=has_credentials,
        has_install_root=has_root,
        has_generated_config=has_config,
        detail=(
            "Existing installation detected."
            if is_installed
            else "No previous installation detected."
        ),
    )


def enrich_from_database(state: InstallState) -> InstallState:
    """
    Adds admin count and the most recent install event, once the app
    package is importable. Failure here is NOT fatal -- a database that
    cannot be queried yet simply leaves these as None rather than
    aborting an install.
    """
    try:
        from app.database import get_sessionmaker
        from app.models.admin import AdminUser
        from app.models.system_info import InstallEvent

        session_local = get_sessionmaker()
        db = session_local()
        try:
            state.admin_count = db.query(AdminUser).count()
            last = db.query(InstallEvent).order_by(InstallEvent.occurred_at.desc()).first()
            if last is not None and last.occurred_at is not None:
                state.previous_install_at = last.occurred_at.isoformat(timespec="seconds")
        finally:
            db.close()
    except Exception:
        # Intentionally swallowed: this is diagnostic detail, not a
        # precondition. On a fresh install the tables do not exist yet.
        pass
    return state


@dataclass
class SchemaDrift:
    missing_tables: list[str] = field(default_factory=list)
    #: table -> [column names present in the models but not the database]
    missing_columns: dict[str, list[str]] = field(default_factory=dict)

    @property
    def has_drift(self) -> bool:
        return bool(self.missing_tables or self.missing_columns)

    def summary_lines(self) -> list[str]:
        lines = []
        for t in sorted(self.missing_tables):
            lines.append(f"table '{t}' is missing entirely")
        for t, cols in sorted(self.missing_columns.items()):
            lines.append(f"table '{t}' is missing column(s): {', '.join(sorted(cols))}")
        return lines


def check_schema_drift() -> SchemaDrift:
    """
    Compares every column the models declare against what the live
    database actually has.

    Missing TABLES should normally be empty, because `init_db()` runs
    `create_all()` just before this -- if a table is still missing,
    something is genuinely wrong and worth saying so.

    Missing COLUMNS are the real finding: `create_all()` cannot add a
    column to a table that already exists, so this is exactly the case
    an upgrade hits and a fresh install never does.

    Only additive drift is reported. A column present in the database
    but no longer in the models is NOT flagged: that is what a removed
    feature leaves behind, it breaks nothing, and dropping it would
    destroy data the operator never asked to lose.
    """
    from sqlalchemy import inspect

    from app.database import Base, get_engine

    drift = SchemaDrift()
    inspector = inspect(get_engine())
    existing_tables = set(inspector.get_table_names())

    for table_name, table in Base.metadata.tables.items():
        if table_name not in existing_tables:
            drift.missing_tables.append(table_name)
            continue
        actual_columns = {c["name"] for c in inspector.get_columns(table_name)}
        expected_columns = {c.name for c in table.columns}
        missing = expected_columns - actual_columns
        if missing:
            drift.missing_columns[table_name] = sorted(missing)

    return drift


def generate_migration_sql(drift: SchemaDrift) -> list[str]:
    """
    Produces the `ALTER TABLE ... ADD COLUMN` statements that would
    resolve the reported column drift, for an operator to review and
    run themselves.

    Emitted as text rather than executed, and every added column is
    nullable regardless of how the model declares it: adding a NOT NULL
    column to a table with existing rows fails unless a default is
    supplied, and inventing a default for someone else's production
    data is not a decision this installer should make silently.
    """
    from app.database import Base

    statements: list[str] = []
    for table_name, columns in sorted(drift.missing_columns.items()):
        table = Base.metadata.tables.get(table_name)
        if table is None:
            continue
        for col_name in columns:
            col = table.columns.get(col_name)
            if col is None:
                continue
            try:
                type_sql = col.type.compile(dialect=get_dialect())
            except Exception:
                type_sql = str(col.type)
            statements.append(
                f"ALTER TABLE {table_name} ADD COLUMN IF NOT EXISTS {col_name} {type_sql};"
            )
    return statements


def get_dialect():
    from app.database import get_engine
    return get_engine().dialect
