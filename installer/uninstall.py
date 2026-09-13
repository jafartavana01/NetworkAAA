"""
installer.uninstall
=====================
Removes everything this platform's installer created -- and nothing
else. Explicitly does NOT remove: Python, pip, or any apt-installed
system package (build tools, the PostgreSQL *server* itself, dev
libraries) -- those were dependencies this installer used, not things
it owns, and other software on the machine could depend on them.

What gets removed:
  - Both systemd services (stopped, disabled, unit files deleted)
  - The tac_plus-ng binary this installer built and installed
  - /opt/aaa-platform (app code, generated config, backups, and the
    upstream source checkout, all nested under this one root)
  - /etc/aaa-platform (secrets, TLS certs, settings, build record)
  - /var/lib/aaa-platform (data dir)
  - /var/log/aaa-platform (logs) -- unless keep_logs=True
  - The scoped sudoers rule (/etc/sudoers.d/aaa-platform)
  - The PostgreSQL database and role THIS installer created
    (postgres_setup.DB_NAME/DB_USER) -- never the PostgreSQL server or
    any other database on the instance
  - The service account (a system user with an auto-managed private
    group of the same name, created with `useradd --user-group`)

Every step checks whether its target actually exists before trying to
remove it, so this is safe to re-run and safe to run against a
partial or already-completed install -- nothing here assumes a full,
successful install happened first.
"""
from __future__ import annotations

import pwd
import shutil
from pathlib import Path

from . import app_install, postgres_setup, sudoers_setup, systemd_setup, upstream_build, utils


def _stop_and_disable_services() -> None:
    for unit in (systemd_setup.MANAGEMENT_UNIT_NAME, systemd_setup.TAC_PLUS_NG_UNIT_NAME):
        utils.run(["systemctl", "stop", unit], check=False)
        utils.run(["systemctl", "disable", unit], check=False)
        unit_path = systemd_setup.SYSTEMD_DIR / unit
        if unit_path.exists():
            unit_path.unlink()
            utils.ok(f"Removed systemd unit {unit_path}.")
        else:
            utils.info(f"Systemd unit {unit_path} not present -- nothing to remove.")
    utils.run(["systemctl", "daemon-reload"], check=False)


def _remove_sudoers_rule() -> None:
    if sudoers_setup.SUDOERS_PATH.exists():
        sudoers_setup.SUDOERS_PATH.unlink()
        utils.ok(f"Removed {sudoers_setup.SUDOERS_PATH}.")
    else:
        utils.info(f"{sudoers_setup.SUDOERS_PATH} not present -- nothing to remove.")


def _drop_database_and_role() -> None:
    """Drops only the database/role this installer created -- never
    touches the PostgreSQL service or any other database on the
    instance."""
    if not shutil.which("psql"):
        utils.warn("psql not found -- skipping database cleanup (PostgreSQL may already be removed).")
        return

    if postgres_setup.database_exists(postgres_setup.DB_NAME):
        utils.run(
            ["sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-c",
             f"DROP DATABASE IF EXISTS {postgres_setup.DB_NAME}"],
            check=False,
        )
        utils.ok(f"Dropped database '{postgres_setup.DB_NAME}'.")
    else:
        utils.info(f"Database '{postgres_setup.DB_NAME}' not present -- nothing to drop.")

    if postgres_setup.role_exists(postgres_setup.DB_USER):
        utils.run(
            ["sudo", "-u", "postgres", "psql", "-v", "ON_ERROR_STOP=1", "-c",
             f"DROP ROLE IF EXISTS {postgres_setup.DB_USER}"],
            check=False,
        )
        utils.ok(f"Dropped role '{postgres_setup.DB_USER}'.")
    else:
        utils.info(f"Role '{postgres_setup.DB_USER}' not present -- nothing to drop.")


def _remove_tac_plus_ng_binary() -> None:
    binary_path = upstream_build.locate_binary()
    if binary_path and Path(binary_path).exists():
        Path(binary_path).unlink()
        utils.ok(f"Removed tac_plus-ng binary at {binary_path}.")
    else:
        utils.info("tac_plus-ng binary not found -- nothing to remove.")


def _remove_directory_preserving(target: Path, preserve: list) -> None:
    """
    Removes `target` but leaves the paths in `preserve` in place.

    Needed because the upstream source checkout lives INSIDE the
    install root, so a plain rmtree of the root takes it with it.
    Deleting entry by entry keeps the exception explicit rather than
    relying on the ordering of two separate removals.
    """
    kept_any = False
    for entry in sorted(target.iterdir()):
        # Three relationships matter, and getting them the wrong way
        # round deletes the thing being preserved:
        #   entry IS a preserved path            -> keep it
        #   entry is INSIDE a preserved path     -> keep it
        #   entry CONTAINS a preserved path      -> recurse, do not rmtree
        # The last one is the case that matters here: `upstream/` is an
        # ancestor of the checkout, not the checkout itself.
        if any(entry == keep or keep in entry.parents for keep in preserve):
            kept_any = True
            continue
        if any(entry in keep.parents for keep in preserve):
            _remove_directory_preserving(entry, preserve)
            kept_any = True
            continue
        if entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry, ignore_errors=True)
        else:
            try:
                entry.unlink()
            except OSError:
                pass

    if not kept_any:
        # Nothing under here needed preserving, so the directory itself
        # goes too rather than being left as an empty shell.
        shutil.rmtree(target, ignore_errors=True)


def _remove_directories(*, keep_logs: bool, keep_upstream: bool = True) -> None:
    # The upstream checkout is a clone of someone else's source, not
    # this product's data. Re-downloading it on the next install costs
    # time and needs internet on a box that may not have it, so it is
    # kept by default and the summary says so. --purge-upstream removes
    # it for anyone who genuinely wants the disk space back.
    preserve = []
    if keep_upstream and upstream_build.UPSTREAM_SRC_DIR.exists():
        preserve.append(upstream_build.UPSTREAM_SRC_DIR)

    targets = [app_install.INSTALL_ROOT, app_install.ETC_DIR, app_install.VAR_LIB_DIR.parent]
    if not keep_logs:
        targets.append(app_install.LOG_DIR)

    for target in targets:
        if not target.exists():
            utils.info(f"{target} not present -- nothing to remove.")
            continue
        relevant = [p for p in preserve if p == target or target in p.parents]
        if relevant:
            _remove_directory_preserving(target, relevant)
            utils.ok(f"Cleared {target} (upstream source checkout kept).")
        else:
            shutil.rmtree(target, ignore_errors=True)
            utils.ok(f"Removed {target}.")

    if keep_logs and app_install.LOG_DIR.exists():
        utils.info(f"Kept {app_install.LOG_DIR} (logs preserved on request).")

    if preserve and upstream_build.UPSTREAM_SRC_DIR.exists():
        utils.info(
            f"Kept {upstream_build.UPSTREAM_SRC_DIR} so the next install can reuse it "
            f"without downloading again (--purge-upstream to remove it)."
        )


def _remove_service_account() -> None:
    try:
        pwd.getpwnam(app_install.SERVICE_USER)
    except KeyError:
        utils.info(f"Service account '{app_install.SERVICE_USER}' not present -- nothing to remove.")
        return
    # --user-group at creation time means this is an auto-managed
    # private group of the same name -- userdel removes it along with
    # the account, no separate groupdel needed.
    utils.run(["userdel", "-r", app_install.SERVICE_USER], check=False)
    utils.ok(f"Removed service account '{app_install.SERVICE_USER}'.")


def describe_removal_plan(*, keep_logs: bool, keep_upstream: bool = True) -> list[str]:
    plan = [
        f"Systemd services: {systemd_setup.MANAGEMENT_UNIT_NAME}, {systemd_setup.TAC_PLUS_NG_UNIT_NAME} (stopped, disabled, unit files deleted)",
        "The tac_plus-ng binary this installer built and installed",
        f"Directory: {app_install.INSTALL_ROOT}",
        f"Directory: {app_install.ETC_DIR}",
        f"Directory: {app_install.VAR_LIB_DIR.parent}",
        f"Directory: {app_install.LOG_DIR}" + ("  (KEPT -- --keep-logs)" if keep_logs else ""),
        f"Sudoers rule: {sudoers_setup.SUDOERS_PATH}",
        f"PostgreSQL database '{postgres_setup.DB_NAME}' and role '{postgres_setup.DB_USER}' "
        "(the PostgreSQL server itself is NOT removed)",
        f"Service account '{app_install.SERVICE_USER}' (and its auto-managed private group)",
    ]
    if keep_upstream:
        plan.append(
            "NOT REMOVED -- the downloaded tac_plus-ng SOURCE CODE only: "
            f"{upstream_build.UPSTREAM_SRC_DIR}"
        )
        plan.append(
            "   (the service, its unit file and the installed binary ARE removed; "
            "only the source tree is kept so the next install skips the download. "
            "Use --purge-upstream to delete it too.)"
        )
    return plan


def run_uninstall(*, force: bool = False, keep_logs: bool = False, purge_upstream: bool = False) -> None:
    utils.header("Uninstalling AAA Management Platform")
    utils.info(
        "This removes ONLY what this platform's installer created. Python, "
        "pip-installed packages, and apt-installed system software -- "
        "including the PostgreSQL server itself -- are left untouched."
    )

    utils.section("The following will be removed:")
    for line in describe_removal_plan(keep_logs=keep_logs, keep_upstream=not purge_upstream):
        utils.info(f"  - {line}")

    if not force:
        if not utils.confirm("This is irreversible. Continue?", default_yes=False):
            utils.info("Uninstall cancelled -- nothing was changed.")
            return

    _stop_and_disable_services()
    _remove_sudoers_rule()
    _drop_database_and_role()
    _remove_tac_plus_ng_binary()
    _remove_directories(keep_logs=keep_logs, keep_upstream=not purge_upstream)
    _remove_service_account()

    utils.ok("Uninstall complete.")
    utils.info(
        "Removed: both systemd services (management and tac_plus-ng), their unit "
        "files, the tac_plus-ng binary, the database and role, the service account, "
        "and the application directories."
    )
    utils.info(
        "Not removed: Python, pip-installed packages, and apt-installed "
        "system software (including the PostgreSQL server itself)."
    )
    if not purge_upstream and upstream_build.UPSTREAM_SRC_DIR.exists():
        utils.info(
            f"Kept: {upstream_build.UPSTREAM_SRC_DIR} -- the downloaded source tree only. "
            "The next install will offer to reuse it instead of downloading again."
        )
