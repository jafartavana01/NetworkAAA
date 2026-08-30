#!/usr/bin/env python3
"""
AAA Management Platform -- Installer
======================================
Run as:  sudo python3 setup.py

Performs the full Phase 1 bootstrap (spec section 50): detects the
Ubuntu environment, downloads and builds tac_plus-ng from the real
upstream source, provisions PostgreSQL, installs this management
application (no virtualenv), creates a least-privilege service
account, generates and enables systemd units, writes an initial
bootstrap tac_plus-ng configuration so the daemon can actually start,
seeds the first platform administrator account, and starts both
services.

This script is the orchestrator only -- the actual logic lives in the
`installer/` package next to it, and the management application's own
source lives in `app/`. Both must be present alongside this file (see
installer.app_install.copy_application_source).
"""
from __future__ import annotations

import sys
import traceback
from pathlib import Path

import grp
import pwd

PROJECT_ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(PROJECT_ROOT))

from installer import (  # noqa: E402
    apt_deps,
    app_install,
    bootstrap_config,
    postgres_setup,
    prompts,
    sudoers_setup,
    system_checks,
    systemd_setup,
    uninstall,
    upstream_build,
    utils,
)

MIN_SUPPORTED_NOTE = (
    "If your platform is close to, but not exactly, a supported configuration, "
    "you can still choose to continue manually -- but automated support is not guaranteed."
)


def phase_system_detection() -> system_checks.SystemReport:
    utils.header("AAA Management Platform Installer")
    report = system_checks.gather()
    system_checks.print_report(report)

    problems = report.fatal_problems
    if problems:
        utils.section("Problems Detected")
        for p in problems:
            utils.error(p)
        utils.info(MIN_SUPPORTED_NOTE)
        if not utils.confirm("Continue anyway despite the problems above?", default_yes=False):
            utils.error("Installation aborted.")
            sys.exit(1)

    if not report.internet_available:
        utils.error(
            "No Internet connectivity detected. This installer needs network "
            "access once, to download tac_plus-ng source and apt packages. "
            "Runtime after installation does not require Internet (spec section 1)."
        )
        sys.exit(1)

    return report


def phase_dependencies() -> None:
    utils.header("Installing System Dependencies")
    if utils.confirm("Run 'apt-get update' to refresh the package index first?", default_yes=True):
        apt_deps.update_package_index()
    else:
        utils.info("Skipping 'apt-get update' -- installing from whatever package index already exists.")
    apt_deps.ensure_packages(apt_deps.ALL_PACKAGES)


def phase_build_tac_plus_ng(report: system_checks.SystemReport) -> dict:
    utils.header("tac_plus-ng -- Download, Configure, Build, Install")

    commit = upstream_build.clone_or_update_upstream()

    profiles = upstream_build.build_profiles()
    profile = prompts.choose_build_profile(profiles)

    if profile.key == "custom":
        options = upstream_build.discover_configure_options()
        configure_args = prompts.choose_custom_flags(options)
    else:
        configure_args = profile.configure_args

    if not prompts.confirm_installation_summary(profile=profile, configure_args=configure_args):
        utils.error("Installation aborted by administrator.")
        sys.exit(1)

    configure_output = upstream_build.run_configure(configure_args)
    upstream_build.run_make()
    upstream_build.run_make_install()

    binary_path = upstream_build.locate_binary()
    if not binary_path:
        raise utils.InstallError(
            "tac_plus-ng was built and 'make install' succeeded, but the "
            "resulting binary could not be located in any known install path. "
            "Check /var/log/aaa-platform/tac_plus-ng-build.log."
        )
    utils.ok(f"tac_plus-ng binary located at {binary_path}")

    version_string = upstream_build.probe_version(binary_path)
    upstream_build.discover_runtime_usage(binary_path)

    build_info = upstream_build.record_build_info(
        commit=commit,
        profile=profile,
        configure_args=configure_args,
        configure_output=configure_output,
        binary_path=binary_path,
        version_string=version_string,
        system_report=report,
    )
    return build_info


def phase_database() -> None:
    utils.header("PostgreSQL Provisioning")
    postgres_setup.provision_database()


def phase_application_install() -> None:
    utils.header("Installing Management Application")
    app_install.ensure_service_account()
    app_install.create_directories()
    app_install.copy_application_source(PROJECT_ROOT)
    app_install.install_python_dependencies(PROJECT_ROOT)
    app_install.fix_etc_file_ownership()
    app_install.provision_secret_files()
    sudoers_setup.install_sudoers_rule()


def phase_schema_and_admin() -> None:
    utils.header("Database Schema & Initial Administrator")

    # Import lazily: these come from the app package whose dependencies
    # (fastapi/sqlalchemy/passlib/...) were only just installed above.
    sys.path.insert(0, str(app_install.INSTALL_ROOT))
    from app.database import init_db, get_sessionmaker  # noqa: E402
    from app.models.admin import AdminUser  # noqa: E402
    from app.models.system_info import InstallEvent  # noqa: E402
    from app.security import hash_password  # noqa: E402

    utils.info("Creating database schema...")
    init_db()
    utils.ok("Schema created.")

    session_local = get_sessionmaker()
    db = session_local()
    try:
        existing_admin_count = db.query(AdminUser).count()
        if existing_admin_count == 0:
            username, password = prompts.create_initial_admin()
            admin = AdminUser(
                username=username,
                password_hash=hash_password(password),
                is_active=True,
                is_superadmin=True,
            )
            db.add(admin)
            db.add(InstallEvent(event_type="initial_install", detail=f"Created admin '{username}'."))
            db.commit()
            utils.ok(f"Administrator account '{username}' created.")
        else:
            utils.info(f"{existing_admin_count} administrator account(s) already exist -- skipping creation.")
            db.add(InstallEvent(event_type="reinstall", detail="setup.py re-run; admin accounts unchanged."))
            db.commit()
    finally:
        db.close()


def phase_tls_and_settings() -> None:
    """
    Generates the default self-signed HTTPS certificate and writes the
    default platform settings file (host/port/HTTPS toggle) -- both
    reused directly from the real app package (not duplicated logic),
    since by this point in the install the app source is already
    copied and its dependencies (including `cryptography`) are already
    installed. HTTPS itself defaults to OFF (plain HTTP on port 8420,
    matching every prior phase's behavior) -- generating a cert
    doesn't silently change what the installer already set up; an
    admin turns HTTPS on explicitly via Platform Settings once ready.
    """
    utils.header("HTTPS Certificate & Platform Settings")

    import os
    import socket

    sys.path.insert(0, str(app_install.INSTALL_ROOT))
    from app import platform_settings  # noqa: E402
    from app.services import tls_certs  # noqa: E402

    uid = pwd.getpwnam(app_install.SERVICE_USER).pw_uid
    gid = grp.getgrnam(app_install.SERVICE_GROUP).gr_gid

    if tls_certs.CERT_PATH.exists() and tls_certs.KEY_PATH.exists():
        utils.info("Existing TLS certificate found -- leaving it in place.")
    else:
        hostname = socket.gethostname()
        cert_pem, key_pem = tls_certs.generate_self_signed(
            common_name=hostname,
            organization="AAA Management Platform",
        )
        tls_certs.write_active_certificate(cert_pem, key_pem, uid=uid, gid=gid)
        utils.ok(f"Generated default self-signed certificate (CN={hostname}).")
        utils.info(
            "HTTPS is generated but NOT enabled by default -- turn it on under "
            "Platform Settings once you've confirmed the GUI is reachable over "
            "plain HTTP first."
        )

    if not platform_settings.SETTINGS_PATH.exists():
        platform_settings.save_settings(platform_settings.DEFAULTS)
        os.chown(platform_settings.SETTINGS_PATH, uid, gid)
        utils.ok(f"Wrote default platform settings to {platform_settings.SETTINGS_PATH}")
    else:
        utils.info("Existing platform settings found -- leaving them in place.")


def phase_bootstrap_tac_config(binary_path: str) -> None:
    utils.header("Bootstrap tac_plus-ng Configuration")
    bootstrap_config.write_bootstrap_config()
    ok, output = bootstrap_config.validate_syntax(binary_path)
    if ok:
        utils.ok("Bootstrap configuration syntax check passed.")
    else:
        utils.warn(
            "Could not confirm configuration syntax via the binary's -P flag "
            "(this flag was verified for legacy tac_plus, not independently "
            "confirmed for tac_plus-ng). Proceeding -- the real check is "
            "whether the service reaches 'active' after start."
        )
        if output:
            utils.info(output[:500])


def phase_systemd(binary_path: str) -> None:
    utils.header("systemd Services")
    systemd_setup.write_management_unit()
    systemd_setup.write_tac_plus_ng_unit(binary_path)
    systemd_setup.reload_and_enable(
        [systemd_setup.MANAGEMENT_UNIT_NAME], start=True
    )

    ok, mgmt_status = systemd_setup.run_first_start_diagnostic(systemd_setup.MANAGEMENT_UNIT_NAME)
    if ok:
        utils.ok(f"{systemd_setup.MANAGEMENT_UNIT_NAME} is active.")
    else:
        utils.error(f"{systemd_setup.MANAGEMENT_UNIT_NAME} did not stay active. Recent journal:")
        print(mgmt_status)

    systemd_setup.reload_and_enable(
        [systemd_setup.TAC_PLUS_NG_UNIT_NAME], start=True
    )
    ok, tac_status = systemd_setup.run_first_start_diagnostic(systemd_setup.TAC_PLUS_NG_UNIT_NAME)
    if ok:
        utils.ok(f"{systemd_setup.TAC_PLUS_NG_UNIT_NAME} is active and listening on TCP/49.")
    else:
        utils.warn(
            f"{systemd_setup.TAC_PLUS_NG_UNIT_NAME} did not stay active. This is the "
            "item flagged as unverified in installer/systemd_setup.py (daemonization "
            "behavior / correct foreground flag) -- recent journal below:"
        )
        print(tac_status)


def print_summary(build_info: dict) -> None:
    utils.header("Installation Summary")
    utils.ok("Management GUI:  http://<server-ip>:8420  (plain HTTP by default -- listens on all interfaces)")
    utils.info("Port, bind address, and HTTPS (self-signed cert already generated, "
               "not yet enabled) are all configurable after login under Platform -> Settings.")
    utils.ok(f"tac_plus-ng     : {build_info.get('tac_plus_ng_version_string', 'unknown')}")
    utils.ok(f"Commit          : {build_info.get('commit', 'unknown')[:12]}")
    utils.ok(f"Build profile   : {build_info.get('build_profile', 'unknown')}")
    utils.info("Full build record: /etc/aaa-platform/build_info.json")
    utils.info("Install log      : /tmp/aaa-platform-install.log")
    utils.info("Next steps       : Phase 8 (Module Management) adds a GUI page showing")
    utils.info("                   installed/enabled/status per module -- the last phase.")


def main() -> None:
    try:
        report = phase_system_detection()
        phase_dependencies()
        build_info = phase_build_tac_plus_ng(report)
        phase_database()
        phase_application_install()
        phase_schema_and_admin()
        phase_tls_and_settings()
        phase_bootstrap_tac_config(build_info["binary_path"])
        app_install.final_ownership_sweep()
        phase_systemd(build_info["binary_path"])
        print_summary(build_info)
    except utils.InstallError as exc:
        utils.error(str(exc))
        utils.info(f"See {utils.LOG_PATH} for the full command log.")
        sys.exit(1)
    except KeyboardInterrupt:
        utils.error("Installation cancelled by administrator.")
        sys.exit(130)
    except Exception:  # pragma: no cover - top-level safety net
        utils.error("Unexpected installer failure:")
        traceback.print_exc()
        utils.info(f"See {utils.LOG_PATH} for the full command log.")
        sys.exit(1)


def run_uninstall(*, force: bool, keep_logs: bool) -> None:
    try:
        uninstall.run_uninstall(force=force, keep_logs=keep_logs)
    except utils.InstallError as exc:
        utils.error(str(exc))
        utils.info(f"See {utils.LOG_PATH} for the full command log.")
        sys.exit(1)
    except KeyboardInterrupt:
        utils.error("Uninstall cancelled by administrator.")
        sys.exit(130)
    except Exception:  # pragma: no cover - top-level safety net
        utils.error("Unexpected uninstaller failure:")
        traceback.print_exc()
        utils.info(f"See {utils.LOG_PATH} for the full command log.")
        sys.exit(1)


def parse_args(argv: list[str]):
    import argparse
    parser = argparse.ArgumentParser(
        description="AAA Management Platform installer. With no arguments, runs the full install."
    )
    parser.add_argument(
        "-u", "--uninstall", action="store_true",
        help="Remove this platform (and only this platform -- not Python, pip packages, "
             "or apt-installed system software such as the PostgreSQL server itself).",
    )
    parser.add_argument(
        "-y", "--force", action="store_true",
        help="With --uninstall, skip the confirmation prompt. Ignored otherwise.",
    )
    parser.add_argument(
        "--keep-logs", action="store_true",
        help="With --uninstall, preserve /var/log/aaa-platform instead of deleting it. Ignored otherwise.",
    )
    return parser.parse_args(argv)


if __name__ == "__main__":
    if sys.version_info[:2] < (3, 8):
        print("Python 3.8+ is required to run this installer.", file=sys.stderr)
        sys.exit(1)

    args = parse_args(sys.argv[1:])
    if args.uninstall:
        run_uninstall(force=args.force, keep_logs=args.keep_logs)
    else:
        main()
