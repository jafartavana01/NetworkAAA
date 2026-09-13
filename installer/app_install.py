"""
installer.app_install
=======================
Lays out the filesystem structure from spec section 41, creates a
dedicated least-privilege service account (section 33/35), copies the
management application source into /opt/aaa-platform, and installs its
Python dependencies directly into the system interpreter -- explicitly
NOT a virtualenv (spec section 7).

Directory layout created:

  /opt/aaa-platform/
      app/            <- this application's source (copied from the
                          project tree that ships alongside setup.py)
      upstream/        <- tac_plus-ng source checkout (installer.upstream_build)
      generated/       <- generated tac_plus-ng.conf candidates/history
      backups/         <- configuration backups
  /etc/aaa-platform/
      config/          <- application settings, build_info.json, db creds
  /var/lib/aaa-platform/
      data/            <- non-DB persistent state
  /var/log/aaa-platform/
      application.log
      audit.log
"""
from __future__ import annotations

import grp
import os
import pwd
import shutil
from pathlib import Path

from . import utils

SERVICE_USER = "aaa-platform"
SERVICE_GROUP = "aaa-platform"

INSTALL_ROOT = Path("/opt/aaa-platform")
APP_DIR = INSTALL_ROOT / "app"
GENERATED_DIR = INSTALL_ROOT / "generated"
BACKUPS_DIR = INSTALL_ROOT / "backups"

ETC_DIR = Path("/etc/aaa-platform")
CONFIG_DIR = ETC_DIR / "config"
TLS_DIR = ETC_DIR / "tls"  # must match app.services.tls_certs.TLS_DIR exactly

VAR_LIB_DIR = Path("/var/lib/aaa-platform/data")
LOG_DIR = Path("/var/log/aaa-platform")

DIRECTORIES = [INSTALL_ROOT, APP_DIR, GENERATED_DIR, BACKUPS_DIR, ETC_DIR, CONFIG_DIR, TLS_DIR, VAR_LIB_DIR, LOG_DIR]


def ensure_service_account() -> None:
    try:
        pwd.getpwnam(SERVICE_USER)
        utils.info(f"Service account '{SERVICE_USER}' already exists.")
        return
    except KeyError:
        pass

    utils.info(f"Creating least-privilege service account '{SERVICE_USER}'.")
    utils.run([
        "useradd",
        "--system",
        "--no-create-home",
        "--shell", "/usr/sbin/nologin",
        "--user-group",
        SERVICE_USER,
    ])
    utils.ok(f"Service account '{SERVICE_USER}' created.")


def create_directories() -> None:
    uid = pwd.getpwnam(SERVICE_USER).pw_uid
    gid = grp.getgrnam(SERVICE_GROUP).gr_gid

    for d in DIRECTORIES:
        d.mkdir(parents=True, exist_ok=True)

    # App/log/generated/backup/data/config/tls dirs are owned by the
    # service account -- CONFIG_DIR and TLS_DIR specifically because the
    # RUNNING service needs to write to them at runtime (platform
    # settings changes, certificate regeneration/upload from the GUI),
    # unlike /etc/aaa-platform itself, which stays root-owned/group-
    # readable-only so the service can't modify its own credentials or
    # build record (db_credentials.json, build_info.json).
    for d in (APP_DIR, GENERATED_DIR, BACKUPS_DIR, VAR_LIB_DIR, LOG_DIR, CONFIG_DIR, TLS_DIR):
        _chown_recursive(d, uid, gid)
        d.chmod(0o750)

    ETC_DIR.chmod(0o750)
    subprocess_chgrp(ETC_DIR, SERVICE_GROUP)
    utils.ok("Directory layout created under /opt, /etc, /var/lib, /var/log.")


def fix_etc_file_ownership() -> None:
    """
    db_credentials.json and build_info.json are written earlier in the
    install by code running as root -- before this function's caller
    is guaranteed to run, and regardless, before anything hands them
    to the service account. The aaa-platform service needs to READ
    both at runtime, but /etc/aaa-platform is deliberately NOT
    group-writable (spec section 33: least privilege -- the runtime
    service shouldn't be able to modify its own credentials or build
    record). Rather than loosen the directory, this fixes ownership of
    exactly the files the service needs to read, in place, now that
    the service account is guaranteed to exist.

    This bug was caught by a real failed install: aaa-platform.service
    exiting immediately with a generic failure, root-caused to the
    service being unable to read its own database credentials.
    """
    uid = pwd.getpwnam(SERVICE_USER).pw_uid
    gid = grp.getgrnam(SERVICE_GROUP).gr_gid

    for name in ("db_credentials.json", "build_info.json"):
        path = ETC_DIR / name
        if not path.exists():
            continue
        os.chown(path, uid, gid)
        path.chmod(0o640)  # owner(root) rw, group(service account) r, other: nothing
    utils.ok("Fixed ownership of existing /etc/aaa-platform files for the service account.")


def provision_secret_files() -> None:
    """
    Pre-creates the two lazily-generated runtime secrets (session
    signing key, device-shared-secret Fernet encryption key) at
    install time, as root, with ownership handed to the service
    account -- rather than letting the unprivileged aaa-platform
    service try to create them itself on first startup, which would
    require write access to /etc/aaa-platform that it deliberately
    doesn't have. Idempotent: an existing file is left untouched (only
    re-chowned) so re-running the installer doesn't rotate secrets and
    invalidate existing sessions or already-encrypted device secrets.

    Requires the `cryptography` package, so this must run after
    install_python_dependencies(), not before.
    """
    import secrets as secrets_module
    from cryptography.fernet import Fernet

    uid = pwd.getpwnam(SERVICE_USER).pw_uid
    gid = grp.getgrnam(SERVICE_GROUP).gr_gid

    session_secret_path = ETC_DIR / "session_secret.key"
    if not session_secret_path.exists():
        session_secret_path.write_text(secrets_module.token_urlsafe(64), encoding="utf-8")
        utils.ok(f"Generated {session_secret_path}")
    os.chown(session_secret_path, uid, gid)
    session_secret_path.chmod(0o600)

    encryption_key_path = ETC_DIR / "secret_encryption.key"
    if not encryption_key_path.exists():
        encryption_key_path.write_text(Fernet.generate_key().decode("utf-8"), encoding="utf-8")
        utils.ok(f"Generated {encryption_key_path}")
    os.chown(encryption_key_path, uid, gid)
    encryption_key_path.chmod(0o600)
    utils.ok("Provisioned session and secret-encryption keys for the service account.")


def final_ownership_sweep() -> None:
    """
    Defense in depth, not the primary fix: a second, final recursive
    chown pass over the directories the aaa-platform service must be
    able to write to, run at the very end of installation after every
    other phase (including tac_plus-ng build artifacts and the
    bootstrap config) has finished writing files as root.

    This exact bug class -- a root-run installer step writing a file
    as root inside a directory that's *supposed* to be owned by the
    service account, with the file itself never getting individually
    chowned -- has now been hit three times (db_credentials.json,
    build_info.json, and the bootstrap tac_plus-ng.conf), each
    requiring a real failed install to surface. Rather than keep
    relying on remembering to chown every new file individually and
    reasoning carefully about phase ordering, this sweep makes the
    whole bug class structurally harder to reintroduce: whatever gets
    missed at its point of creation is caught here regardless.

    Deliberately does NOT touch /etc/sudoers.d or
    /etc/systemd/system -- those must stay root-owned; a compromised
    service account being able to rewrite its own sudo grant or
    systemd unit would be a real privilege-escalation path, not a
    permissions bug to "fix".
    """
    uid = pwd.getpwnam(SERVICE_USER).pw_uid
    gid = grp.getgrnam(SERVICE_GROUP).gr_gid

    for d in (APP_DIR, GENERATED_DIR, BACKUPS_DIR, VAR_LIB_DIR, LOG_DIR):
        _chown_recursive(d, uid, gid)

    fix_etc_file_ownership()
    utils.ok("Final ownership sweep complete.")


def subprocess_chgrp(path: Path, group: str) -> None:
    utils.run(["chgrp", "-R", group, str(path)])


def _chown_recursive(path: Path, uid: int, gid: int) -> None:
    for root, dirs, files in _walk(path):
        for name in dirs + files:
            p = Path(root) / name
            try:
                os.chown(p, uid, gid)
            except OSError:
                pass
    try:
        os.chown(path, uid, gid)
    except OSError:
        pass


def _walk(path: Path):
    yield from os.walk(path)


def copy_application_source(project_root: Path) -> None:
    """
    Copies the `app/` tree that ships alongside setup.py into the
    installed location. This installer's own project directory is the
    source of truth for the management-plane application code; only
    tac_plus-ng itself is fetched from the network at install time.
    """
    src = project_root / "app"
    if not src.exists():
        raise utils.InstallError(
            f"Application source not found at {src}. The installer expects "
            "to be run from within the project directory that contains "
            "both setup.py and the app/ source tree."
        )

    utils.info(f"Copying application source from {src} to {APP_DIR} ...")
    if APP_DIR.exists():
        shutil.rmtree(APP_DIR)
    shutil.copytree(src, APP_DIR)
    utils.ok("Application source installed.")


def _pip_needs_break_system_packages() -> bool:
    import sysconfig
    stdlib = Path(sysconfig.get_paths()["stdlib"])
    marker = stdlib / "EXTERNALLY-MANAGED"
    return marker.exists()


def install_python_dependencies(project_root: Path) -> None:
    """
    Installs directly into the system Python -- no venv is created, per
    spec section 7. On Ubuntu 23.04+ (and backported to 22.04/24.04 in
    some images) pip refuses system-wide installs unless
    --break-system-packages is passed (PEP 668); we detect that via the
    EXTERNALLY-MANAGED marker rather than assuming.

    Two failure modes are handled by retrying narrowly, NOT by weakening
    the base install command for every run -- a blanket workaround here
    would defeat pip's normal "already satisfied, nothing to do" check
    and force a full re-download of every dependency on every single
    re-run, which is exactly the wrong trade-off on a host with flaky
    connectivity:

    1. Debian-packaged system Python modules with no pip RECORD file
       (observed: Jinja2, pulled in by unrelated Ubuntu tooling). A
       plain `pip install` can refuse to proceed trying to safely
       replace one of these, even when the already-installed version
       already satisfies our requirement. Rather than passing
       `--ignore-installed` for the whole command (which would make
       pip re-verify and reinstall *every* package on *every* run),
       this parses the specific package name(s) pip names in that
       error, takes ownership of only those with a scoped
       `pip install --ignore-installed <name>`, then retries the full
       requirements.txt install normally. After that one-time
       ownership transfer, pip's own RECORD file exists for that
       package and future runs see it as already satisfied like
       everything else -- no more forced reinstalls, no more
       re-downloads of the whole dependency set.

    2. A dependency's Rust extension (pydantic-core, etc.) predating
       this Python version's support in PyO3, which fails a source
       build outright rather than just being slow. Retried once with
       PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 -- PyO3's own documented
       escape hatch to build against the stable ABI regardless. The
       version floors in requirements.txt address the specific case
       found during testing (pydantic-core needing pydantic>=2.12.1
       for real Python 3.14 wheels); this is a fallback for whatever
       the next one of these turns out to be, not a substitute for it.
    """
    requirements = project_root / "requirements.txt"
    if not requirements.exists():
        raise utils.InstallError(f"requirements.txt not found at {requirements}")

    needs_break_system_packages = _pip_needs_break_system_packages()

    def _base_argv() -> list[str]:
        argv = ["pip3", "install", "--no-cache-dir", "-r", str(requirements)]
        if needs_break_system_packages:
            argv.insert(2, "--break-system-packages")
        return argv

    def _run_pip(argv: list[str], env: dict | None = None) -> utils.CommandResult:
        return utils.run(argv, timeout=600, check=False, env=env)

    if needs_break_system_packages:
        utils.info("Externally-managed Python detected -- using --break-system-packages (no venv, per requirements).")
    utils.info("Installing Python dependencies into the system interpreter...")

    result = _run_pip(_base_argv())
    output = result.stdout + result.stderr

    if not result.ok and ("uninstall-no-record-file" in output or "no RECORD file was found" in output):
        import re
        conflicting = sorted(set(re.findall(r"Cannot uninstall ([A-Za-z0-9_.\-]+)", output)))
        if conflicting:
            utils.warn(
                f"{', '.join(conflicting)} is present as a Debian-packaged system module with "
                "no pip metadata. Taking ownership of just that package with pip, then "
                "retrying the full install normally (this only happens once)."
            )
            ownership_argv = ["pip3", "install", "--no-cache-dir", "--ignore-installed"] + conflicting
            if needs_break_system_packages:
                ownership_argv.insert(2, "--break-system-packages")
            ownership_result = _run_pip(ownership_argv)
            if not ownership_result.ok:
                raise utils.InstallError(
                    f"Could not take ownership of {', '.join(conflicting)} via pip:\n"
                    f"{ownership_result.stdout}{ownership_result.stderr}"
                )
            result = _run_pip(_base_argv())
            output = result.stdout + result.stderr

    if not result.ok and ("PyO3" in output or "maturin" in output):
        utils.warn(
            "A dependency's Rust extension doesn't yet recognize this Python version. "
            "Retrying once with PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 (builds against the "
            "stable ABI regardless)..."
        )
        import os
        retry_env = {**os.environ, "PYO3_USE_ABI3_FORWARD_COMPATIBILITY": "1"}
        result = _run_pip(_base_argv(), env=retry_env)
        output = result.stdout + result.stderr

    if not result.ok:
        raise utils.InstallError(f"pip install failed:\n{output}")

    utils.ok("Python dependencies installed.")
