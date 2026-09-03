"""
installer.upstream_build
==========================
Handles spec sections 3/4/6/8-11/43: clone the real upstream
event-driven-servers repository, discover the *actual* configure
options by running `./configure --help` (never hard-coded), let the
administrator pick a build profile, build tac_plus-ng, install it, and
record exact, reproducible build metadata.

Verified against the upstream README (https://github.com/MarcJHuber/
event-driven-servers) at the time this installer was written:
  - Build is `./configure [options] tac_plus-ng && make && make install`.
  - Running configure with no feature flags builds "everything and uses
    all optional features your system supports at first glance".
  - `./configure --minimum tac_plus-ng` builds TACACS+ only, without
    optional features such as TLS.
  - The full, current list of fine-grained flags is only reliably known
    by running `./configure --help` against the checked-out source, so
    that is what the "Custom" profile is built from at install time
    rather than a guessed/hard-coded flag list.
  - The project has no tagged GitHub releases (verified: "No releases
    published"), so there is no upstream "stable tag" to pin to.
    Reproducibility instead comes from recording the exact commit hash
    resolved at clone time and pinning future rebuilds to it unless the
    administrator explicitly runs an upgrade.
"""
from __future__ import annotations

import json
import platform
import re
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from . import utils

UPSTREAM_REPO_URL = "https://github.com/jafartavana01/GUi-event-driven-servers.git"
# Points at the administrator's own fork of the real upstream
# (https://github.com/MarcJHuber/event-driven-servers), per their
# explicit request, rather than the original repository directly.
# Everything else in this module -- the configure-flag discovery, the
# commit-pinning behavior described above -- still applies exactly the
# same way, since this is still a real git clone of a real source
# tree, just from a different remote.

UPSTREAM_SRC_DIR = Path("/opt/aaa-platform/upstream/event-driven-servers")
BUILD_INFO_PATH = Path("/etc/aaa-platform/build_info.json")
BUILD_LOG_PATH = Path("/var/log/aaa-platform/tac_plus-ng-build.log")


@dataclass
class ConfigureOption:
    flag: str
    description: str


@dataclass
class BuildProfile:
    key: str
    name: str
    description: str
    configure_args: list[str]


def clone_or_update_upstream() -> str:
    """Clone the upstream repo if absent, or fetch+reset if present.
    Returns the resolved commit hash."""
    UPSTREAM_SRC_DIR.parent.mkdir(parents=True, exist_ok=True)

    if (UPSTREAM_SRC_DIR / ".git").exists():
        utils.info("Upstream source already present -- fetching latest.")
        utils.run(["git", "-C", str(UPSTREAM_SRC_DIR), "fetch", "--all", "--tags"])
        utils.run(["git", "-C", str(UPSTREAM_SRC_DIR), "reset", "--hard", "origin/master"])
    else:
        utils.info(f"Cloning {UPSTREAM_REPO_URL} ...")
        utils.run(["git", "clone", "--depth", "1", UPSTREAM_REPO_URL, str(UPSTREAM_SRC_DIR)])

    result = utils.run(["git", "-C", str(UPSTREAM_SRC_DIR), "rev-parse", "HEAD"])
    commit = result.stdout.strip()
    utils.ok(f"Upstream checked out at commit {commit[:12]}")
    return commit


def checkout_pinned_commit(commit: str) -> None:
    """Used on rebuilds so we don't silently drift to a new upstream HEAD
    (spec section 43: prefer a known commit for reproducibility)."""
    utils.run(["git", "-C", str(UPSTREAM_SRC_DIR), "fetch", "--all"])
    utils.run(["git", "-C", str(UPSTREAM_SRC_DIR), "checkout", commit])


def discover_configure_options() -> list[ConfigureOption]:
    """
    Runs `./configure --help` against the checked-out source and parses
    it into flag/description pairs. This is intentionally best-effort:
    the exact --help output format is upstream's to change, so parsing
    falls back to showing raw lines rather than guessing at structure
    it can't confirm.
    """
    configure_path = UPSTREAM_SRC_DIR / "configure"
    if not configure_path.exists():
        raise utils.InstallError(f"configure script not found at {configure_path}")

    result = utils.run(["./configure", "--help"], cwd=UPSTREAM_SRC_DIR, check=False)
    raw = (result.stdout + "\n" + result.stderr).strip()

    options: list[ConfigureOption] = []
    # Typical autoconf-style help lines look like:
    #   --enable-foo         enable the foo feature
    #   --without-bar        disable bar support
    # We match a leading "--xxx" token followed by a description, and
    # keep anything we can't confidently parse out of the structured
    # list (it's still shown to the admin verbatim in Custom mode).
    pattern = re.compile(r"^\s*(--[A-Za-z0-9][A-Za-z0-9\-=\[\]]*)\s{2,}(.+)$")
    for line in raw.splitlines():
        m = pattern.match(line)
        if m:
            options.append(ConfigureOption(flag=m.group(1), description=m.group(2).strip()))

    return options


def build_profiles() -> list[BuildProfile]:
    """
    Only two profiles are actually distinct in the upstream build system
    (verified from the README): the default (auto-detect all optional
    features the host supports) and --minimum (bare TACACS+, no optional
    features). "Custom" exposes whatever discover_configure_options()
    actually found for this checkout. We do not fabricate separate
    "TLS-only" or "Full" profiles that upstream doesn't distinguish.
    """
    return [
        BuildProfile(
            key="recommended",
            name="Recommended / Best Default",
            description=(
                "Default `./configure tac_plus-ng` -- auto-detects and enables every "
                "optional feature your build environment supports (TLS via OpenSSL, "
                "IPv6, c-ares DNS, RADIUS). Recommended for general enterprise use."
            ),
            configure_args=["tac_plus-ng"],
        ),
        BuildProfile(
            key="minimal",
            name="Minimal TACACS+ Server",
            description=(
                "`./configure --minimum tac_plus-ng` -- TACACS+ core only, no "
                "optional features (no TLS). Smallest dependency footprint."
            ),
            configure_args=["--minimum", "tac_plus-ng"],
        ),
        BuildProfile(
            key="custom",
            name="Custom",
            description="Interactively choose from the flags this checkout's ./configure --help reports.",
            configure_args=[],  # filled in interactively
        ),
    ]


def run_configure(args: list[str]) -> str:
    utils.info(f"Running: ./configure {' '.join(args)}")
    result = utils.run(["./configure"] + args, cwd=UPSTREAM_SRC_DIR)
    return result.stdout + result.stderr


def run_make() -> None:
    BUILD_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    utils.info("Compiling (this can take a few minutes)...")
    import os
    nproc = os.cpu_count() or 2
    result = utils.run(["make", f"-j{nproc}"], cwd=UPSTREAM_SRC_DIR, timeout=1800)
    with BUILD_LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(f"\n===== make @ {datetime.now(timezone.utc).isoformat()} =====\n")
        fh.write(result.stdout)
        fh.write(result.stderr)
    utils.ok("Compilation finished.")


def run_make_install() -> None:
    utils.info("Installing compiled binaries (make install)...")
    result = utils.run(["make", "install"], cwd=UPSTREAM_SRC_DIR)
    with BUILD_LOG_PATH.open("a", encoding="utf-8") as fh:
        fh.write(f"\n===== make install @ {datetime.now(timezone.utc).isoformat()} =====\n")
        fh.write(result.stdout)
        fh.write(result.stderr)
    utils.ok("tac_plus-ng installed.")


def locate_binary() -> str | None:
    """
    `make install` locations are governed by the upstream Makefile and
    were not independently confirmed for every Ubuntu layout, so we
    search the common sbin/bin locations rather than assuming one.
    """
    candidates = [
        "/usr/local/sbin/tac_plus-ng",
        "/usr/local/bin/tac_plus-ng",
        "/usr/sbin/tac_plus-ng",
        "/usr/bin/tac_plus-ng",
    ]
    for c in candidates:
        if Path(c).exists():
            return c
    found = shutil.which("tac_plus-ng")
    return found


def probe_version(binary_path: str) -> str:
    """
    Best-effort version probe. The exact CLI flag for version output was
    not independently confirmed, so several common conventions are
    tried and the first one that returns output is used; if none work,
    this is reported honestly rather than fabricated.
    """
    for flag in ("-v", "-V", "--version"):
        result = utils.run([binary_path, flag], check=False, timeout=10)
        text = (result.stdout + result.stderr).strip()
        if text:
            return text.splitlines()[0]
    return "unknown (binary present, but no recognized version flag responded)"


def discover_runtime_usage(binary_path: str) -> str:
    """
    Captures the built binary's own usage/help text so the systemd unit
    and, later, the configuration compiler can be reconciled against
    what this specific build actually supports rather than an assumed
    CLI surface. Tries the common conventions in order and keeps
    whichever produced the most output; never raises, since a binary
    refusing all of these is itself useful diagnostic information.
    """
    best = ""
    for argv_tail in (["-h"], ["--help"], []):
        result = utils.run([binary_path] + argv_tail, check=False, timeout=10)
        text = (result.stdout + result.stderr).strip()
        if len(text) > len(best):
            best = text

    usage_path = Path("/opt/aaa-platform/generated/tac_plus-ng-usage.txt")
    usage_path.parent.mkdir(parents=True, exist_ok=True)
    usage_path.write_text(
        best or "(binary produced no usage output for -h / --help / no-args)",
        encoding="utf-8",
    )
    return best


def compiler_version() -> str:
    for compiler in ("clang", "gcc", "cc"):
        path = utils.which(compiler)
        if path:
            result = utils.run([compiler, "--version"], check=False)
            first_line = (result.stdout or result.stderr).strip().splitlines()
            if first_line:
                return f"{compiler}: {first_line[0]}"
    return "unknown"


def record_build_info(
    *,
    commit: str,
    profile: BuildProfile,
    configure_args: list[str],
    configure_output: str,
    binary_path: str | None,
    version_string: str,
    system_report,
) -> dict:
    BUILD_INFO_PATH.parent.mkdir(parents=True, exist_ok=True)

    enabled, disabled = _guess_features(configure_output)

    info = {
        "upstream_repository": UPSTREAM_REPO_URL,
        "commit": commit,
        "tac_plus_ng_version_string": version_string,
        "build_date_utc": datetime.now(timezone.utc).isoformat(),
        "ubuntu_version": f"{system_report.distro_id} {system_report.distro_version}",
        "architecture": system_report.architecture,
        "compiler": compiler_version(),
        "build_profile": profile.key,
        "configure_arguments": configure_args,
        "binary_path": binary_path,
        "features_detected_enabled": enabled,
        "features_detected_disabled": disabled,
        "note": (
            "Feature enabled/disabled detection is parsed best-effort from "
            "./configure output text and may be incomplete; see "
            "/var/log/aaa-platform/tac_plus-ng-build.log for the full record."
        ),
    }
    BUILD_INFO_PATH.write_text(json.dumps(info, indent=2), encoding="utf-8")
    utils.ok(f"Build metadata recorded at {BUILD_INFO_PATH}")
    return info


def _guess_features(configure_output: str) -> tuple[list[str], list[str]]:
    """
    Best-effort scan of configure's own stdout for lines mentioning
    a feature and yes/no/found/not found, so the GUI's 'System -> Core
    Information' page (spec section 11) has something concrete to show.
    This is deliberately conservative -- ambiguous lines are skipped
    rather than guessed at.
    """
    enabled, disabled = [], []
    pattern = re.compile(
        r"(?i)\b(tls|ssl|ipv6|c-ares|cares|dns|radius|pcre2?)\b.*?\b(yes|no|found|not found|enabled|disabled)\b"
    )
    for line in configure_output.splitlines():
        m = pattern.search(line)
        if not m:
            continue
        feature, verdict = m.group(1).upper(), m.group(2).lower()
        target = enabled if verdict in ("yes", "found", "enabled") else disabled
        if feature not in target:
            target.append(feature)
    return enabled, disabled
