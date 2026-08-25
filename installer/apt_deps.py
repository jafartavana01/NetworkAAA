"""
installer.apt_deps
====================
Installs Ubuntu package dependencies via apt. Package lists are derived
from the upstream event-driven-servers PREREQUISITES.txt (build tools,
libpcre2, libc-ares, OpenSSL 3.x dev headers, Perl) plus what the
management plane itself needs (PostgreSQL server, Python dev headers).

Nothing here is invented: the upstream PREREQUISITES.txt lists a C
compiler, GNU make, Perl, libpcre2 dev headers/libs, libc-ares dev
headers/libs, and OpenSSL 3.x dev headers/libs as required to build
tac_plus-ng; Python is called out as optional there and is not part of
the tac_plus-ng build itself. Perl CPAN modules used only by the
optional `mavis` backends (LDAP/RADIUS auth backends, not the TACACS+
core) are intentionally NOT installed by default -- they belong to a
future LDAP/RADIUS module (spec sections 46/22), not TACACS+ core.

NOTE ON NOT RUNNING `apt-get update`: deliberately removed on request.
The tradeoff this creates: `ensure_packages()` below installs from
whatever package index already exists on the machine, which could be
stale or (on a genuinely brand-new VM image that has never run apt at
all) entirely absent, in which case `apt-get install` can fail with
"Unable to locate package". This is a real operational consequence,
not a hidden one -- if a fresh install hits that failure, running
`sudo apt update` once yourself before re-running this installer is
the fix.
"""
from __future__ import annotations

from . import utils

# Packages required to build tac_plus-ng itself.
TAC_PLUS_NG_BUILD_DEPS = [
    "build-essential",   # gcc/g++/make/libc headers
    "clang",             # preferred compiler per upstream docs
    "make",
    "perl",
    "libpcre2-dev",
    "libc-ares-dev",
    "libssl-dev",        # OpenSSL 3.x dev headers (Ubuntu 22.04+ ships OpenSSL 3)
    "git",
    "pkg-config",
]

# Packages required to run the management plane (this application).
MANAGEMENT_PLANE_DEPS = [
    "python3",
    "python3-pip",
    "python3-venv",       # present on the base image even though we do not
                           # create a venv (spec section 7) -- some distro
                           # python3-pip packages depend on it being present.
    "postgresql",
    "postgresql-contrib",
    "libpq-dev",          # headers for the psycopg client library
    "python3-dev",
    "sudo",                # required for the scoped sudoers grant in
                            # installer.sudoers_setup (visudo + sudo -n)
]

ALL_PACKAGES = TAC_PLUS_NG_BUILD_DEPS + MANAGEMENT_PLANE_DEPS


def _installed_packages() -> set[str]:
    result = utils.run(
        ["dpkg-query", "-W", "-f=${Package} ${Status}\n"], check=False
    )
    installed = set()
    for line in result.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[-1] == "installed":
            installed.add(parts[0])
    return installed


def ensure_packages(packages: list[str]) -> list[str]:
    """
    Install any packages from `packages` that are not already present.
    Returns the list actually installed. Package names are drawn only
    from the static lists in this module -- never from free-form user
    input -- before being placed in an apt-get argv.
    """
    allowed = set(TAC_PLUS_NG_BUILD_DEPS + MANAGEMENT_PLANE_DEPS)
    packages = [p for p in packages if p in allowed]

    already = _installed_packages()
    missing = [p for p in packages if p not in already]

    if not missing:
        utils.ok("All required apt packages are already installed.")
        return []

    utils.info(f"Installing {len(missing)} package(s): {', '.join(missing)}")
    env = {"DEBIAN_FRONTEND": "noninteractive"}
    import os
    full_env = {**os.environ, **env}
    utils.run(["apt-get", "install", "-y"] + missing, env=full_env)
    utils.ok("apt package installation complete.")
    return missing
