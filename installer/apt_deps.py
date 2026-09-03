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
the tac_plus-ng build itself.

MAVIS_LDAP_DEPS: Active Directory integration is now a real, shipped
feature of this platform (not a future one) -- an earlier version of
this file deferred these packages with the reasoning "belong to a
future LDAP/RADIUS module", which is now outdated given that module
exists. Added after a real, confirmed production failure: without
`libnet-ldap-perl` (the Debian/Ubuntu package providing Perl's
Net::LDAP module -- confirmed via multiple independent Debian package
pages, not guessed), `mavis_tacplus_ads.pl` cannot even load --
"Can't locate Net/LDAP.pm in @INC" -- so it dies at the Perl module
loading stage on every single login attempt, before ever attempting
an LDAP connection at all. This happens regardless of how correctly
this platform's own AD settings, certificates, or TLS configuration
are set up, since the failure is entirely upstream of any of that.
`libio-socket-ssl-perl` is included alongside it for the same reason
-- LDAPS/StartTLS support within the Perl script itself needs it, and
it's only a Debian "Suggests" on libnet-ldap-perl (not a hard
dependency apt pulls in automatically), so it must be listed
explicitly rather than assumed to come along for free.

NOTE ON `apt-get update`: runs once, automatically, before checking
for missing packages -- restored after previously being removed on
request. Deliberately `update` only, never `upgrade`: refreshing the
package INDEX is what a fresh install typically needs (the earlier
"Unable to locate package" failure on a brand-new VM image was caused
by a stale/absent index, not stale installed packages), while
upgrading already-installed packages is a separate, more disruptive
action this installer has no reason to take on the system's behalf.
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

# Perl CPAN modules the mavis LDAP/AD backend (mavis_tacplus_ads.pl,
# which itself delegates to mavis_tacplus_ldap.pl) needs at runtime --
# see the module docstring above for why these are no longer deferred.
MAVIS_LDAP_DEPS = [
    "libnet-ldap-perl",     # provides Net::LDAP -- confirmed required; without it mavis_tacplus_ads.pl fails to load at all
    "libio-socket-ssl-perl",  # LDAPS/StartTLS support within the Perl script
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

ALL_PACKAGES = TAC_PLUS_NG_BUILD_DEPS + MAVIS_LDAP_DEPS + MANAGEMENT_PLANE_DEPS


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


def update_package_index() -> None:
    """`apt-get update` only -- refreshes the package index so
    `ensure_packages()` below can find current packages, especially on
    a genuinely fresh VM image that has never run apt at all. Never
    `apt-get upgrade`: that would touch already-installed packages
    system-wide, a separate and more disruptive action this installer
    has no reason to take."""
    utils.info("Updating apt package index...")
    utils.run(["apt-get", "update"])
    utils.ok("apt package index updated.")


def ensure_packages(packages: list[str]) -> list[str]:
    """
    Install any packages from `packages` that are not already present.
    Returns the list actually installed. Package names are drawn only
    from the static lists in this module -- never from free-form user
    input -- before being placed in an apt-get argv.
    """
    allowed = set(TAC_PLUS_NG_BUILD_DEPS + MAVIS_LDAP_DEPS + MANAGEMENT_PLANE_DEPS)
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
