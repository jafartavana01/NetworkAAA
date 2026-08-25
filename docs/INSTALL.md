# Installation Guide

## Requirements

- Ubuntu Server 22.04, 24.04, or 26.04 LTS (other versions are not
  automatically supported -- the installer will warn you and ask for
  explicit confirmation to proceed anyway).
- Root or sudo privileges.
- Outbound Internet access **during installation only** (to clone
  `github.com/MarcJHuber/event-driven-servers` and to install apt
  packages). No Internet access is required at runtime.
- At least 5 GB free disk space and 1 GB RAM recommended.

## What gets installed

| Component | Source | Location |
|---|---|---|
| tac_plus-ng | Built from upstream source at install time | `/usr/local/sbin/tac_plus-ng` (or wherever `make install` places it -- recorded in `build_info.json`) |
| Upstream source checkout | `git clone` | `/opt/aaa-platform/upstream/event-driven-servers` |
| Management application | Copied from this project's `app/` directory | `/opt/aaa-platform/app` |
| Generated tac_plus-ng config | Written by the installer, then by the configuration compiler on every Apply | `/opt/aaa-platform/generated/tac_plus-ng.conf` |
| Configuration backups | One per applied version, written just before each Apply | `/opt/aaa-platform/backups/` |
| Application config/secrets | Generated at install time | `/etc/aaa-platform/` (root-only) |
| Scoped sudoers grant | Generated + `visudo`-validated at install time | `/etc/sudoers.d/aaa-platform` |
| PostgreSQL database | `aaa_platform` role + database | Local PostgreSQL instance |
| Logs | | `/var/log/aaa-platform/` |

## Running the installer

```
git clone <this project's repository>   # or copy the project directory to the server
cd aaa-platform
sudo python3 setup.py
```

The installer:

1. Detects your Ubuntu version, architecture, compiler, disk/memory,
   and Internet connectivity, and refuses to proceed automatically if
   something looks unsupported.
2. Installs apt dependencies (build tools + tac_plus-ng's documented
   prerequisites + PostgreSQL).
3. Clones `event-driven-servers` and asks you to choose a build
   profile:
   - **Recommended** -- default `./configure tac_plus-ng`, auto-detects
     every optional feature your system supports (TLS, IPv6, RADIUS, DNS).
   - **Minimal** -- `./configure --minimum tac_plus-ng`, TACACS+ core
     only, no optional features.
   - **Custom** -- flags are parsed live from that checkout's own
     `./configure --help` output, never hard-coded.
4. Builds and installs tac_plus-ng, and records the exact commit,
   build date, compiler, configure arguments, and detected features to
   `/etc/aaa-platform/build_info.json` (visible later in the GUI under
   System → Core Information).
5. Provisions a local PostgreSQL role + database.
6. Creates a least-privilege `aaa-platform` system account, installs
   the management application's Python dependencies **directly into
   the system interpreter** (no virtualenv is created, per project
   requirements), and copies the application source into `/opt/aaa-platform/app`.
7. Creates the database schema and prompts you to create the first
   platform administrator account (password is never echoed or logged).
8. Generates a default self-signed HTTPS certificate and writes the
   default platform settings (HTTPS starts OFF -- see "Enabling HTTPS"
   below).
9. Writes a minimal bootstrap `tac_plus-ng.conf` (no devices/policies
   yet -- that's Phase 2) so the daemon can actually start and be
   health-checked.
10. Generates and starts two systemd services: `aaa-platform.service`
    (the management API/GUI, on `0.0.0.0:8420` -- reachable from your
    LAN, not just the server itself) and `tac-plus-ng.service` (the
    TACACS+ daemon, on TCP/49).

## After installation

Open `http://<server-lan-ip>:8420` from any machine on the same LAN,
or `http://127.0.0.1:8420` on the server itself.

If Ubuntu's firewall is active, open the port first:

```
sudo ufw status
# if active:
sudo ufw allow from 192.168.0.0/16 to any port 8420 proto tcp
# (adjust the CIDR to match your actual LAN range; avoid a bare
# "ufw allow 8420/tcp" unless you genuinely want it open to everyone)
```

## Platform Settings: admin accounts, trusted hosts, HTTPS

Log in and go to **Platform → Admin Users** and **Platform → Settings**
(superadmin-only -- the account you created during install is a
superadmin by default).

- **Admin Users**: add additional accounts, set a standard-vs-superadmin
  role, disable an account, or restrict which IPs/CIDRs it may log in
  from at all (leave blank for unrestricted, the default). Built-in
  guardrails prevent you from deleting/disabling your own account or
  removing the last active superadmin -- both would risk locking
  everyone out.
- **Settings → Network**: change the GUI's bind address/port, the
  tac_plus-ng TACACS+ port, and toggle HTTPS. **Nothing here applies
  until you explicitly restart the management service** (a button on
  the same page) -- if you change the port or enable HTTPS, expect
  your current connection to drop and to need to reconnect at the new
  address.
- **Settings → HTTPS**: a self-signed certificate already exists from
  install time (unused until you enable HTTPS above). Regenerate it
  with your own CN/organization/validity period, or upload a
  certificate from your own CA. Enabling HTTPS without a valid
  certificate installed is refused outright rather than silently
  falling back to plain HTTP.

No TLS is enabled by default -- login and every request are plain HTTP
until you turn HTTPS on. That's fine for a trusted internal network you
control; if you're on a shared or larger LAN, enabling HTTPS (even with
the default self-signed certificate -- your browser will warn about it
being unrecognized, which is expected and safe to accept for an
internal tool you administer yourself) closes that gap without needing
a separate reverse proxy.

## Known verification items

This installer builds and configures tac_plus-ng based on the
upstream project's public README, PREREQUISITES.txt, and sample
configuration files. The following behaviors were **not**
independently confirmed against a live build and are worth checking
on your first install and first configuration apply:

- ~~Whether `tac_plus-ng -h` / `-C <conf>` is the complete, correct
  invocation~~ **Confirmed and fixed via a real failed install.**
  There is no `-C` flag at all -- the config file is a bare positional
  argument (`tac_plus-ng [options] <configuration file> [<id>]`), and
  `-f` ("force staying in foreground") is the correct flag for
  systemd `Type=simple`. The old `-C` invocation exited immediately
  with status 64 (`EX_USAGE`). Fixed in `installer/systemd_setup.py`,
  `installer/bootstrap_config.py`, and `app/services/config_compiler.py`.
- Whether tac_plus-ng's `-P` flag really means "parse config and exit"
  (confirmed for legacy tac_plus, not independently confirmed for
  tac_plus-ng). The configuration compiler treats a non-zero exit from
  this check as *inconclusive*, not a hard failure -- it logs the
  output and proceeds to the real gate: applying the config, reloading
  the daemon, and checking it's still `active` two seconds later, with
  automatic rollback to the previous known-good config if it isn't.
- Whether `sudo -n systemctl ...` from inside the management service
  works cleanly under its `ProtectSystem=strict` sandboxing. The
  management unit deliberately does **not** set `NoNewPrivileges=true`
  (unlike tac_plus-ng's unit) because that flag would silently block
  the `sudo` escalation the app needs to control tac_plus-ng -- see
  `docs/ARCHITECTURE.md#privilege-model`. `/var/lib/sudo` is added to
  `ReadWritePaths` for sudo's own state file, but this combination
  wasn't tested against a live sudo installation.
- IPv6 device addresses are stored and shown in the GUI, but **not**
  emitted into the generated tac_plus-ng config yet -- no IPv6-specific
  `host` block syntax was confirmed against upstream docs/samples, and
  guessing at one risked silently generating configuration that looks
  plausible but doesn't do what it says (spec section 20). It appears
  as a comment in the generated file instead. IPv4 devices are fully
  functional.

## Applying your first device

Once you've added a device under **TACACS+ → Devices**, nothing
changes on the wire until you visit **TACACS+ → Configuration** and
click **Apply configuration** -- that page shows exactly what would
change (a diff against what's actually deployed on disk), and only
touches the running daemon once you confirm.

## Re-running the installer

**This project targets clean installs only.** There is no supported
upgrade path from an existing, populated installation to a newer
version of this project -- `setup.py` is safe to re-run if it fails
partway through (it reuses an existing PostgreSQL role/database and
won't create a second administrator account if one already exists),
but it does not attempt to reconcile an old database schema with a
newer one. If you're picking up a newer version of this project,
install it on a fresh VM rather than re-running the installer over an
existing one.

## Uninstalling

```
sudo python3 setup.py -u
```

Shows exactly what will be removed, then asks for confirmation before
touching anything. Removes **only** what this installer created:

- Both systemd services (stopped, disabled, unit files deleted)
- The tac_plus-ng binary this installer built
- `/opt/aaa-platform`, `/etc/aaa-platform`, `/var/lib/aaa-platform`,
  `/var/log/aaa-platform`
- The scoped sudoers rule
- The `aaa_platform` PostgreSQL database and role (**not** the
  PostgreSQL server itself)
- The `aaa-platform` service account

**Never removed:** Python, pip-installed packages, and any
apt-installed system software (build tools, the PostgreSQL server
package itself, dev libraries) -- those are dependencies this
installer used, not things it owns.

Useful flags:

```
sudo python3 setup.py -u --keep-logs   # preserve /var/log/aaa-platform
sudo python3 setup.py -u -y            # skip the confirmation prompt (for scripted use)
```

Every removal step checks whether its target actually exists first,
so this is safe to run against a partial install and safe to run
twice.

## A note on `apt-get update`

This installer does **not** run `apt-get update` before installing
packages -- it installs from whatever package index already exists on
the machine. On a genuinely brand-new VM image that has never run
`apt` at all, this can cause `apt-get install` to fail with "Unable to
locate package." If that happens, run `sudo apt update` once yourself
and re-run the installer.
