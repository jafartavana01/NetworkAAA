# NetworkAAA — Enterprise TACACS+ AAA Management Platform

**Open-source enterprise AAA platform for network infrastructure**
Centralized TACACS+ authentication, authorization, policy management, accounting, auditing, and privileged access governance — built around the real upstream `tac_plus-ng` daemon.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04%20%7C%2024.04%20%7C%2026.04-orange)](#requirements)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](#requirements)

---

## What's New in This Update

This is a substantial update. Highlights:

- **New Policy Condition Engine** — policies are no longer limited to three flat fields. Build arbitrary AND / OR / NOT condition trees (User, User Group, Device, Device Group, Source IP) through an interactive GUI, with genuinely unlimited nesting depth. Every condition compiles into real, confirmed `tac_plus-ng` syntax — anything that can't be safely compiled (like matching a bare username) is excluded from the generated config with a clear, auditable reason, never faked. The old flat-field model still works unchanged for policies that haven't been migrated; migration is an explicit, one-way action you choose per policy.
- **Command Sets & Command Categories** — reusable, named permit/deny rule collections, referenced by one or more policies instead of duplicating rules. A Policy Simulator page lets you test a hypothetical request end-to-end and see the full evaluation trace (which condition matched, why, and what was permitted or denied).
- **Policy Versioning** — every policy change is snapshotted, diffable against the current state, and restorable (restoring creates a new version; history is never destroyed).
- **Device-level Access Grants** — grant a user group unrestricted privilege-15 access to a specific device or device group, taking precedence over anything in Policies — useful for break-glass-style admin access. Deliberately group-only: there's no confirmed way to compile a per-user restriction safely, so it isn't offered.
- **Session Monitoring & AAA Health** — a real Sessions view correlating TACACS+ accounting start/stop records, and an AAA Health page with genuine failure-analysis breakdowns (permit/deny counts, top denied devices and users) — all computed from real parsed accounting data, never fabricated statistics.
- **Effective Access** — answer "what can this user access?" and "who can access this device?" directly, with the reasoning chain shown for each result.
- **Dashboard charts** — hourly activity trends and an authorization-results breakdown, backed by real accounting data.
- **Configuration backup & restore from file** — export a structured, version-tagged backup; restore checks compatibility before touching anything, and shows a diff against the live config before you confirm.
- **Uninstall support** — `sudo python3 setup.py -u` removes everything this platform's installer created (and only that — never Python, pip packages, or other system software like the PostgreSQL server itself). Shows exactly what will be removed and asks for confirmation first.
- Installer no longer runs `apt-get update` automatically (installs from whatever package index already exists on the machine — see [Installation](#installation)).
- A large number of GUI modernization passes: redesigned dropdowns, autofocus on every modal, drag-to-reorder policy priority, richer Command Set previews inline on the Policy editor, and a "promote to Command Set" action directly from the Accounting page.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full technical history of every increment, including exactly what's confirmed-real `tac_plus-ng` syntax versus reasoned extensions, and several real bugs that were caught and fixed along the way — nothing here is presented as more finished than it is.

---

## Table of Contents

- [Why NetworkAAA Exists](#why-networkaaa-exists)
- [Key Features](#key-features)
- [Architecture Overview](#architecture-overview)
- [Technology Stack](#technology-stack)
- [Project Status](#project-status)
- [Requirements](#requirements)
- [Installation](#installation)
- [How to Use](#how-to-use)
- [Configuration Compiler & Safe Apply Workflow](#configuration-compiler--safe-apply-workflow)
- [Directory Layout](#directory-layout-after-installation)
- [Security Model](#security-model)
- [Verification Philosophy (tac_plus-ng)](#verification-philosophy-tac_plus-ng)
- [Known Limitations & Roadmap](#known-limitations--roadmap)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)

---

## Why NetworkAAA Exists

`tac_plus-ng` (from [Marc Huber's event-driven-servers](https://github.com/MarcJHuber/event-driven-servers)) is a capable, actively maintained TACACS+ daemon. However, it's traditionally configured by hand-editing a text file that uses its own domain-specific scripting language.

NetworkAAA places a real **management plane** in front of it:

- PostgreSQL is the **single source of truth**
- A configuration compiler turns database state into valid `tac_plus-ng` configuration
- Changes go through a **candidate → validate → diff → apply → automatic rollback** workflow
- Day-to-day operations (add a device, create a user, decide who can run `configure terminal`, build a multi-condition access policy) happen entirely through a web GUI — never by editing the config file by hand

The TACACS+ engine itself is **never modified**. NetworkAAA only ever *configures* it.

---

## Key Features

| Area | Capabilities |
| --- | --- |
| **Network Devices** | Full CRUD, encrypted shared secrets (Fernet), device groups, config compiler with candidate/diff/apply/rollback, device-level access grants |
| **TACACS+ Users & Groups** | bcrypt-hashed passwords, native `tac_plus-ng` group support, device-group membership, trusted-host field (stored for planning; not yet enforced — see [Known Limitations](#known-limitations--roadmap)) |
| **Authorization Policies** | Priority-ordered (unique priorities, drag-to-reorder), an interactive AND/OR/NOT condition builder (User / User Group / Device / Device Group / Source IP, unlimited nesting), full version history with diff/restore, a Policy Simulator with a step-by-step evaluation trace |
| **Command Sets** | Reusable, named permit/deny rule collections referenced by one or more policies; "starts with / contains / exact / custom regex" pattern builder; promote a command straight from the Accounting page into a Command Set |
| **Command Categories** | A vendor-scoped command taxonomy for reporting/filtering, with an optional risk-level tag |
| **Sessions & Accounting** | Session view correlating accounting start/stop records; searchable, filterable accounting logs with CSV export; AAA Health page with real permit/deny and failure-analysis breakdowns; Effective Access lookups |
| **Diagnostics** | On-demand config validation (now correctly distinguishes a definitive failure from a genuinely inconclusive one), configuration audit trail, service logs, auth/authz log tails |
| **Platform Self-Management** | Two-tier RBAC (superadmin vs standard), per-admin trusted-host IP restrictions (enforced), full HTTPS support (self-signed by default + custom certificate upload), structured config backup export/import with version checking |
| **GUI** | Single-window shell with client-side view transitions across every page; modernized form controls; dashboard charts backed by real accounting data |

---

## Architecture Overview

```
Browser
   │
   ▼
Web GUI (server-rendered Jinja2 + single-window JS shell)
   │
   ▼
Management API (FastAPI)
   │
   ▼
PostgreSQL  ──►  Configuration Compiler  ──►  Candidate tac_plus-ng.conf
(source of truth)         │
                          ▼
                     Validation
                          │
                     Diff + Apply
                          │
                          ▼
                 tac_plus-ng (TCP/49)
                          │
                          ▼
                 Network Devices (switches, routers, firewalls…)
```

- The database is **always** the source of truth.
- The generated `tac_plus-ng.conf` is a derived artifact — never hand-edited.
- Every change is validated before being applied.
- If the daemon fails to come back healthy after an apply, the previous configuration is automatically restored.
- A policy's condition tree is compiled into real `tac_plus-ng` boolean expressions (`&&`, `||`, `==`, `!=`, and generated `acl {}` blocks for CIDR matching). Anything that can't be safely compiled — a bare-username condition, or a NOT group, since neither has confirmed `tac_plus-ng` syntax — excludes just that one policy from the generated ruleset, with the reason recorded as an auditable event, rather than guessing at syntax.
- Device-level access grants are written into the generated ruleset **before** any policy rule, so precedence comes from evaluation order, not a priority number.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design, including the module system, privilege model, the policy engine internals, and directory layout.

---

## Technology Stack

| Layer | Technology |
| --- | --- |
| **Data plane** | `tac_plus-ng` (upstream C, completely unmodified) |
| **Management plane** | FastAPI + SQLAlchemy + PostgreSQL |
| **Frontend** | Server-rendered Jinja2 + vanilla JavaScript (no build step, no frontend framework); Chart.js loaded on-demand for the Dashboard |
| **OS target** | Ubuntu Server 22.04 / 24.04 / 26.04 LTS — **native install only** |
| **Deployment style** | No containers, no Python virtual environments, system-wide packages |

Python dependencies (see `requirements.txt`) are installed system-wide with `--break-system-packages` when the externally-managed-environment marker is present.

---

## Project Status

The original 8-phase build plan is complete through Phase 7, plus a substantial PAM (Privileged Access Management) expansion beyond it:

| Phase | Area | Status |
| --- | --- | --- |
| 1 | Installer, GUI shell, live dashboard | Done |
| 2 | Network Devices + configuration compiler | Done |
| 3 | TACACS+ Users (end-to-end auth tested) | Done |
| 4 | TACACS+ Groups & Device Groups | Done |
| 5 | Authorization Policies | Done |
| 6 | Accounting | Done |
| 7 | Diagnostics | Done |
| 8 | Module Management | Not started |

**PAM expansion, beyond the original plan — done:**

- Policy condition engine v2 (schema, evaluator, compiler, interactive GUI builder), Policy Versioning, Policy Simulator, Effective Access
- Command Sets & Command Categories
- Session Monitoring, AAA Health & Failure Analysis, Dashboard charts
- Device-level Access Grants
- Config backup/restore from file with version checking
- Uninstall support, apt-update removed from the installer
- TACACS+ user trusted-host (data model + GUI only — see limitations)
- Two-tier RBAC, per-admin trusted-host, HTTPS (from the prior update)
- Single-window GUI redesign (complete — every authenticated page)

**Not yet implemented:**

- Module Management GUI (Phase 8)
- CLI
- Automated test suite
- RADIUS, LDAP, or Active Directory backends
- Granular RBAC (permission-level, beyond the current two-tier superadmin/standard split)
- Command-as-a-policy-condition (researched and deliberately deferred — see [Known Limitations](#known-limitations--roadmap))

---

## Requirements

- **OS:** Ubuntu Server 22.04, 24.04, or 26.04 LTS
- **Privileges:** Root / sudo
- **Network:** Outbound internet **only during installation** (to download `tac_plus-ng` source and apt packages). Runtime requires no internet.
- **Python:** 3.8+ (the installer itself requires this)

---

## Installation

### Quick Start

```bash
git clone https://github.com/jafartavana01/NetworkAAA.git
cd NetworkAAA
sudo python3 setup.py
```

The installer is interactive and will guide you through the process.

> **Important:** The full source tree (including `app/`, `installer/`, and `docs/`) must be present for the installer to succeed — cloning only the top-level files will not work.

> **Note:** The installer does **not** run `apt-get update` before installing packages — it installs from whatever package index already exists on the machine. On a genuinely brand-new VM image that's never run `apt` at all, this can cause package installation to fail with "Unable to locate package." If that happens, run `sudo apt update` once yourself and re-run the installer.

### What the Installer Does

| Phase | Actions |
| --- | --- |
| **System Detection** | Checks Ubuntu version, Python, internet connectivity, and reports any problems. Allows you to continue on near-supported systems if desired. |
| **Dependencies** | Installs all required system packages from the existing package index (see the note above). |
| **tac_plus-ng Build** | Clones/updates the real upstream source, lets you choose a build profile (or custom `./configure` flags), builds, installs, and records build metadata. |
| **PostgreSQL** | Provisions a dedicated database and role for the platform. |
| **Application Install** | Creates a least-privilege service account, copies application source to `/opt/aaa-platform/app`, installs Python dependencies system-wide, sets ownership, provisions secret files, and installs a narrowly-scoped sudoers rule. |
| **Schema & Admin** | Creates the database schema and walks you through creating the first **superadmin** account. |
| **TLS & Settings** | Generates a self-signed certificate (HTTPS is **off** by default) and writes default platform settings. |
| **Bootstrap Config** | Writes a minimal working `tac_plus-ng` configuration so the daemon can start. |
| **systemd** | Creates and enables two units — `aaa-platform.service` (management GUI) and `tac-plus-ng.service` (the daemon). Starts both and performs first-start diagnostics. |

Installation logs are written to `/tmp/aaa-platform-install.log`. Full build metadata is stored at `/etc/aaa-platform/build_info.json`.

### Uninstalling

```bash
sudo python3 setup.py -u
```

Shows exactly what will be removed and asks for confirmation before touching anything. Removes **only** what this installer created: both systemd services, the `tac_plus-ng` binary it built, `/opt/aaa-platform`, `/etc/aaa-platform`, `/var/lib/aaa-platform`, `/var/log/aaa-platform`, the scoped sudoers rule, and the platform's own PostgreSQL database/role and service account.

**Never removed:** Python, pip-installed packages, or any apt-installed system software — including the PostgreSQL *server* itself, which keeps running with any other databases on it untouched.

Useful flags: `-y` / `--force` skips the confirmation prompt (for scripted use); `--keep-logs` preserves `/var/log/aaa-platform` instead of deleting it.

### Post-Install Access

```
Management GUI:  http://<server-ip>:8420
```

- Default listen address: all interfaces
- Default port: **8420**
- Protocol: **HTTP** (HTTPS is generated but disabled until you enable it under Platform → Settings)

---

## How to Use

### First Login & Platform Settings

1. Open `http://<server-ip>:8420` in a browser.
2. Log in with the superadmin account you created during installation.
3. Go to **Platform → Settings** (superadmin only) to change bind address/port, enable HTTPS, or manage certificates.
4. Go to **Platform → Admin Users** to manage additional administrators and per-account trusted-host IP restrictions.

### Devices & Access Grants

- Create devices with name, IP/hostname, and shared secret (encrypted at rest with Fernet); organize them into Device Groups.
- **Access Grants**, on the same page: give a user group unrestricted privilege-15 access to a device or device group, evaluated *before* any policy. Intended for break-glass-style access, not day-to-day authorization — group-only by design (see [Known Limitations](#known-limitations--roadmap)).

### TACACS+ Users & Groups

- Create users with bcrypt-hashed passwords; assign them to a group.
- A user's "trusted hosts" field can be set for planning purposes, but is **not currently enforced** — the GUI says so directly.

### Authorization Policies

- Every policy needs a unique priority; enabled policies are evaluated in ascending order and the first full match wins. Drag rows on the Policies page to reorder — every affected priority is renumbered automatically.
- Build conditions with the interactive **condition builder**: pick an object type (User, User Group, Device, Device Group, Source IP), an operator, and a value; combine multiple conditions with AND/OR/NOT, with unlimited nesting depth via "+ Add Condition Group."
- A policy's **result** is a privilege level, a default action, and zero or more **Command Sets**.
- Every save creates a new **version** — view history, diff against the current state, or restore an old version (restoring creates a new version; nothing is ever destroyed).
- Use the **Policy Simulator** to test a hypothetical request (user, device, source IP, command) and see the full step-by-step evaluation trace, including which policy matched and why.
- **Effective Access** answers "what can this user access?" and "who can access this device?" directly.

### Command Sets & Command Categories

- A Command Set is a named, reusable collection of permit/deny command rules, referenced by one or more policies instead of duplicating rules.
- Build rules with "Starts with / Contains / Exact match / Custom regex" — no need to hand-write a regex for the common cases.
- Promote a command straight from the **Accounting** page into a Command Set with one click.
- **Command Categories** provide an optional, vendor-scoped taxonomy (with a risk-level tag) for reporting.

### Sessions, Accounting & AAA Health

- **Sessions** correlates accounting start/stop records by device and port to show active and historical TACACS+ sessions.
- **Accounting** is fully searchable and filterable (user, device, device group, source IP, result, date range), with CSV export.
- **AAA Health** shows genuine permit/deny breakdowns and failure analysis (top denied devices/users) computed from real parsed accounting data — no fabricated statistics.

### Diagnostics

- On-demand configuration validation, now correctly distinguishing a **definitive** syntax failure from a genuinely inconclusive one.
- Configuration change audit trail, live service logs, authentication/authorization log tails.

### Platform Self-Management

- Two-tier RBAC (superadmin vs standard admin), per-admin trusted-host IP allow-lists, full HTTPS control.
- **Configuration backup/restore**: export a structured, version-tagged backup file; restoring checks version compatibility first and shows a diff against the live config before you confirm anything.

---

## Configuration Compiler & Safe Apply Workflow

Whenever you change devices, users, groups, or policies:

1. The management plane generates a **candidate** configuration from the current database state.
2. The candidate is validated against the real `tac_plus-ng` binary's own syntax checker.
3. You're shown a **diff** against the currently running configuration.
4. On apply, the new configuration is written and `tac_plus-ng` is reloaded.
5. If the daemon doesn't come back healthy, the previous configuration is **automatically restored**.

A validation failure the daemon itself reports unambiguously (not just a generic nonzero exit) now **blocks the apply outright** — nothing is written to disk or touched on the live daemon — rather than relying solely on the post-reload health check to catch it after the fact.

This protects you from locking yourself out of network devices due to a bad authorization rule or syntax error.

---

## Directory Layout (After Installation)

```
/opt/aaa-platform/
├── app/                     # Management application (FastAPI + Jinja2)
│   ├── run.py               # systemd entrypoint
│   ├── platform_settings.py
│   ├── models/
│   ├── services/            # config_compiler.py, policy_engine.py, condition_engine.py, tls_certs.py, …
│   └── …
├── generated/                # compiled tac_plus-ng.conf
└── backups/                  # one backup per applied version

/etc/aaa-platform/
├── build_info.json           # tac_plus-ng build metadata
├── db_credentials.json
├── config/platform_settings.json
└── tls/

# systemd units
aaa-platform.service          # management GUI
tac-plus-ng.service           # the TACACS+ daemon
```

The source tree (before installation) looks like:

```
setup.py                      # Installer entrypoint (supports -u to uninstall)
installer/                    # Installer implementation modules
app/                           # Application source (copied to /opt)
docs/
  ├── INSTALL.md
  ├── ARCHITECTURE.md
  └── PAM_EXPANSION_PLAN.md
requirements.txt
LICENSE
README.md
```

---

## Security Model

- Device shared secrets are encrypted at rest (Fernet) and never logged.
- Administrator passwords are bcrypt-hashed; never stored or logged in plaintext.
- CSRF protection on every state-changing request.
- Least-privilege service account with a narrowly-scoped sudoers rule (only the two systemd units it needs to control).
- Identifiers are restricted to a safe character set at input time (config-injection defense by construction rather than escaping).
- HTTPS is fully supported (self-signed generated at install time; custom certificates can be uploaded).
- A policy's condition tree is validated as a whole on save — a bad database reference, an invalid operator for an object type, or a malformed CIDR anywhere in the tree rejects the entire save, never a partially-applied one.

If you discover a security issue, please open a GitHub issue or contact the maintainer privately for sensitive reports.

---

## Verification Philosophy (tac_plus-ng)

`tac_plus-ng`'s configuration language is not fully documented in a single place. Every claim this project makes about its syntax is explicitly tagged as one of:

- **Confirmed** — verified against a real working configuration (upstream sample, real deployment, or a live test)
- **Reasoned, not verified** — a defensible extension of confirmed language mechanics, clearly called out as such

This project has, more than once, caught and corrected its own mistakes in this area rather than letting them stand — including a case where a "reasoned, not confirmed" field (an accounting log variable) turned out to be genuinely invalid syntax when tested against a real deployment, and was removed. The distinction is documented throughout `docs/ARCHITECTURE.md` and in code comments at every point it matters, especially around the configuration compiler and the new condition engine. The project deliberately avoids silently guessing at protocol or configuration behavior — when something can't be confirmed, it's either left unimplemented or clearly labeled as unenforced, never quietly assumed to work.

---

## Known Limitations & Roadmap

**Current limitations**

- No CLI yet
- No automated test suite
- No RADIUS / LDAP / Active Directory backends yet
- Phase 8 (Module Management) not started
- Granular, permission-level RBAC is not implemented — only the two-tier superadmin/standard split
- TACACS+ user trusted-host is stored but **not enforced** — no confirmed `tac_plus-ng` syntax exists yet for restricting one specific user (as opposed to a whole group) by source IP
- Device-level Access Grants and per-user targeting in the condition builder are **group-only** — the same underlying reason: no confirmed syntax exists for matching a bare username in the generated config
- Command-as-a-policy-condition (matching on which specific command triggered a request, as part of deciding *which policy* applies) was researched and deliberately not implemented — every real-world `tac_plus-ng` configuration example found checks commands only inside a profile's own script, never as part of policy/ruleset selection; inventing that would mean guessing at unconfirmed syntax
- NOT-groups in the condition builder are supported for evaluation and simulation, but not yet compilable into the generated config — no confirmed `!` operator exists in `tac_plus-ng`'s scripting language
- Full source (`app/`, `installer/`, `docs/`) must be present for the installer to succeed

**Planned**

- Module Management GUI (Phase 8)
- Granular RBAC with role templates
- RADIUS and external identity providers
- CLI and comprehensive automated testing

---

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Installer aborts on system checks | Read the printed report. You can force-continue on near-supported systems. |
| Package install fails with "Unable to locate package" | Run `sudo apt update` once, then re-run the installer (see [Installation](#installation)) |
| Management service fails to start | `journalctl -u aaa-platform.service -e` |
| tac_plus-ng fails to start | `journalctl -u tac-plus-ng.service -e` and check the generated config under Diagnostics |
| Cannot reach GUI | Confirm firewall allows TCP/8420 (or whatever port you configured) |
| HTTPS not working | Enable it under **Platform → Settings** after confirming HTTP works |
| Config apply rejected outright | The daemon's own syntax check found a definitive error — see the message shown; nothing was applied |
| Config apply rolls back after being applied | Check the validation output and daemon logs on the Diagnostics page; the previous config was restored automatically |

Install log: `/tmp/aaa-platform-install.log`
Build record: `/etc/aaa-platform/build_info.json`

---

## Contributing

Contributions are welcome once the full source tree is published.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Open a pull request with a clear description

Please keep the "Confirmed vs Reasoned" distinction for any `tac_plus-ng` configuration claims, and never implement a feature that requires guessing at unconfirmed syntax — see [Verification Philosophy](#verification-philosophy-tac_plus-ng).

---

## Acknowledgments

Built on top of [`tac_plus-ng`](https://github.com/MarcJHuber/event-driven-servers) by Marc Huber and contributors — the actual TACACS+ engine that performs the protocol work underneath this platform.

---

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for the full text.

---

**NetworkAAA** — because managing TACACS+ shouldn't require editing configuration files by hand.
