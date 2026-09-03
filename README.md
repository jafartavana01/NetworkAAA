# NetworkAAA — Enterprise TACACS+ AAA Management Platform

**Open-source enterprise AAA platform for network infrastructure**
Centralized TACACS+ authentication, authorization, policy management, accounting, auditing, and privileged access governance — built around the real upstream `tac_plus-ng` daemon.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04%20%7C%2024.04%20%7C%2026.04-orange)](#requirements)
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)](#requirements)

---

## What's New This Week

Full details in [`CHANGELOG.md`](CHANGELOG.md). Highlights:

- **Policy priorities now start at 0 and insert like an ordered list** — creating or editing a policy at an already-used priority no longer rejects with a conflict; it inserts there and shifts everything else by exactly one slot to make room, in either direction.
- **A silently-excluded policy is no longer invisible.** If a policy can't compile into the real configuration (e.g. an unsupported condition type) and that's the *only* pending change, the platform now surfaces exactly why — from the Config page and the global Apply button both — instead of the change simply never appearing at all.
- **Dashboard now shows live activity**: a large active-sessions count and a "who accessed what in the last 5 minutes" table, with a click-through to any device's full time-sorted history.
- **Promote a command straight into a policy from Accounting** — not just into a command set; the platform finds or creates the right one automatically.
- **Apply AAA config to any manually-added device**, not just ones discovered by a scan — using the device's own already-saved secret, with a safe, placeholder-based preview so the real secret is never shown in the browser.
- **`bootstrap.sh`** — a single bash script that ensures Python 3 is available (installing it via apt if missing) and hands off to the real installer, for the rare case a fresh machine doesn't have Python yet.
- A real, repeat bug in the Command Set editor is fixed: a rule containing a literal "." (IP addresses, version numbers) was always shown as raw "Custom regex" instead of its original plain text — root-caused and fixed with a proper round-trip check.
- Modals now size to their content and keep Save/Cancel always visible via a sticky footer, instead of a fixed width with buttons that could scroll out of view.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full technical history of every increment, including exactly what's confirmed-real `tac_plus-ng`/Cisco IOS syntax versus a reasoned extension — nothing here is presented as more finished or more certain than it is.

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
- Changes go through a **candidate → validate → diff → apply → automatic rollback** workflow, reachable from a single **Apply Configuration** button on every page — which also surfaces, by name and reason, any policy that can't be compiled at all, so a silent exclusion is never invisible
- Day-to-day operations — add a device, create a user, build a multi-condition access policy, discover and provision new hardware over SSH, watch live authentication activity — happen entirely through a web GUI, never by editing the config file by hand

The TACACS+ engine itself is **never modified**. NetworkAAA only ever *configures* it — an unmodified, separately-built copy of the real upstream source. See [Verification Philosophy](#verification-philosophy-tac_plus-ng) for why the project keeps this boundary strict.

---

## Key Features

| Area | Capabilities |
| --- | --- |
| **Network Devices** | Full CRUD, encrypted shared secrets (Fernet), device groups with member management, config compiler with candidate/diff/apply/rollback, device-level access grants, device-overlap validation, a visible "secret configured" indicator so a scan-provisioned device's secret is never mistaken for missing |
| **Network Scan & Provision** | Scan an IP range for SSH-reachable hosts; push Cisco IOS TACACS+ client AAA configuration (single or bulk) with live progress and an admin-editable, persistent command template; automatic device creation with `show version`-derived vendor/platform/description and a unique secret per device |
| **Apply AAA to Existing Devices** | Any manually-added device gets its own Apply AAA action too, reusing its own already-saved secret rather than generating a new one — with an editable, placeholder-masked command preview so the real secret is never exposed in the browser |
| **Monitoring Mode** | See connection attempts from unconfigured devices live, via a safe catch-all mechanism that never affects already-configured devices; one-click Add |
| **Active Directory / LDAP** | Simple Domain/Username/Password setup with an Advanced section for full control; real connectivity testing and health checks; browse-and-select pickers for AD users and groups; configures `tac_plus-ng`'s own MAVIS backend |
| **TACACS+ Users & Groups** | bcrypt-hashed passwords or AD-linked (no local password) accounts, native `tac_plus-ng` group support with member management, device-group membership, trusted-host field (stored for planning; not yet enforced) |
| **Authorization Policies** | Priorities start at 0 and insert-and-shift like an ordered list (no manual renumbering, no reject-on-conflict); an interactive two-list condition picker as the default view plus a full AND/OR/NOT advanced tree builder with unlimited nesting; full version history with diff/restore; a Policy Simulator with a step-by-step evaluation trace; a silently-uncompilable policy is surfaced with a specific reason from the Config page and the global Apply button |
| **Command Sets** | Reusable, named permit/deny rule collections referenced by one or more policies; "starts with / contains / exact / custom regex" pattern builder that correctly round-trips back to plain text, not raw regex, when you reopen a rule; promote a command straight from the Accounting page into a Command Set *or directly into a policy* |
| **Network Operations** *(new)* | Run commands against one or more devices or device groups, with automatic deduplication when the same device is reachable through more than one selection; reusable Command Templates; live per-device, per-command execution progress with full raw output retained for every run; a small Check engine evaluating already-collected output against real Cisco IOS hardening checks (AAA, password encryption, VTY transport, HTTP server), never guessing when evidence is missing — a real execution and evaluation engine, kept deliberately distinct from Command Sets (a TACACS+ authorization concept, not a command-execution one) |
| **Command Categories** | A vendor-scoped command taxonomy for reporting/filtering, with an optional risk-level tag |
| **Dashboard** | Live active-sessions count and a "who accessed what in the last 5 minutes" table with a per-device drill-down, alongside hourly activity and authorization-result charts |
| **Sessions & Accounting** | Session view correlating accounting start/stop records; searchable, filterable accounting logs with CSV export; AAA Health page with real permit/deny and failure-analysis breakdowns; Effective Access lookups |
| **Diagnostics** | On-demand config validation that distinguishes a definitive failure from a genuinely inconclusive one, configuration audit trail, service logs, auth/authz log tails |
| **Platform Self-Management** | Granular, role-based RBAC (strictly additive over the original superadmin/standard split) alongside per-admin trusted-host IP restrictions (enforced), full HTTPS support, structured config backup export/import with version checking, an admin-editable persistent AAA command template |
| **GUI** | Single-window shell with client-side view transitions across every page, a global Apply Configuration button, ESC-to-close with unsaved-changes protection, modern scrollbars, content-sized modals with an always-visible sticky footer |

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
   ├──► PostgreSQL (source of truth)
   │
   ├──► Configuration Compiler ──► Candidate tac_plus-ng.conf ──► Validate ──► Diff ──► Apply ──► tac_plus-ng
   │
   └──► SSH Provisioning ──► Cisco IOS devices (pushes the client-side TACACS+ AAA config)
```

- The database is **always** the source of truth.
- The generated `tac_plus-ng.conf` is a derived artifact — never hand-edited.
- Every change is validated before being applied, and a global **Apply Configuration** button (visible whenever changes are pending, or whenever a policy can't compile and needs attention) is available from any page, not just the Config page.
- If the daemon fails to come back healthy after an apply, the previous configuration is automatically restored.
- A migrated policy's condition tree compiles into real `tac_plus-ng` boolean expressions (`&&`, `||`, `==`, `!=`, and generated `acl {}` blocks for CIDR matching). Anything that can't be safely compiled — a bare-username condition, a NOT group — excludes just that one policy from the generated ruleset, with the reason recorded as an auditable event *and* surfaced directly in the GUI, rather than guessing at syntax or leaving the exclusion invisible.
- Device-level access grants and monitoring mode's catch-all host block are both emitted in a specific, deliberate position in the generated ruleset/host list — precedence and safety come from that ordering, not from priority-number tricks.
- Network Scan & Provision, and the Apply AAA action on any existing device, are the mirror image of the compiler: instead of configuring `tac_plus-ng`, they SSH into a network device and configure *it* to point at this platform — the real secret involved is generated server-side or read from encrypted storage, and is never sent to or displayed in the browser.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design, including the module system, privilege model, the policy engine internals, and directory layout.

---

## Technology Stack

| Layer | Technology |
| --- | --- |
| **Data plane** | `tac_plus-ng` (upstream C, completely unmodified) |
| **Management plane** | FastAPI + SQLAlchemy + PostgreSQL |
| **Frontend** | Server-rendered Jinja2 + vanilla JavaScript (no build step, no frontend framework); Chart.js loaded on-demand for the Dashboard |
| **Directory integration** | `ldap3` (pure-Python LDAP client) for Active Directory connectivity |
| **Device provisioning** | `paramiko` (SSH client) for pushing configuration to network devices |
| **OS target** | Ubuntu Server 22.04 / 24.04 / 26.04 LTS — **native install only** |
| **Deployment style** | No containers, no Python virtual environments, system-wide packages |

Python dependencies (see `requirements.txt`) are installed system-wide with `--break-system-packages` when the externally-managed-environment marker is present.

---

## Project Status

The original 8-phase build plan is complete through Phase 7, plus a substantial expansion well beyond it:

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

**Beyond the original plan — done:**

- Policy condition engine (tree-based, compiler-integrated, interactive GUI, unlimited nesting), with insert-and-shift priority ordering starting at 0
- A silently-uncompilable policy is now surfaced directly in the GUI with a specific reason, not just recorded after the fact
- Command Sets & Command Categories, Policy Versioning, Policy Simulator, Effective Access, and promoting an observed command directly into a policy from Accounting
- Session Monitoring, AAA Health & Failure Analysis, Dashboard charts *and* live activity (active-session count, last-5-minutes table, per-device drill-down)
- Device-level Access Grants, device-overlap validation
- Granular, role-based RBAC (additive over the original two-tier model)
- Active Directory / LDAP integration (settings, testing, health, AD pickers, MAVIS config generation)
- Monitoring mode (unrecognized-device discovery)
- Network Scan & Provision (SSH-based bulk device onboarding with live progress, `show version`-derived device info) *and* an Apply AAA action for devices added manually
- Config backup/restore from file with version checking
- Group membership management (TACACS+ Groups and Device Groups)
- Global Apply Configuration button, ESC-to-close with unsaved-changes protection
- `bootstrap.sh` for environments without Python 3 pre-installed; interactive `apt-get update` prompt in the main installer
- Uninstall support
- TACACS+ user trusted-host (data model + GUI only — see limitations)
- Full HTTPS control, per-admin trusted-host
- Single-window GUI redesign (complete — every authenticated page), content-sized modals with sticky Save/Cancel
- **Network Operations & Assurance Engine, Phase 1 (Command Jobs) and Phase 3 (Check Engine)** — run commands against devices/device groups with deduplication, reusable Command Templates, live per-device/per-command progress, full raw-output history; a small registry of real Cisco IOS hardening checks (AAA new-model, password encryption, VTY SSH-only transport, HTTP server disabled) evaluating already-collected job output, with a strict "never guess PASS/FAIL when evidence is missing" discipline. Two increments of a much larger, explicitly phased capability (12 phases total: Command Jobs → Templates → Check engine → Audit engine → security-auditor integration → remediation → compliance → scheduling → fleet Finder → visualization) — Phase 2 (Templates, effectively covered already by Phase 1) and Phase 3 are built; Phases 4-12 are not. See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full assessment and what's deliberately deferred.

**Not yet implemented:**

- Module Management GUI (Phase 8)
- CLI
- Automated test suite
- RADIUS backend
- "Demo mode" (timed configuration apply with automatic revert) — deliberately deferred; a scheduled auto-revert carries real safety weight if done wrong, and deserves a dedicated design pass rather than a rushed addition
- Granular RBAC is applied to Policies, Command Sets, Devices, Device Groups, and Network Operations so far — not yet extended to every route in the API
- Command-as-a-policy-condition — researched and deliberately not implemented (no confirmed `tac_plus-ng` syntax for it; see Known Limitations)
- Network Operations & Assurance Engine, Phases 4-12 (Audit engine grouping multiple checks into a named suite, Cisco IOS security-auditor domain integration, interface security engine, remediation/approval workflow, compliance mapping, scheduling, fleet Finder, visualization) — not started. Phase 3's Check engine currently has only 4 starter checks, all Management Plane / Cisco IOS, all requiring `show running-config` specifically — no Layer 2/3/CoPP/VPN/PKI domains yet, no correlation engine, no per-device Security Score.

---

## Requirements

- **OS:** Ubuntu Server 22.04, 24.04, or 26.04 LTS
- **Privileges:** Root / sudo
- **Network:** Outbound internet **during installation** (to download `tac_plus-ng` source and apt packages), and to reach any Active Directory server or network devices you configure at runtime. TACACS+ operation itself requires no internet.
- **Python:** 3.8+ (the installer itself requires this — see `bootstrap.sh` below if a target machine doesn't have it yet)

---

## Installation

### Quick Start

```bash
git clone https://github.com/jafartavana01/NetworkAAA.git
cd NetworkAAA
sudo python3 setup.py
```

If the target machine doesn't have Python 3 yet, use the bootstrap script instead — it installs Python 3 via apt if needed, then runs the exact same installer:

```bash
sudo bash bootstrap.sh
```

Both are interactive and will guide you through the process. `bootstrap.sh` passes any arguments straight through to `setup.py` — for example, `sudo bash bootstrap.sh -u` uninstalls, exactly like `sudo python3 setup.py -u` would.

> **Important:** The full source tree (including `app/`, `installer/`, and `docs/`) must be present for the installer to succeed — cloning only the top-level files will not work.

### What the Installer Does

| Phase | Actions |
| --- | --- |
| **System Detection** | Checks Ubuntu version, Python, internet connectivity, and reports any problems. Allows you to continue on near-supported systems if desired. |
| **Dependencies** | Asks whether to run `apt-get update` first (default: yes; index refresh only, never `upgrade`), then installs all required system packages. |
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
4. Go to **Platform → Admin Users** to manage additional administrators, assign roles, and set per-account trusted-host IP restrictions. Go to **Platform → Admin Roles** to create or edit roles and their permissions.

### The Global Apply Configuration Button

Visible from any page, whenever there's something that needs your attention:

- **Pending changes** — click it to see the diff and apply, exactly like the Config page's own button.
- **A policy can't compile** — even with nothing else pending, the button shows a distinct warning state (⚠ Policy Excluded) naming the policy and the specific reason it's excluded from the real configuration, so this is never silently invisible.

### Devices, Monitoring & Network Scan

- Create devices manually with name, IP/hostname, and shared secret (encrypted at rest); a **"✓ Configured"** badge confirms a secret is saved without ever displaying it. Organize devices into Device Groups, which support full member management from the group's own page.
- **Apply AAA config** works on *any* device, not just ones from a scan — click it on a manually-added device, enter SSH credentials, and the platform pushes the AAA template using that device's own already-saved secret. The command preview is editable; the real secret is shown only as a placeholder, never in plaintext, and is substituted in automatically unless you deliberately replace it (in which case the stored secret updates to match what you actually sent).
- **Access Grants**: give a user group unrestricted privilege-15 access to a device or device group, evaluated *before* any policy — intended for break-glass-style access, group-only by design.
- **Monitoring**: enable to see connection attempts from devices that aren't configured yet, live, with a one-click Add (assigns to a seeded "monitor" group). Requires applying the configuration for the underlying mechanism to take effect — watch for the global Apply Configuration button.
- **Network Scan & Provision**: enter an IP range and SSH credentials, scan for reachable hosts, then push Cisco IOS AAA configuration to one or all of them — with an editable command preview, a persistent admin-customizable default template, live per-device progress during a bulk apply, and automatic vendor/platform/description population from each device's own `show version` output.

### Active Directory

- Go to **Platform → Active Directory**. Enter your domain name, a service account username, and its password — host, search base, and filter are derived automatically; expand Advanced to override anything.
- **Test Connection** before saving to confirm this platform can reach and bind to your AD server.
- Once enabled and applied, AD group membership becomes available as User Group conditions in policies, same as local groups.
- On the Users and Groups pages, use the AD search picker to link a local record to a real AD identity, or type one manually.

### TACACS+ Users & Groups

- Create local users with bcrypt-hashed passwords, or AD-linked users (no local password — authentication is delegated to `tac_plus-ng`'s AD integration).
- Assign a group, or use the **Members** view on the Groups page to add/remove users directly.
- A user's "trusted hosts" field can be set for planning purposes, but is **not currently enforced** — the GUI says so directly.

### Authorization Policies

- Priorities start at **0**. The default condition builder is a two-list picker: **Users & Groups** and **Devices & Device Groups**, each with Add/Remove. Switch to the **Advanced** tab for full AND/OR/NOT logic, Source IP conditions, and unlimited nesting.
- Entering a priority that's already in use doesn't reject the save — it inserts the policy there and shifts every affected policy by exactly one slot to make room, the same way inserting into an ordered list works, in either direction.
- A policy's **result** is a privilege level, a default action, and zero or more **Command Sets**.
- Every save creates a new **version** — view history, diff, or restore (restoring creates a new version; nothing is ever destroyed).
- Use the **Policy Simulator** to test a hypothetical request and see the full evaluation trace. **Effective Access** answers "what can this user access?" and "who can access this device?" directly.
- If a policy can't be compiled into the real configuration (e.g. it uses a condition type with no confirmed `tac_plus-ng` syntax), the global Apply button and the Config page both show exactly which policy and why — never a silent, invisible gap.

### Command Sets & Command Categories

- A Command Set is a named, reusable collection of permit/deny command rules, referenced by one or more policies.
- Build rules with "Starts with / Contains / Exact match / Custom regex" — no need to hand-write a regex for common cases, and reopening an existing rule correctly shows your original plain text back, not a raw escaped pattern.
- Promote a command straight from the **Accounting** page — into an existing Command Set, or **directly into a policy**, in which case the platform finds or creates the right command set for you automatically.

### Sessions, Accounting & the Dashboard

- **Dashboard** now shows a large live count of active sessions, and a table of every device/user pair active in the last 5 minutes — click a device to see its full time-sorted activity history.
- **Sessions** correlates accounting records by device and port to show active and historical TACACS+ sessions.
- **Accounting** is fully searchable and filterable, with CSV export.
- **AAA Health** shows genuine permit/deny breakdowns and failure analysis from real parsed accounting data.

### Diagnostics

- On-demand configuration validation, distinguishing a **definitive** syntax failure from a genuinely inconclusive one.
- Configuration change audit trail, live service logs, authentication/authorization log tails.

### Platform Self-Management

- **Admin Roles**: create named roles with a specific set of permissions, or start from a template (Read-Only Auditor, Policy Manager, Device Operator). A superadmin always has full access regardless of role; an account with no role assigned keeps the original full standard-admin access.
- Per-admin trusted-host IP allow-lists, full HTTPS control.
- **Configuration backup/restore**: export a structured, version-tagged backup file; restoring checks version compatibility first and shows a diff before you confirm anything.
- **Default AAA command template**: the Cisco IOS commands pushed by both Network Scan and the per-device Apply AAA action are admin-editable and persist for future use, not just a one-off edit.

### Network Operations *(Phase 1 — Command Jobs, Phase 3 — Check Engine)*

- Go to **Network Operations → Command Jobs → New Command Job**. Select targets (individual devices, device groups, or both — the same device selected two different ways only runs once), either type commands directly or start from a saved template, and supply SSH credentials for this run (never stored). **Preview Targets** shows exactly which devices will be reached before you commit.
- Sequential or controlled-parallel execution, with configurable concurrency and per-command/connection timeouts.
- The job detail page live-polls progress while running, then shows every command's classification (read-only / configuration / destructive / unknown — a heuristic aid, always review the actual command list yourself) alongside its full raw output.
- **Templates** page: build and reuse named command lists across future jobs — include `show running-config` (or `sh run`) if you want to run Checks against a job's results afterward.
- **Checks**: from a job's detail page, click **Run Checks** to evaluate that job's already-collected output against the registered check library — no new device connection is made. Results show PASS/FAIL/NOT_APPLICABLE with evidence and a suggested fix where relevant; a device whose job didn't collect `show running-config` output correctly reports NOT_APPLICABLE rather than a guessed result. See the **Checks** page for the full registered catalog.
- This is an early slice of a much larger, explicitly phased capability — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for what's built versus deliberately deferred.

---

## Configuration Compiler & Safe Apply Workflow

Whenever you change devices, users, groups, or policies:

1. The management plane generates a **candidate** configuration from the current database state.
2. The candidate is validated against the real `tac_plus-ng` binary's own syntax checker.
3. You're shown a **diff** against the currently running configuration — from the Config page, or from the **Apply Configuration** button available on every page whenever changes are pending (or whenever a policy needs attention because it can't compile).
4. On apply, the new configuration is written and `tac_plus-ng` is reloaded.
5. If the daemon doesn't come back healthy, the previous configuration is **automatically restored**.

A validation failure the daemon itself reports unambiguously **blocks the apply outright** — nothing is written to disk or touched on the live daemon — rather than relying solely on the post-reload health check to catch it after the fact.

This protects you from locking yourself out of network devices due to a bad authorization rule or syntax error.

---

## Directory Layout (After Installation)

```
/opt/aaa-platform/
├── app/                     # Management application (FastAPI + Jinja2)
│   ├── run.py               # systemd entrypoint
│   ├── platform_settings.py
│   ├── models/
│   ├── services/            # config_compiler.py, policy_engine.py, condition_engine.py,
│   │                        #   ad_directory.py, monitoring.py, network_scan.py,
│   │                        #   ssh_provision.py, tls_certs.py, …
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
bootstrap.sh                  # Ensures Python 3 is available, then runs setup.py
installer/                    # Installer implementation modules
app/                           # Application source (copied to /opt)
docs/
  ├── INSTALL.md
  ├── ARCHITECTURE.md
  └── PAM_EXPANSION_PLAN.md
CHANGELOG.md
requirements.txt
LICENSE
README.md
```

---

## Security Model

- Device shared secrets, AD bind passwords, and per-device provisioning secrets are all encrypted at rest (Fernet) and never logged.
- A device's shared secret is never displayed once set, anywhere — including in the Apply AAA command preview, where a clearly-fake placeholder stands in for it and the real value is substituted only server-side, at the moment of the actual SSH push.
- Administrator passwords are bcrypt-hashed; never stored or logged in plaintext.
- SSH credentials used for Network Scan & Provision and the per-device Apply AAA action are **never persisted** — used only for the duration of the request that needs them.
- CSRF protection on every state-changing request.
- Least-privilege service account with a narrowly-scoped sudoers rule (only the two systemd units it needs to control).
- Identifiers are restricted to a safe character set at input time (config-injection defense by construction rather than escaping).
- HTTPS is fully supported (self-signed generated at install time; custom certificates can be uploaded).
- A policy's condition tree is validated as a whole on save — a bad database reference, an invalid operator, or a malformed CIDR anywhere in the tree rejects the entire save, never a partially-applied one.
- Every device-provisioning AAA push includes `local` and `if-authenticated` fallbacks, so a misconfigured or unreachable TACACS+ server can't lock a device's own console/SSH access — `aaa authorization console` extends the same protected method lists to the console line specifically, rather than defining a separate one.
- Monitoring mode's catch-all mechanism, and device network-overlap validation, are both designed to be safe regardless of an unconfirmed `tac_plus-ng` host-matching precedence question — see `docs/ARCHITECTURE.md` for the reasoning.

If you discover a security issue, please open a GitHub issue or contact the maintainer privately for sensitive reports.

---

## Verification Philosophy (tac_plus-ng)

`tac_plus-ng`'s configuration language is not fully documented in a single place. Every claim this project makes about its syntax — or about Cisco IOS's own AAA configuration, for the device-provisioning side — is explicitly tagged as one of:

- **Confirmed** — verified against a real working configuration (upstream sample, real deployment, or a live test)
- **Reasoned, not verified** — a defensible extension of confirmed language mechanics, clearly called out as such

This project has, more than once, caught and corrected its own mistakes in this area rather than letting them stand — including a case where a "reasoned, not confirmed" field turned out to be genuinely invalid syntax when tested against a real deployment, and was removed. The distinction is documented throughout `docs/ARCHITECTURE.md` and in code comments at every point it matters. The project deliberately avoids silently guessing at protocol or configuration behavior — when something can't be confirmed, it's either left unimplemented or clearly labeled as unenforced, never quietly assumed to work.

`tac_plus-ng` itself is used strictly as an unmodified, upstream dependency, built fresh from the real source at install time — never forked or vendored into this project's own repository. Its own license (a permissive, BSD-style license from Marc Huber) allows for that, but this project's own installer-driven build keeps the two codebases and their licenses cleanly separate, and lets every install automatically pick up upstream fixes with no merge work required.

---

## Known Limitations & Roadmap

**Current limitations**

- No CLI yet
- No automated test suite
- No RADIUS backend yet (LDAP/AD is implemented)
- Phase 8 (Module Management) not started
- Granular RBAC covers Policies, Command Sets, Devices, and Device Groups — not yet extended to every route
- TACACS+ user trusted-host is stored but **not enforced** — no confirmed `tac_plus-ng` syntax exists yet for restricting one specific user (as opposed to a whole group) by source IP
- Device-level Access Grants and per-user targeting in the condition builder are **group-only** — same underlying reason: no confirmed syntax exists for matching a bare username
- Command-as-a-policy-condition was researched and deliberately not implemented — every real-world `tac_plus-ng` configuration example found checks commands only inside a profile's own script, never as part of policy/ruleset selection
- NOT-groups in the condition builder are supported for evaluation and simulation, but not yet compilable into the generated config — no confirmed `!` operator exists
- "Demo mode" (timed apply with automatic revert) is not implemented — deliberately deferred pending a dedicated design pass, given the real safety implications of a buggy auto-revert
- Network Scan & Provision and the per-device Apply AAA action both generate Cisco IOS-specific AAA commands — stated as exactly that, not vendor-detected or vendor-generic
- Full source (`app/`, `installer/`, `docs/`) must be present for the installer to succeed

**Planned**

- Module Management GUI (Phase 8)
- Granular RBAC extended to the remaining API surface
- Demo mode, once designed carefully
- RADIUS support
- CLI and comprehensive automated testing

---

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| Installer aborts on system checks | Read the printed report. You can force-continue on near-supported systems. |
| Machine has no Python 3 at all | Use `sudo bash bootstrap.sh` instead of `sudo python3 setup.py` — it installs Python 3 first |
| Management service fails to start | `journalctl -u aaa-platform.service -e` |
| tac_plus-ng fails to start | `journalctl -u tac-plus-ng.service -e` and check the generated config under Diagnostics |
| Cannot reach GUI | Confirm firewall allows TCP/8420 (or whatever port you configured) |
| HTTPS not working | Enable it under **Platform → Settings** after confirming HTTP works |
| Config apply rejected outright | The daemon's own syntax check found a definitive error — see the message shown; nothing was applied |
| Config apply rolls back after being applied | Check the validation output and daemon logs on the Diagnostics page; the previous config was restored automatically |
| A new/edited policy never shows as a pending change | Check the global Apply button and the Config page for a "⚠ Policy Excluded" warning — the policy may be using a condition type with no confirmed `tac_plus-ng` syntax, which is now shown by name and reason rather than silently producing no diff |
| Monitoring mode shows nothing | Confirm you've applied the configuration after enabling it — the global Apply Configuration button will show if changes are pending |
| AD Test Connection fails | Check host/port/TLS in the Advanced section, and confirm the bind account has read access to the search base |
| Network Scan finds nothing | Confirm the target range has hosts with SSH (port 22) reachable from this platform, not just ICMP-reachable |
| SSH Apply fails with an auth error | Double-check the SSH username/password entered — these are never saved, so they must be re-entered each session |
| Command Set rule shows raw regex instead of my original text | Fixed — reopening a rule now correctly reconstructs "Starts with / Contains / Exact" and the original plain text whenever the stored pattern is exactly what one of those modes would produce |

Install log: `/tmp/aaa-platform-install.log`
Build record: `/etc/aaa-platform/build_info.json`

---

## Contributing

Contributions are welcome once the full source tree is published.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Open a pull request with a clear description

Please keep the "Confirmed vs Reasoned" distinction for any `tac_plus-ng`/Cisco IOS configuration claims, and never implement a feature that requires guessing at unconfirmed syntax — see [Verification Philosophy](#verification-philosophy-tac_plus-ng).

---

## Acknowledgments

Built on top of [`tac_plus-ng`](https://github.com/MarcJHuber/event-driven-servers) by Marc Huber and contributors — the actual TACACS+ engine that performs the protocol work underneath this platform.

---

## License

This project is licensed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for the full text.

---

**NetworkAAA** — because managing TACACS+ shouldn't require editing configuration files by hand.
