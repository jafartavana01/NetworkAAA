# NetworkAAA — Enterprise TACACS+ AAA Management Platform

**Open-source enterprise AAA platform for network infrastructure**  
Centralized TACACS+ authentication, authorization, policy management, accounting, auditing, and privileged access governance — built around the real upstream `tac_plus-ng` daemon.

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2022.04%20%7C%2024.04%20%7C%2026.04-orange)]()
[![Python](https://img.shields.io/badge/Python-3.8%2B-blue)]()
[![Status](https://img.shields.io/badge/Status-Phases%201–7%20Complete-green)]()

---
<img width="1555" height="1166" alt="v1" src="https://github.com/user-attachments/assets/fcec4b33-8081-4acf-af09-374f9b43ffa9" />

## Table of Contents

- [Why NetworkAAA Exists](#why-networkaaa-exists)
- [Key Features](#key-features)
- [Architecture Overview](#architecture-overview)
- [Technology Stack](#technology-stack)
- [Project Status](#project-status)
- [Requirements](#requirements)
- [Installation](#installation)
  - [Quick Start](#quick-start)
  - [Detailed Installation Walkthrough](#detailed-installation-walkthrough)
  - [What the Installer Does](#what-the-installer-does)
  - [Post-Install Access](#post-install-access)
- [How to Use](#how-to-use)
  - [First Login & Platform Settings](#first-login--platform-settings)
  - [Managing Network Devices](#managing-network-devices)
  - [TACACS+ Users & Groups](#tacacs-users--groups)
  - [Authorization Policies](#authorization-policies)
  - [Accounting](#accounting)
  - [Diagnostics](#diagnostics)
  - [Platform Self-Management](#platform-self-management)
- [Configuration Compiler & Safe Apply Workflow](#configuration-compiler--safe-apply-workflow)
- [Directory Layout (After Installation)](#directory-layout-after-installation)
- [Security Model](#security-model)
- [Verification Philosophy (tac_plus-ng)](#verification-philosophy-tac_plus-ng)
- [Known Limitations & Roadmap](#known-limitations--roadmap)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [Acknowledgments](#acknowledgments)
- [License](#license)

---
<img width="1730" height="852" alt="v2" src="https://github.com/user-attachments/assets/9e18bcd0-58e9-4e48-b5d1-45a6a0782a1c" />

## Why NetworkAAA Exists

`tac_plus-ng` (from [Marc Huber’s event-driven-servers](https://github.com/MarcJHuber/event-driven-servers)) is a capable, actively maintained TACACS+ daemon.  
However, it is traditionally configured by hand-editing a text file that uses its own domain-specific language.

NetworkAAA places a real **management plane** in front of it:

- PostgreSQL becomes the **single source of truth**
- A configuration compiler turns database state into valid `tac_plus-ng` configuration
- Changes go through a **candidate → validate → diff → apply → automatic rollback** workflow
- Day-to-day operations (add a device, create a user, change who can run `configure terminal`) happen through a clean web GUI — never by editing the config file by hand

The TACACS+ engine itself is **never modified**. NetworkAAA only ever *configures* it.

---

## Key Features

| Area | Capabilities |
|------|--------------|
| **Network Devices** | Full CRUD, encrypted shared secrets (Fernet), device groups, configuration compiler with candidate/diff/apply/rollback |
| **TACACS+ Users & Groups** | bcrypt-hashed passwords, native `tac_plus-ng` group support, device-group membership |
| **Authorization Policies** | Privilege levels, permit/deny command rules with deny-overrides semantics, Cisco IOS starter templates (Admin / Network-Manager / Auditor) |
| **Accounting** | Searchable, filterable accounting logs + CSV export over a deliberately parseable log format |
| **Diagnostics** | On-demand config validation, configuration audit trail, service logs, authentication/authorization log tails |
| **Platform Self-Management** | Two-tier RBAC (superadmin vs standard), per-admin trusted-host IP restrictions, full HTTPS support (self-signed by default + custom certificate upload) |
| **GUI** | Server-rendered Jinja2 with a single-window shell (client-side view transitions). Every page also works as pure server-rendered HTML with zero JavaScript required |

---

## Architecture Overview
<img width="1855" height="826" alt="v3" src="https://github.com/user-attachments/assets/78d24936-f55c-4a3a-9112-e65aa4b29f2e" />

```
Browser
   │
   ▼
Web GUI (server-rendered Jinja2 + optional JS shell)
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

---

## Technology Stack

| Layer | Technology |
|-------|------------|
| **Data plane** | `tac_plus-ng` (upstream C, completely unmodified) |
| **Management plane** | FastAPI + SQLAlchemy + PostgreSQL |
| **Frontend** | Server-rendered Jinja2 + vanilla JavaScript (no build step, no frontend framework) |
| **OS target** | Ubuntu Server 22.04 / 24.04 / 26.04 LTS — **native install only** |
| **Deployment style** | No containers, no Python virtual environments, system-wide packages |

Python dependencies (see `requirements.txt`) are installed system-wide with `--break-system-packages` when the externally-managed-environment marker is present.

---

## Project Status
<img width="1489" height="833" alt="v4" src="https://github.com/user-attachments/assets/5b5c93c6-6996-4f85-bfaf-8bc369bbb3a7" />

Phases 1–7 of the original 8-phase plan are complete:

| Phase | Area | Status |
|-------|------|--------|
| 1 | Installer, GUI shell, live dashboard | ✅ Done |
| 2 | Network Devices + configuration compiler | ✅ Done |
| 3 | TACACS+ Users (end-to-end auth tested) | ✅ Done |
| 4 | TACACS+ Groups & Device Groups | ✅ Done |
| 5 | Authorization Policies | ✅ Done |
| 6 | Accounting | ✅ Done |
| 7 | Diagnostics | ✅ Done |
| 8 | Module Management | ⏳ Not started |

**Also completed outside the original plan:**

- Platform self-management (two-tier RBAC, trusted-host IP restrictions, HTTPS)
- Single-window GUI redesign (in progress)

**Not yet implemented:**

- CLI
- Automated test suite
- RADIUS, LDAP, or Active Directory backends (architecture is designed to accommodate them without a redesign)

---

## Requirements

- **OS:** Ubuntu Server 22.04, 24.04, or 26.04 LTS
- **Privileges:** Root / sudo
- **Network:** Outbound internet **only during installation** (to download `tac_plus-ng` source and apt packages). Runtime requires no internet.
- **Python:** 3.8+ (the installer itself requires this)

---
<img width="874" height="790" alt="v5" src="https://github.com/user-attachments/assets/10ee981e-bcfe-4786-aaf2-8e7d03475642" />

## Installation

### Quick Start

```bash
git clone https://github.com/jafartavana01/NetworkAAA.git
cd NetworkAAA
sudo python3 setup.py
```

The installer is interactive and will guide you through the process.

> **Important:** The full source tree (including `app/`, `installer/`, and `docs/`) must be present for the installer to succeed. The currently published GitHub repository only contains the top-level files (`setup.py`, `requirements.txt`, `LICENSE`, `README.md`). Make sure the complete source is available before running the installer.

### Detailed Installation Walkthrough

1. Clone the repository (full source including `app/`, `installer/`, and `docs/` must be present).
2. Run the installer as root:

   ```bash
   sudo python3 setup.py
   ```

3. The installer performs the following phases automatically (see next section).
<img width="1685" height="788" alt="v6" src="https://github.com/user-attachments/assets/0ba90123-1ed2-4408-b4f6-60ebc496bb6a" />

### What the Installer Does

| Phase | Actions |
|-------|---------|
| **System Detection** | Checks Ubuntu version, Python, internet connectivity, and reports any problems. Allows you to continue on near-supported systems if desired. |
| **Dependencies** | Runs `apt update` and installs all required system packages. |
| **tac_plus-ng Build** | Clones/updates the real upstream source, lets you choose a build profile (or custom `./configure` flags), builds, installs, and records build metadata. |
| **PostgreSQL** | Provisions a dedicated database and user for the platform. |
| **Application Install** | Creates a least-privilege service account, copies application source to `/opt/aaa-platform/app`, installs Python dependencies system-wide, sets ownership, provisions secret files, and installs a narrowly-scoped sudoers rule. |
| **Schema & Admin** | Creates the database schema and walks you through creating the first **superadmin** account. |
| **TLS & Settings** | Generates a self-signed certificate (HTTPS is **off** by default) and writes default platform settings. |
| **Bootstrap Config** | Writes a minimal working `tac_plus-ng` configuration so the daemon can start. |
| **systemd** | Creates and enables two units (management GUI + `tac_plus-ng`). Starts both and performs first-start diagnostics. |

Installation logs are written to `/tmp/aaa-platform-install.log`.  
Full build metadata is stored at `/etc/aaa-platform/build_info.json`.
<img width="1650" height="818" alt="v7" src="https://github.com/user-attachments/assets/4c4a20bc-c03e-425e-9e07-fb6bfcf4cd6c" />

### Post-Install Access

After a successful install you will see something like:

```
Management GUI:  http://<server-ip>:8420
```

- Default listen address: all interfaces
- Default port: **8420**
- Protocol: **HTTP** (HTTPS is generated but disabled until you enable it under Platform → Settings)

---

## How to Use
<img width="1672" height="849" alt="v8" src="https://github.com/user-attachments/assets/8b4ac2c0-9dba-4938-a1dc-1d2e20e1da78" />

### First Login & Platform Settings

1. Open `http://<server-ip>:8420` in a browser.
2. Log in with the superadmin account you created during installation.
3. Go to **Platform → Settings** (superadmin only) to:
   - Change bind address / port
   - Enable HTTPS
   - Regenerate the self-signed certificate or upload your own certificate + key
4. Go to **Platform → Admin Users** to manage additional administrators and set per-account trusted-host IP restrictions.

### Managing Network Devices

- Create devices with name, IP/hostname, and shared secret (encrypted at rest with Fernet).
- Organize devices into **Device Groups**.
- The configuration compiler uses these objects when generating `tac_plus-ng` configuration.

### TACACS+ Users & Groups

- Create users with bcrypt-hashed passwords.
- Assign users to TACACS+ groups.
- Groups can be mapped to device groups and authorization policies.

### Authorization Policies

- Define privilege levels and command authorization rules.
- Rules support permit/deny with **deny-overrides** semantics.
- Starter templates are provided for common Cisco IOS roles:
  - Admin
  - Network-Manager
  - Auditor

### Accounting
<img width="1690" height="824" alt="v9" src="https://github.com/user-attachments/assets/671968ff-e880-4d7d-acc0-042aa3c43198" />

- View, search, and filter accounting records.
- Export to CSV.
- The log format is intentionally designed to be reliably parseable.

### Diagnostics

- On-demand configuration validation
- Configuration change audit trail
- Live service logs
- Authentication and authorization log tails
<img width="1842" height="851" alt="v10" src="https://github.com/user-attachments/assets/bfea49f0-8791-445c-bced-fcf98c638504" />

### Platform Self-Management

- **Two-tier RBAC**: superadmin vs standard admin
- Per-admin **trusted-host** IP allow-lists
- Full control over HTTPS (self-signed generation or custom certificate upload)
- All of the above is managed from the GUI under **Platform → …**

---

## Configuration Compiler & Safe Apply Workflow


<img width="1864" height="830" alt="v11" src="https://github.com/user-attachments/assets/524d5d8e-f560-4730-856a-91599acfc9ba" />

Whenever you change devices, users, groups, or policies:

1. The management plane generates a **candidate** configuration from the current database state.
2. The candidate is validated.
3. You are shown a **diff** against the currently running configuration.
4. On apply, the new configuration is written and `tac_plus-ng` is reloaded/restarted.
5. If the daemon does not come back healthy, the previous configuration is **automatically restored**.

This protects you from locking yourself out of network devices due to a bad authorization rule or syntax error.

---

## Directory Layout (After Installation)

```
/opt/aaa-platform/
├── app/                    # Management application (FastAPI + Jinja2)
│   ├── run.py              # systemd entrypoint
│   ├── platform_settings.py
│   ├── models/
│   ├── services/           # includes config_compiler.py, tls_certs.py, …
│   └── …
└── …

/etc/aaa-platform/
├── build_info.json         # tac_plus-ng build metadata
├── platform settings / secrets
└── …

# systemd units
aaa-platform-management.service
aaa-platform-tac-plus-ng.service
```

The original source tree (before installation) looks like:

```
setup.py                    # Installer entrypoint
installer/                  # Installer implementation modules
app/                        # Application source (copied to /opt)
docs/
  ├── INSTALL.md
  ├── ARCHITECTURE.md
  └── PAM_EXPANSION_PLAN.md
requirements.txt
LICENSE
README.md
```

---

<img width="1733" height="833" alt="v12" src="https://github.com/user-attachments/assets/6616b4d5-0714-4c6b-99c7-f8f6c2308ca3" />

## Security Model

- Device shared secrets are encrypted at rest (Fernet) and never logged.
- Administrator passwords are bcrypt-hashed; never stored or logged in plaintext.
- CSRF protection on every state-changing request.
- Least-privilege service account with a **narrowly-scoped** sudoers rule (only the two systemd units it needs to control).
- Identifiers are restricted to a safe character set at input time (config-injection defense by construction rather than escaping).
- HTTPS is fully supported (self-signed generated at install time; custom certificates can be uploaded).

If you discover a security issue, please open a GitHub issue or contact the maintainer privately for sensitive reports.

---

## Verification Philosophy (tac_plus-ng)

`tac_plus-ng`’s configuration language is not fully documented in a single place.  
Every claim this project makes about its syntax is explicitly tagged as one of:

- **Confirmed** — verified against a real working configuration (upstream sample, real deployment, or live test)
- **Reasoned, not verified** — a defensible extension of confirmed language mechanics, clearly called out

This distinction is documented throughout the architecture notes and in code comments (especially around the configuration compiler). The project deliberately avoids silently guessing at protocol or configuration behavior.

---

## Known Limitations & Roadmap

**Current limitations**

- No CLI yet
- No automated test suite
- No RADIUS / LDAP / Active Directory backends yet
- Phase 8 (Module Management) not started
- Full source (`app/`, `installer/`, `docs/`) must be present for the installer to succeed

**Planned**

- Module Management GUI (Phase 8)
- Broader AAA / Privileged Access Management expansion (see `docs/PAM_EXPANSION_PLAN.md` when available)
- RADIUS and external identity providers
- CLI and comprehensive testing

---

## Troubleshooting

| Symptom | What to check |
|---------|---------------|
| Installer aborts on system checks | Read the printed report. You can force-continue on near-supported systems. |
| Management service fails to start | `journalctl -u aaa-platform-management.service -e` |
| tac_plus-ng fails to start | `journalctl -u aaa-platform-tac-plus-ng.service -e` and check the generated config |
| Cannot reach GUI | Confirm firewall allows TCP/8420 (or whatever port you configured) |
| HTTPS not working | Enable it under **Platform → Settings** after confirming HTTP works |
| Config apply rolls back | Check the validation output and the daemon logs; the previous config was restored for safety |

Install log: `/tmp/aaa-platform-install.log`  
Build record: `/etc/aaa-platform/build_info.json`

---

## Contributing

Contributions are welcome once the full source tree is published.

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Open a pull request with a clear description

Please keep the “Confirmed vs Reasoned” distinction for any `tac_plus-ng` configuration claims.

---

## Acknowledgments

Built on top of **[tac_plus-ng](https://github.com/MarcJHuber/event-driven-servers)** by Marc Huber and contributors — the actual TACACS+ engine that performs the protocol work underneath this platform.

---

## License

This project is licensed under the **Apache License 2.0**.  
See the [LICENSE](LICENSE) file for the full text.

---

**NetworkAAA** — because managing TACACS+ shouldn’t require editing configuration files by hand.
```
