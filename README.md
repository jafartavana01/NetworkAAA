# AAA Management Platform

A native Ubuntu Server platform for managing TACACS+ AAA (Authentication,
Authorization, and Accounting) infrastructure — built around the real
upstream [`tac_plus-ng`](https://github.com/MarcJHuber/event-driven-servers)
daemon as the data plane, with a Python (FastAPI + PostgreSQL) management
plane and web GUI on top.

The TACACS+ engine itself is never modified — this project only ever
*configures* it. The management plane is a separate control layer that
compiles database state into validated `tac_plus-ng` configuration,
applies it safely, and gives you a real GUI for devices, users, groups,
authorization policies, accounting, and diagnostics.

## Why this exists

`tac_plus-ng` is a capable, actively maintained TACACS+ daemon — but it's
configured by hand-editing a text file with its own scripting language.
This project puts a real management plane in front of it: a database as
the single source of truth, a compiler that turns that state into
`tac_plus-ng` config, a diff-before-you-apply workflow with automatic
rollback on failure, and a proper GUI so day-to-day changes (add a
device, create a user, adjust who can run `configure terminal`) don't
require touching the config file directly.

## Features

- **Network Devices** — full CRUD, encrypted shared secrets, device
  groups, config compiler with candidate/diff/apply/rollback
- **TACACS+ Users & Groups** — bcrypt-hashed passwords, native
  `tac_plus-ng` group support
- **Authorization Policies** — privilege levels, permit/deny command
  rules with deny-overrides semantics, Cisco IOS starter templates
  (Admin / Network-Manager / Auditor)
- **Accounting** — search, filter, and CSV export over a self-defined,
  reliably-parseable accounting log format
- **Diagnostics** — on-demand config validation, configuration audit
  trail, service logs, auth/authz log tails
- **Platform self-management** — two-tier RBAC, per-admin trusted-host
  IP restriction, HTTPS (self-signed by default, custom certificate
  upload supported), all configurable from the GUI
- **Single-window GUI** — persistent shell with client-side view
  transitions; every page still works as a plain server-rendered HTML
  page too, with zero JavaScript required

## Requirements

- Ubuntu Server 22.04, 24.04, or 26.04 LTS
- Root/sudo access
- Outbound internet access during installation only (to build
  `tac_plus-ng` from source and install packages) — no internet
  required at runtime

## Quick start

```bash
git clone <this-repo-url>
cd aaa-platform
sudo python3 setup.py
```

The installer detects your environment, builds `tac_plus-ng` from
upstream source, sets up PostgreSQL, installs the management app, and
walks you through creating the first administrator account. See
[`docs/INSTALL.md`](docs/INSTALL.md) for the full walkthrough.

## Architecture

```
Browser
   |
Web GUI (server-rendered, single-window shell)
   |
Management API (FastAPI)
   |
PostgreSQL  ---->  Configuration Compiler  ---->  Candidate config
(source of truth)                                       |
                                                     Validation
                                                          |
                                                    Diff + Apply
                                                          |
                                                     tac_plus-ng  (TCP/49)
                                                          |
                                                  Network Devices
```

The database is always the source of truth. The generated
`tac_plus-ng.conf` is a derived artifact — never hand-edited, always
regenerated from what's actually stored, validated before being
applied, and automatically rolled back if the daemon doesn't come back
healthy after a change.

See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) for the full design,
including the module system, privilege model, and directory layout.

## A note on how `tac_plus-ng` behavior is verified

`tac_plus-ng`'s configuration language is not fully documented in one
place. Every claim this project makes about its syntax is explicitly
tagged as one of:

- **Confirmed** — verified against a real, working configuration (the
  official upstream sample, a real deployment example, or a live test)
- **Reasoned, not verified** — a defensible extension of confirmed
  language mechanics, called out clearly rather than presented as fact

This distinction is documented throughout `docs/ARCHITECTURE.md` and in
code comments at every point it matters (e.g. `app/services/config_compiler.py`).
The project does not silently guess at protocol or config behavior.

## Project status

The core 8-phase build plan is in progress:

| Phase | Area | Status |
|---|---|---|
| 1 | Installer, GUI shell, dashboard | Done |
| 2 | Network Devices, configuration compiler | Done |
| 3 | TACACS+ Users | Done |
| 4 | Groups & Device Groups | Done |
| 5 | Authorization Policies | Done |
| 6 | Accounting | Done |
| 7 | Diagnostics | Done |
| 8 | Module Management | Not started |

Also built, beyond the original plan: platform self-management (admin
RBAC, trusted-host restriction, HTTPS), and an in-progress single-window
GUI redesign.

**Not yet implemented:** a CLI, an automated test suite, and
RADIUS/LDAP/Active Directory support (the architecture is designed to
accommodate these without a redesign, but none are built yet). See
`docs/ARCHITECTURE.md` and `docs/PAM_EXPANSION_PLAN.md` for what's
planned.

## Stack

- **Data plane:** `tac_plus-ng` (upstream C, unmodified)
- **Management plane:** FastAPI, SQLAlchemy, PostgreSQL
- **Frontend:** server-rendered Jinja2, vanilla JavaScript (no build
  step, no frontend framework)
- **OS target:** Ubuntu Server, native install — no containers, no
  Python virtual environment

## Documentation

- [`docs/INSTALL.md`](docs/INSTALL.md) — installation walkthrough,
  known verification items, upgrade notes
- [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — full system design
- [`docs/PAM_EXPANSION_PLAN.md`](docs/PAM_EXPANSION_PLAN.md) — the plan
  for evolving this into a broader AAA/privileged-access-management
  platform

## Security

- Device shared secrets are encrypted at rest (Fernet) and never
  logged
- Admin passwords are bcrypt-hashed; never stored or logged in
  plaintext
- CSRF protection on every state-changing request
- Least-privilege service account with a narrowly-scoped `sudo` grant
  (not root) for the two systemd units it's allowed to control
- Config-injection defenses: identifiers are restricted to a safe
  charset at input time rather than escaped

If you find a security issue, please open an issue (or, for anything
sensitive, reach out privately before disclosing details publicly).

## Acknowledgments

Built on top of [`tac_plus-ng`](https://github.com/MarcJHuber/event-driven-servers)
by Marc Huber and contributors — the actual TACACS+ engine doing the
protocol work underneath this platform.

## License

No license has been chosen for this project yet. Until a `LICENSE`
file is added, all rights are reserved by default — add one before
relying on this project in a context that requires a specific license.
