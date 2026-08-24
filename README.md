# AAA Management Platform (Phase 7 + Platform Self-Management)

A modular TACACS+ AAA management platform for Ubuntu Server, built
around the upstream [tac_plus-ng](https://github.com/MarcJHuber/event-driven-servers)
daemon as the data plane, with a Python (FastAPI + PostgreSQL)
management plane on top.

**Phases 1-7 of an 8-phase build are complete.** Phase 1 delivered the
installer, tac_plus-ng build/install pipeline, Web GUI shell,
authentication, and a live system dashboard. Phase 2 added Network
Devices end-to-end and the configuration compiler. Phase 3 added
TACACS+ Users, tested end-to-end through to a real authentication
response. Phase 4 added TACACS+ Groups and Device Groups. Phase 5
added Authorization Policies. Phase 6 added Accounting. Phase 7 added
Diagnostics. Module Management (Phase 8) is the last one remaining --
see `docs/ARCHITECTURE.md` for the full plan and what's confirmed vs.
reasoned-but-unverified at each phase.

**Also built, outside the phase plan (user-requested):** the platform
can now manage itself. Admin accounts have real two-tier RBAC
(superadmin vs standard) with per-account trusted-host IP
restrictions, and HTTPS is fully supported -- self-signed by default
(generated at install time), with GUI-driven regeneration and custom
certificate upload, all under **Platform → Admin Users** /
**Platform → Settings** (superadmin-only). See `docs/ARCHITECTURE.md`'s
"Platform self-management" section for how it's built and
`docs/INSTALL.md`'s "Platform Settings" section for how to use it.

## Quick start

```
sudo python3 setup.py
```

See `docs/INSTALL.md` for the full walkthrough and `docs/ARCHITECTURE.md`
for how the pieces fit together.

## Stack

- **Data plane:** tac_plus-ng (upstream C, unmodified)
- **Management plane:** FastAPI, PostgreSQL, server-rendered Jinja2 GUI
- **OS:** Ubuntu Server 22.04 / 24.04 / 26.04, native install, no
  containers, no virtualenv

## Project layout

```
setup.py              installer entrypoint -- sudo python3 setup.py
installer/             installer implementation (imported by setup.py)
app/                   the management application (installed to /opt/aaa-platform/app)
  run.py                fixed systemd entrypoint -- reads platform_settings.py at startup
  platform_settings.py  boot-time host/port/TLS settings (JSON, not DB -- see its docstring)
docs/                  INSTALL.md, ARCHITECTURE.md
requirements.txt       Python dependencies (installed system-wide, no venv)
```

