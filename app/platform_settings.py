"""
app.platform_settings
=======================
Settings the process needs to know BEFORE it can bind a socket --
host, port, and TLS configuration. Deliberately a JSON file, not a
database table: at the moment app/run.py needs these values, we don't
yet know we can reach PostgreSQL (and don't want the web server's
ability to start to depend on the database being up first). Everything
that doesn't need to exist before the socket binds -- admin accounts,
trusted-host lists, TACACS+ entities -- lives in the database as
normal.

Written once by the installer with sane defaults
(installer/tls_setup.py, installer/platform_settings_bootstrap.py),
then read-and-occasionally-rewritten by the running app itself when an
admin changes settings via the GUI. A change here requires restarting
aaa-platform.service to take effect -- true of virtually all server
software's bind address/port/TLS settings, not a shortcut taken here.
"""
from __future__ import annotations

import json

from .config import CONFIG_DIR

SETTINGS_PATH = CONFIG_DIR / "platform_settings.json"

DEFAULTS = {
    "web_host": "0.0.0.0",
    "web_port": 8420,
    "https_enabled": False,
    "tls_cert_path": "/etc/aaa-platform/tls/server.crt",
    "tls_key_path": "/etc/aaa-platform/tls/server.key",
    "tacacs_port": 49,
}


def load_settings() -> dict:
    if not SETTINGS_PATH.exists():
        return dict(DEFAULTS)
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return dict(DEFAULTS)
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in data.items() if k in DEFAULTS})
    return merged


def save_settings(settings: dict) -> None:
    """
    Writes atomically (write to a temp file, then rename) so a crash
    or concurrent read mid-write can never leave a half-written,
    unparseable settings file behind -- which would otherwise be a
    genuinely bad failure mode for a file the web server itself needs
    to read in order to start at all.
    """
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    merged = dict(DEFAULTS)
    merged.update({k: v for k, v in settings.items() if k in DEFAULTS})

    tmp_path = SETTINGS_PATH.with_suffix(".json.tmp")
    tmp_path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
    tmp_path.replace(SETTINGS_PATH)
