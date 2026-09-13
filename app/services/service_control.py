"""
app.services.service_control
==============================
Wraps systemctl for the two services this platform manages (spec
section 34). Every call is an argv list through subprocess -- never a
shell string -- unit names are restricted to a fixed allow-list, and
every call runs through `sudo -n` against the exact scoped sudoers
rule installer.sudoers_setup installs. The management API itself runs
as an unprivileged account (least privilege, spec section 33); this is
the one, narrowly-scoped exception, granting control over exactly
these two units and nothing else -- not a blanket "run as root".
"""
from __future__ import annotations

import subprocess
from dataclasses import dataclass

MANAGEMENT_UNIT = "aaa-platform.service"
TAC_PLUS_NG_UNIT = "tac-plus-ng.service"
_ALLOWED_UNITS = {MANAGEMENT_UNIT, TAC_PLUS_NG_UNIT}

# Must match installer/sudoers_setup.py exactly -- these strings are
# matched literally by sudo against the installed sudoers rule.
_SUDO = ["sudo", "-n"]
_SYSTEMCTL = "/usr/bin/systemctl"
_JOURNALCTL = "/usr/bin/journalctl"
_JOURNAL_LINES = "100"


class ServiceControlError(RuntimeError):
    pass


@dataclass
class ServiceStatus:
    unit: str
    active_state: str      # active, inactive, failed, activating, ...
    sub_state: str
    enabled: bool


def _run(argv: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(argv, capture_output=True, text=True, timeout=15)


def _check_unit(unit: str) -> None:
    if unit not in _ALLOWED_UNITS:
        raise ServiceControlError(f"Refusing to operate on unrecognized unit: {unit!r}")


def get_status(unit: str) -> ServiceStatus:
    _check_unit(unit)
    active = _run(_SUDO + [_SYSTEMCTL, "is-active", unit]).stdout.strip() or "unknown"
    sub = _run(
        _SUDO + [_SYSTEMCTL, "show", unit, "--property=SubState", "--value"]
    ).stdout.strip() or "unknown"
    enabled_result = _run(_SUDO + [_SYSTEMCTL, "is-enabled", unit])
    enabled = enabled_result.stdout.strip() == "enabled"
    return ServiceStatus(unit=unit, active_state=active, sub_state=sub, enabled=enabled)


def start(unit: str) -> None:
    _check_unit(unit)
    result = _run(_SUDO + [_SYSTEMCTL, "start", unit])
    if result.returncode != 0:
        raise ServiceControlError(result.stderr.strip())


def stop(unit: str) -> None:
    _check_unit(unit)
    result = _run(_SUDO + [_SYSTEMCTL, "stop", unit])
    if result.returncode != 0:
        raise ServiceControlError(result.stderr.strip())


def restart(unit: str) -> None:
    _check_unit(unit)
    result = _run(_SUDO + [_SYSTEMCTL, "restart", unit])
    if result.returncode != 0:
        raise ServiceControlError(result.stderr.strip())


def reload(unit: str) -> None:
    """
    Only meaningful for tac_plus-ng once the config compiler can apply
    a validated candidate config via SIGHUP (ExecReload in the unit
    file). Not assumed safe for arbitrary state without that
    validation step in front of it -- spec section 34: "Do not assume
    reload is safe."
    """
    _check_unit(unit)
    result = _run(_SUDO + [_SYSTEMCTL, "reload", unit])
    if result.returncode != 0:
        raise ServiceControlError(result.stderr.strip())


def recent_logs(unit: str) -> str:
    _check_unit(unit)
    result = _run(_SUDO + [_JOURNALCTL, "-u", unit, "-n", _JOURNAL_LINES, "--no-pager"])
    return result.stdout
