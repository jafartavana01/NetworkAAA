"""
installer.sudoers_setup
=========================
The management API runs as the unprivileged `aaa-platform` account
(spec section 33: least privilege), but section 34 requires it to
start/stop/restart/reload tac_plus-ng and read its journal. Plain
systemctl/journalctl calls from a non-root user are denied by default
policy on Ubuntu -- so rather than running the API as root (which
would defeat the least-privilege requirement), this grants a single
sudoers rule scoped to the exact commands, exact arguments, and exact
two unit names the application ever calls. Nothing wildcard, nothing
"ALL".

The file is validated with `visudo -c` against a temp copy before it's
ever installed to /etc/sudoers.d -- a syntactically broken sudoers
drop-in can break sudo system-wide, so this is not optional.
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from . import utils
from .app_install import SERVICE_USER
from .systemd_setup import MANAGEMENT_UNIT_NAME, TAC_PLUS_NG_UNIT_NAME

SUDOERS_PATH = Path("/etc/sudoers.d/aaa-platform")

# Must match app.services.service_control's SYSTEMCTL_BIN / JOURNALCTL_BIN
# and JOURNAL_LINES constants exactly -- these are string-matched by sudo,
# not interpreted.
SYSTEMCTL_BIN = "/usr/bin/systemctl"
JOURNALCTL_BIN = "/usr/bin/journalctl"
JOURNAL_LINES = "100"

_UNITS = (MANAGEMENT_UNIT_NAME, TAC_PLUS_NG_UNIT_NAME)


def _sudoers_content() -> str:
    lines = [
        "# Managed by the AAA Management Platform installer. Do not hand-edit --",
        "# regenerated on every install/reinstall.",
        "#",
        "# Grants the unprivileged service account permission to control ONLY",
        "# its own two systemd units, via exact, non-wildcard command matches.",
        "",
    ]
    commands = []
    for unit in _UNITS:
        for verb in ("start", "stop", "restart", "reload", "is-active", "is-enabled"):
            commands.append(f"{SYSTEMCTL_BIN} {verb} {unit}")
        commands.append(f"{SYSTEMCTL_BIN} show {unit} --property=SubState --value")
        commands.append(f"{JOURNALCTL_BIN} -u {unit} -n {JOURNAL_LINES} --no-pager")

    cmd_list = ", ".join(commands)
    lines.append(f"{SERVICE_USER} ALL=(root) NOPASSWD: {cmd_list}")
    lines.append("")
    return "\n".join(lines)


def install_sudoers_rule() -> None:
    content = _sudoers_content()

    with tempfile.NamedTemporaryFile("w", suffix=".sudoers", delete=False) as tmp:
        tmp.write(content)
        tmp_path = tmp.name

    try:
        result = utils.run(["visudo", "-c", "-f", tmp_path], check=False)
        if not result.ok:
            raise utils.InstallError(
                f"Generated sudoers file failed validation, refusing to install it:\n{result.stdout}{result.stderr}"
            )

        SUDOERS_PATH.parent.mkdir(parents=True, exist_ok=True)
        SUDOERS_PATH.write_text(content, encoding="utf-8")
        SUDOERS_PATH.chmod(0o440)  # sudoers.d files must not be group/world-writable
        utils.ok(f"Installed scoped sudoers rule at {SUDOERS_PATH} (validated with visudo -c).")
    finally:
        Path(tmp_path).unlink(missing_ok=True)
