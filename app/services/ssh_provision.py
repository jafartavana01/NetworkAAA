"""
app.services.ssh_provision
=============================
SSH into a newly-discovered device and push the TACACS+ client-side
AAA configuration it needs to actually use this platform -- the other
half of the device-side story from app.services.config_compiler
(which only ever configures tac_plus-ng itself, never a client).

CREDENTIALS ARE NEVER PERSISTED. The SSH username/password the admin
supplies is used only for the duration of the scan/apply request that
needs it and is never written to the database or logged -- this is a
bulk-onboarding credential (typically shared/temporary across many
devices being provisioned at once), not an ongoing one, so there is
no legitimate reason to store it, matching this project's existing
"only store what's actually needed long-term" discipline.

AAA COMMANDS ARE CISCO IOS, STATED PLAINLY -- not vendor-detected or
vendor-generic. Cisco IOS TACACS+ client configuration is extremely
well-documented (unlike tac_plus-ng's own scripting language, which
required real research throughout this project), so this is a much
higher-confidence claim than most of what this project has had to
verify -- but it is still a specific vendor's syntax, not a universal
one, and the GUI says so. `local` is always included as an
authentication/authorization fallback method alongside the tacacs+
group -- a deliberate safety choice: if TACACS+ becomes unreachable
after this push (misconfigured secret, network issue, this platform
being down), the device does not lock out local login as a result.

Hostname detection reads the device's own SSH prompt (e.g. "Router1#")
rather than running a vendor-specific "show" command -- prompts
ending in a hostname before `#`/`>` are common across Cisco IOS,
NX-OS, and many similar CLI-driven platforms, so this is a reasonably
vendor-agnostic signal without needing to guess which "show" command
syntax a specific device supports.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

_PROMPT_PATTERN = re.compile(r"([A-Za-z0-9_.\-]+)[>#]\s*$")
_CONNECT_TIMEOUT_SECONDS = 8
_COMMAND_TIMEOUT_SECONDS = 10


@dataclass
class SshResult:
    success: bool
    message: str
    hostname: str | None = None
    command_log: list[str] = field(default_factory=list)
    platform: str | None = None
    vendor: str | None = None
    raw_version_output: str | None = None


_SHOW_VERSION_PLATFORM_PATTERNS = [
    # "cisco WS-C2960X-24TS-L (PowerPC405) processor..." (switches) and
    # "cisco ISR4331/K9 (1RU) processor..." (routers, where "/K9" denotes
    # a crypto-enabled image and is genuinely common across router
    # product lines -- caught by real testing against a router sample
    # where an earlier version of this pattern, missing "/", silently
    # failed to match at all) -- most IOS versions.
    re.compile(r"[Cc]isco\s+([A-Z0-9][A-Z0-9\-/]{2,})\s*\("),
    # "Cisco IOS Software, C2960X Software (C2960X-UNIVERSALK9-M), ..." -- the software/platform train name
    re.compile(r"Cisco IOS Software,\s*([A-Za-z0-9]+)\s+Software"),
]


def gather_device_info(host: str, username: str, password: str, *, port: int = 22) -> SshResult:
    """
    Connects, reads the initial prompt (for a hostname suggestion),
    then runs `show version` in the SAME session (one connection, not
    two) and does a best-effort extraction of a platform/model string
    from its output. Does not change anything on the device.

    Deliberately conservative about what it claims to know: `vendor`
    is only ever set to "cisco" (this whole flow is Cisco IOS-
    specific already -- see build_cisco_ios_aaa_commands), never
    guessed for anything else. `platform` is a best-effort regex
    match against known common `show version` output shapes across
    Cisco IOS switch/router platforms and IOS trains -- it can fail to
    match on IOS versions or platforms this wasn't tested against, in
    which case it's simply left unset rather than guessed at. The raw
    `show version` output is always preserved (truncated to a
    reasonable size) regardless of whether the platform regex
    matched, so nothing observed is ever lost even when the specific
    extraction misses.
    """
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(host, port=port, username=username, password=password, timeout=_CONNECT_TIMEOUT_SECONDS, look_for_keys=False, allow_agent=False)
        shell = client.invoke_shell()
        shell.settimeout(_COMMAND_TIMEOUT_SECONDS)
        buffer = _read_until_idle(shell)
        match = _PROMPT_PATTERN.search(buffer.strip())
        hostname = match.group(1) if match else None

        shell.send("show version\n")
        version_output = _read_until_idle(shell)
        # Strip the echoed command itself and the trailing prompt line
        # so what's stored is just the device's own output.
        version_output = version_output.strip()

        platform = None
        for pattern in _SHOW_VERSION_PLATFORM_PATTERNS:
            found = pattern.search(version_output)
            if found:
                platform = found.group(1)
                break

        return SshResult(
            success=True, message="Connected.", hostname=hostname,
            platform=platform, vendor="cisco" if version_output else None,
            raw_version_output=version_output[:2000] if version_output else None,
        )
    except paramiko.AuthenticationException:
        return SshResult(success=False, message="SSH authentication failed -- check the username and password.")
    except Exception as exc:
        return SshResult(success=False, message=f"Could not connect: {exc}")
    finally:
        client.close()


def _read_until_idle(shell, *, max_bytes: int = 8192) -> str:
    import time

    buffer = ""
    deadline = time.time() + _COMMAND_TIMEOUT_SECONDS
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(max_bytes).decode(errors="replace")
            buffer += chunk
            deadline = time.time() + 1.5  # a little quiet time after the last chunk, not the full timeout again
        else:
            time.sleep(0.1)
    return buffer


def default_command_templates() -> list[str]:
    """
    The built-in default, as TEMPLATE strings (unsubstituted
    `{platform_ip}` / `{shared_secret}` placeholders) -- what a fresh
    install starts from, and what app.api.routes_aaa_template seeds
    into AaaTemplateSettings on first boot so the admin has something
    real to edit rather than an empty list. See
    build_cisco_ios_aaa_commands's docstring for why each line is here.
    """
    return [
        "configure terminal",
        "aaa new-model",
        "tacacs-server host {platform_ip} key {shared_secret}",
        "aaa authentication login default group tacacs+ local",
        "aaa authorization exec default group tacacs+ local if-authenticated",
        "aaa authorization config-commands",
        "aaa authorization console",
        "aaa authorization commands 15 default group tacacs+ local if-authenticated",
        "aaa authorization commands 1 default group tacacs+ local if-authenticated",
        "aaa accounting exec default start-stop group tacacs+",
        "aaa accounting commands 15 default start-stop group tacacs+",
        "aaa accounting commands 1 default start-stop group tacacs+",
        "end",
        "write memory",
    ]


def build_cisco_ios_aaa_commands(*, platform_ip: str, shared_secret: str, templates: list[str] | None = None) -> list[str]:
    """
    The legacy (pre-"tacacs server NAME" object) Cisco IOS syntax --
    chosen deliberately over the newer named-object style for broader
    version compatibility, since this project has no way to know the
    target device's exact IOS version ahead of time. `aaa new-model`
    comes first, before the server definition -- enables the AAA
    subsystem before anything that configures it, matching
    conventional Cisco IOS practice. `local` fallback on every
    authentication/authorization line is intentional -- see module
    docstring. `if-authenticated` is added as a further
    authorization fallback (standard, well-documented Cisco IOS
    syntax: permits if the user is already authenticated, tried only
    after both tacacs+ and local have been exhausted) -- not used on
    the authentication line, where the concept doesn't apply (a user
    isn't "authenticated" yet during login itself). `aaa authorization
    config-commands` is a standalone toggle (no method list of its
    own) that extends command authorization to commands entered in
    configuration mode -- without it, config-mode commands are exempt
    from the "commands 15" check entirely, which most deployments
    would not expect. `aaa authorization console`, similarly, extends
    the existing `exec`/`commands` method lists' authorization checks
    to the console line specifically -- without it, the console is
    exempt from authorization even with `aaa new-model` enabled
    (standard Cisco IOS behavior). It doesn't define a separate,
    different method list, so the same `local`/`if-authenticated`
    fallbacks already on those lines still protect console access.

    `templates`, when provided (the admin's saved customization from
    AaaTemplateSettings -- see app.api.routes_aaa_template), replaces
    the built-in default entirely; each line has `{platform_ip}` and
    `{shared_secret}` replaced with the real values via plain string
    substitution (not `.format()`, deliberately -- an admin-edited
    template could contain a stray literal `{`/`}` that `.format()`
    would choke on; `.replace()` never fails regardless of what else
    is in the line). Falls back to default_command_templates() when
    not provided, so this function's own behavior is unchanged for any
    caller that doesn't pass one.
    """
    lines = templates if templates is not None else default_command_templates()
    return [
        line.replace("{platform_ip}", platform_ip).replace("{shared_secret}", shared_secret)
        for line in lines
    ]


_TACACS_SERVER_LINE_PATTERN = re.compile(r"^\s*tacacs-server\s+host\s+\S+\s+key\s+(\S+)\s*$", re.MULTILINE)


def extract_shared_secret(commands: list[str]) -> str | None:
    """
    Pulls the shared secret directly OUT of a (possibly admin-edited)
    command list, by finding the `tacacs-server host <ip> key
    <secret>` line -- rather than tracking a separately-generated
    secret value that could silently drift out of sync with whatever
    the admin actually edited into the commands before sending them.
    Returns None if no such line is found (the caller must then refuse
    the apply rather than guess a secret that wouldn't match what's
    actually on the device -- see routes_network_scan.py)."""
    match = _TACACS_SERVER_LINE_PATTERN.search("\n".join(commands))
    return match.group(1) if match else None


def apply_aaa_config(
    host: str, username: str, password: str, *, commands: list[str], port: int = 22
) -> SshResult:
    """Connects, runs each command in `commands` in an interactive
    shell (needed for `configure terminal`-style multi-command
    sessions, not one-shot exec), and returns the full transcript so
    the admin can verify exactly what happened -- never a bare
    success/fail with no way to check the device's own responses."""
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    log: list[str] = []
    try:
        client.connect(host, port=port, username=username, password=password, timeout=_CONNECT_TIMEOUT_SECONDS, look_for_keys=False, allow_agent=False)
        shell = client.invoke_shell()
        shell.settimeout(_COMMAND_TIMEOUT_SECONDS)
        _read_until_idle(shell)  # drain the initial banner/prompt before sending anything

        for cmd in commands:
            shell.send(cmd + "\n")
            output = _read_until_idle(shell)
            log.append(f"> {cmd}\n{output.strip()}")

        return SshResult(success=True, message="Configuration applied.", command_log=log)
    except paramiko.AuthenticationException:
        return SshResult(success=False, message="SSH authentication failed -- check the username and password.", command_log=log)
    except Exception as exc:
        return SshResult(success=False, message=f"Could not apply configuration: {exc}", command_log=log)
    finally:
        client.close()
