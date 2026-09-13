"""
app.services.ncm_drivers
===========================
Vendor abstraction for configuration retrieval.

This is deliberately a THIN layer over
app.services.network_ops_execution.run_commands_on_device -- it does
NOT open its own SSH connection, manage its own credentials, or
re-implement prompt/paging/timeout handling. All of that already
exists and is used by Network Operations; NCM reuses it verbatim. What
a driver owns is only the vendor-specific part: which commands
retrieve which configuration, and how to clean the resulting text.

The abstraction boundary exists now so later drivers (NX-OS, Junos,
EOS, FortiOS) and later operations (apply_config, commit, rollback,
save_config, get_version) can be added without touching NCM's backup
engine, archive, diff or API. Only the Cisco IOS/IOS-XE driver is
implemented -- building empty subclasses for vendors that cannot be
tested here would be fake structure, not architecture.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from . import network_ops_execution

#: A bare device prompt on its own line (what the reader stops on).
#: Anchored to the whole line so a config line that merely CONTAINS a
#: "#" -- a comment, a banner delimiter -- is never mistaken for one.
_TRAILING_PROMPT_RE = re.compile(r"^[\w.\-@/]+(?:\([\w\-]+\))?[>#]\s*$")


@dataclass
class ConfigRetrievalResult:
    ok: bool
    content: str = ""
    connection_ok: bool = False
    retrieval_ok: bool = False
    error: str | None = None


class NetworkDeviceDriver:
    """
    Base driver. Subclasses declare their retrieval commands and any
    vendor-specific output cleanup; connection handling stays in the
    shared SSH service.
    """

    #: Commands run before retrieval to make output machine-readable
    #: (e.g. disabling pagination). Kept per-driver because the command
    #: differs by platform.
    preamble_commands: list[str] = []

    #: configuration_type -> command that retrieves it. A driver simply
    #: omits a type it does not support, which is how "not every device
    #: supports both running and startup" is represented without a flag.
    config_commands: dict[str, str] = {}

    name = "generic"

    def supports(self, configuration_type: str) -> bool:
        return configuration_type in self.config_commands

    #: Lines that are device chatter rather than configuration. Removed
    #: only when they appear BEFORE the configuration body, never from
    #: within it.
    _NOISE_PREFIXES = ("Building configuration", "Current configuration")

    def clean_output(self, raw: str, command: str) -> str:
        """
        Strips the echoed command, the device's own progress chatter,
        and the trailing prompt, leaving the configuration itself.

        Note what is NOT done here: this never truncates on encountering
        an unexpected line. If the device sends something unrecognised,
        it is kept -- losing real configuration is a far worse failure
        than carrying one odd line into the archive.
        """
        text = raw.replace("\r\n", "\n").replace("\r", "\n")
        lines = text.split("\n")

        # Drop the echoed command (device echoes what we typed).
        cmd = (command or "").strip()
        if cmd and lines and cmd in lines[0]:
            lines = lines[1:]

        # Drop leading blank/progress lines only.
        while lines and (
            not lines[0].strip()
            or lines[0].strip().startswith(self._NOISE_PREFIXES)
        ):
            lines.pop(0)

        # Drop the trailing prompt the reader stopped on, plus blanks.
        while lines and (not lines[-1].strip() or _TRAILING_PROMPT_RE.match(lines[-1])):
            lines.pop()

        return "\n".join(lines).strip()

    def get_configuration(
        self, host: str, username: str, password: str, configuration_type: str,
        *, connect_timeout_seconds: int = 15, command_timeout_seconds: int = 60,
    ) -> ConfigRetrievalResult:
        command = self.config_commands.get(configuration_type)
        if not command:
            return ConfigRetrievalResult(
                ok=False,
                error=f"{self.name} driver does not support '{configuration_type}' configuration.",
            )

        result = network_ops_execution.run_commands_on_device(
            host, username, password, [*self.preamble_commands, command],
            connect_timeout_seconds=connect_timeout_seconds,
            command_timeout_seconds=command_timeout_seconds,
        )

        # `success` on the shared service means the CONNECTION worked --
        # see its own docstring. That distinction is exactly what NCM
        # records per target as connection_ok vs retrieval_ok.
        if not result.success:
            return ConfigRetrievalResult(ok=False, connection_ok=False, error=result.message or "Connection failed.")

        if not result.command_results:
            return ConfigRetrievalResult(
                ok=False, connection_ok=True, retrieval_ok=False,
                error="Connected, but the device returned no command output.",
            )

        content = self.clean_output(result.command_results[-1].output or "", command)
        if not content.strip():
            return ConfigRetrievalResult(
                ok=False, connection_ok=True, retrieval_ok=False,
                error="Connected, but the configuration came back empty.",
            )

        return ConfigRetrievalResult(ok=True, content=content, connection_ok=True, retrieval_ok=True)


class CiscoIOSDriver(NetworkDeviceDriver):
    name = "cisco_ios"
    preamble_commands = ["terminal length 0"]
    config_commands = {
        "running": "show running-config",
        "startup": "show startup-config",
    }


#: Vendor string (lowercased, as stored on NetworkDevice.vendor) ->
#: driver. Unknown vendors fall back to the Cisco IOS driver rather
#: than failing outright: this platform's device model and existing
#: audit engine are IOS/IOS-XE oriented today, so that is the honest
#: default -- and a genuinely incompatible device fails with a real
#: error from the device itself rather than a guess made here.
_DRIVERS: dict[str, NetworkDeviceDriver] = {
    "cisco": CiscoIOSDriver(),
    "cisco_ios": CiscoIOSDriver(),
    "cisco_iosxe": CiscoIOSDriver(),
}

_DEFAULT_DRIVER = CiscoIOSDriver()


def get_driver(vendor: str | None) -> NetworkDeviceDriver:
    if not vendor:
        return _DEFAULT_DRIVER
    return _DRIVERS.get(vendor.strip().lower(), _DEFAULT_DRIVER)
