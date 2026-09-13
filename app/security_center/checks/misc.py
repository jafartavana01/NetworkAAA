"""
app.security_center.checks.misc
===============================
Unnecessary Services / Misc domain. Migrated verbatim from cisco-ios-security-auditor's
cisco_audit.py -- function bodies extracted programmatically (byte-
for-byte from source, not retyped) specifically to eliminate the
transcription-error risk a manual migration carries; see
app.security_center.checks.management's own module docstring for the
one such error that approach caught and fixed in this project's first
migrated domain.
"""
from __future__ import annotations

import re

from ..engine.context import Context
from ..engine.finding import F, Finding, Severity, Status
from ..parser.cisco_config import CiscoConfig


def _service_disabled(cfg: CiscoConfig, enable_pattern: str) -> bool:
    """True if the given service does NOT appear enabled (either absent, or explicitly 'no <cmd>')."""
    return not re.search(rf"^{enable_pattern}$", cfg.text, re.M | re.I)


def check_unnecessary_services(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Unnecessary Services"
    out: list[Finding] = []

    services = [
        ("SVC-01", "TCP small-servers disabled", r"service tcp-small-servers", Severity.MEDIUM, "no service tcp-small-servers"),
        ("SVC-02", "UDP small-servers disabled", r"service udp-small-servers", Severity.MEDIUM, "no service udp-small-servers"),
        ("SVC-03", "BOOTP server disabled", r"ip bootp server", Severity.LOW, "no ip bootp server"),
        ("SVC-04", "Finger service disabled", r"ip finger", Severity.LOW, "no ip finger"),
        ("SVC-05", "Identd service disabled", r"ip identd", Severity.LOW, "no ip identd"),
        ("SVC-06", "TFTP-based config load disabled", r"service config", Severity.MEDIUM, "no service config"),
        ("SVC-07", "PAD service disabled", r"service pad", Severity.LOW, "no service pad"),
    ]
    for check_id, title, pattern, sev, fix_cmd in services:
        disabled = _service_disabled(cfg, pattern)
        out.append(F(check_id, d, title, Status.PASS if disabled else Status.FAIL, sev,
                      recommendation=f"Ensure '{pattern}' is not enabled (default-off on modern IOS-XE; "
                                     f"flagged only if explicitly present without a preceding 'no').",
                      fix_command=fix_cmd))

    vstack_no = cfg.search(r"^no vstack\b")
    vstack_yes = cfg.search(r"^vstack\b") and not vstack_no
    out.append(F("SVC-08", d, "Smart Install (vstack) explicitly disabled",
                  Status.FAIL if vstack_yes else (Status.PASS if vstack_no else Status.MANUAL),
                  Severity.CRITICAL,
                  detail="" if (vstack_no or vstack_yes) else "Neither 'vstack' nor 'no vstack' found -- default "
                                                                "state is platform/version dependent.",
                  recommendation="Explicitly configure 'no vstack' -- Smart Install has a long history of "
                                 "critical, unauthenticated remote-code-execution vulnerabilities.",
                  fix_command="no vstack"))

    cdp_off = cfg.search(r"^no cdp run\b")
    out.append(F("SVC-09", d, "CDP posture reviewed",
                  Status.PASS if cdp_off else Status.MANUAL, Severity.LOW,
                  recommendation="Disable globally with 'no cdp run' if not operationally required, or at minimum "
                                 "disable per-interface on untrusted/external-facing ports.",
                  fix_command="no cdp run\n! Or, per untrusted interface only:\ninterface <interface>\n no cdp enable"))
    lldp_off = cfg.search(r"^no lldp run\b")
    out.append(F("SVC-10", d, "LLDP posture reviewed",
                  Status.PASS if lldp_off else Status.MANUAL, Severity.LOW,
                  recommendation="Disable globally with 'no lldp run' if not operationally required, or at minimum "
                                 "disable per-interface on untrusted/external-facing ports.",
                  fix_command="no lldp run\n! Or, per untrusted interface only:\ninterface <interface>\n no lldp transmit\n no lldp receive"))
    return out


def check_misc(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Miscellaneous / Often-Missed"
    out: list[Finding] = []

    errdisable = cfg.search_lines(r"^errdisable recovery cause\b")
    out.append(F("MISC-01", d, "Errdisable recovery configured for at least one cause",
                  Status.PASS if errdisable else Status.FAIL, Severity.LOW, evidence=errdisable,
                  evidence_label="Current errdisable recovery causes",
                  recommendation="Configure 'errdisable recovery cause <cause>' + 'errdisable recovery interval "
                                 "<seconds>' so ports don't stay down indefinitely requiring manual intervention.",
                  fix_command="errdisable recovery cause bpduguard\nerrdisable recovery cause psecure-violation\n"
                              "errdisable recovery interval 300"))

    mcast_routing = cfg.search(r"^ip multicast-routing\b")
    if mcast_routing:
        out.append(F("MISC-02", d, "Multicast routing is enabled -- verify PIM/IGMP CoPP policing",
                      Status.MANUAL, Severity.LOW,
                      recommendation="Cross-check the Control Plane / CoPP domain's MCAST class coverage."))
    else:
        out.append(F("MISC-02", d, "Multicast routing not enabled", Status.PASS, Severity.INFO))

    tcl_restricted = cfg.search(r"no scripting tcl")
    out.append(F("MISC-03", d, "Tcl shell availability reviewed",
                  Status.MANUAL if not tcl_restricted else Status.PASS, Severity.LOW,
                  recommendation="Restrict/disable the Tcl shell if not operationally required."))

    dhcp_relay = cfg.search_lines(r"ip helper-address \S+")
    out.append(F("MISC-04", d, f"DHCP relay helper-address(es) present ({len(dhcp_relay)}) -- verify trust",
                  Status.MANUAL if dhcp_relay else Status.NA, Severity.LOW, evidence=dhcp_relay[:10],
                  recommendation="Confirm every 'ip helper-address' points only at a trusted, authorized DHCP server."))

    mgmt_vrf = cfg.search(r"^vrf definition (Mgmt-intf|Management|MGMT)\b") or cfg.search(r"^ip vrf (Mgmt-intf|Management|MGMT)\b")
    out.append(F("MISC-05", d, "Management-plane VRF isolation in use",
                  Status.PASS if mgmt_vrf else Status.FAIL, Severity.LOW,
                  recommendation="Consider isolating management traffic in a dedicated VRF (Mgmt-intf or similar).",
                  fix_command="vrf definition Mgmt-intf\n address-family ipv4\n!\n"
                              "interface <mgmt-interface>\n vrf forwarding Mgmt-intf\n ip address <ip> <mask>"))

    autosecure = cfg.search(r"auto secure")
    out.append(F("MISC-06", d, "AutoSecure baseline reviewed",
                  Status.MANUAL, Severity.INFO,
                  detail="AutoSecure is an interactive exec wizard and generally not reflected as a discrete "
                          "line in running-config.",
                  recommendation="Not independently verifiable from running-config; informational only."))

    dot1x_rule_note = F("MISC-07", d, "802.1X + MAB correlation rule",
                         Status.NA, Severity.INFO,
                         detail="802.1X/MAB domain checks are on the roadmap for a future version; the "
                                 "corresponding correlation rule from the checklist is intentionally not yet "
                                 "implemented rather than faked.")
    out.append(dot1x_rule_note)
    return out


def check_ios_version(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "IOS-XE Version"
    out: list[Finding] = []
    version = cfg.get_version()
    out.append(F("VER-01", d, f"Running version extracted: {version}",
                  Status.PASS if version != "unknown" else Status.MANUAL, Severity.INFO,
                  recommendation="Cross-reference this version against Cisco PSIRT openVuln / the Security "
                                 "Advisories page for known CVEs -- this tool does not call out to the internet, "
                                 "so that lookup is a manual (or future-scripted) step."))
    hostname = cfg.get_hostname()
    out.append(F("VER-02", d, f"Hostname: {hostname}", Status.PASS, Severity.INFO))
    return out


MISC_CHECKS = [check_unnecessary_services, check_misc, check_ios_version]
