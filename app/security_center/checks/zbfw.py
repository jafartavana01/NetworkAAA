"""
app.security_center.checks.zbfw
===============================
Zone-Based Firewall domain. Migrated verbatim from cisco-ios-security-auditor's
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


def check_zbfw(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Zone-Based Policy Firewall"
    out: list[Finding] = []
    zones = cfg.get_blocks("zone security")
    if not zones:
        out.append(F("ZBFW-00", d, "No Zone-Based Firewall configuration detected", Status.NA, Severity.INFO))
        return out

    zone_pairs = cfg.get_blocks("zone-pair security")
    out.append(F("ZBFW-01", d, "Zone-pairs defined for the configured security zones",
                  Status.PASS if zone_pairs else Status.FAIL, Severity.HIGH,
                  recommendation="Define 'zone-pair security' for every intended traffic direction between zones.",
                  fix_command="zone-pair security IN-OUT source INSIDE destination OUTSIDE"))

    inspect_policies = [b for b in cfg.get_blocks("policy-map") if b.has(r"type inspect")]
    out.append(F("ZBFW-02", d, "Inspect policy-maps exist for zone-pairs",
                  Status.PASS if inspect_policies else Status.FAIL, Severity.HIGH,
                  recommendation="Define 'policy-map type inspect' with class-maps matching intended traffic.",
                  fix_command="class-map type inspect match-any CM-INSPECT\n match protocol tcp\n match protocol udp\n"
                              " match protocol icmp\n!\n"
                              "policy-map type inspect PM-INSPECT\n class type inspect CM-INSPECT\n  inspect\n"
                              " class class-default\n  drop"))

    applied = any(zp.has(r"service-policy type inspect") for zp in zone_pairs)
    out.append(F("ZBFW-03", d, "Inspect policy actually applied via service-policy on zone-pairs",
                  Status.PASS if applied else Status.FAIL, Severity.HIGH,
                  recommendation="Apply 'service-policy type inspect <policy>' inside each zone-pair.",
                  fix_command="zone-pair security IN-OUT source INSIDE destination OUTSIDE\n"
                              " service-policy type inspect PM-INSPECT"))

    self_zone = any("self" in zp.header.lower() for zp in zone_pairs)
    out.append(F("ZBFW-04", d, "Self-zone protection configured (device itself, not just transit traffic)",
                  Status.PASS if self_zone else Status.FAIL, Severity.MEDIUM,
                  recommendation="Configure a zone-pair with 'source self' or 'destination self' to protect the "
                                 "device's own control/management plane, not just transit traffic.",
                  fix_command="zone-pair security SELF-PROTECT source self destination OUTSIDE\n"
                              " service-policy type inspect PM-SELF-INSPECT"))
    return out


ZBFW_CHECKS = [check_zbfw]
