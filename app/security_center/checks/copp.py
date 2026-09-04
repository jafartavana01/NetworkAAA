"""
app.security_center.checks.copp
===============================
Control Plane / CoPP domain. Migrated verbatim from cisco-ios-security-auditor's
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


_COPP_CATEGORY_KEYWORDS = {
    "ICMP": [r"\bicmp\b"],
    "ROUTING": [r"\bospf\b", r"\beigrp\b", r"\bbgp\b", r"\brip\b", r"eq 179"],
    "ARP": [r"\barp\b"],
    "L2CTRL": [r"\bcdp\b", r"bpdu", r"\blldp\b", r"\bvtp\b"],
    "MGMT": [r"\bssh\b", r"\btelnet\b", r"\bsnmp\b", r"\bntp\b", r"eq 22", r"eq 23", r"eq 161", r"eq 123"],
    "DHCP": [r"\bdhcp\b", r"eq 67", r"eq 68"],
    "FHRP": [r"\bhsrp\b", r"\bvrrp\b", r"\bglbp\b", r"eq 1985"],
    "MCAST": [r"\bigmp\b", r"\bpim\b"],
}


def check_copp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Control Plane / CoPP"
    out: list[Finding] = []

    cp_blocks = cfg.get_blocks("control-plane")
    service_policy = None
    for blk in cp_blocks:
        m = blk.find(r"service-policy input (\S+)")
        if m:
            service_policy = m.group(1)
            break

    out.append(F("COPP-01", d, "CoPP service-policy applied to control-plane",
                  Status.PASS if service_policy else Status.FAIL, Severity.CRITICAL,
                  detail=f"Policy in use: {service_policy}" if service_policy else "",
                  recommendation="Apply a CoPP policy-map to the control-plane with 'service-policy input <name>'.",
                  fix_command="policy-map COPP-POLICY\n"
                              " class class-default\n"
                              "  police 8000 conform-action transmit exceed-action drop\n"
                              "!\n"
                              "control-plane\n"
                              " service-policy input COPP-POLICY\n"
                              "! This is a minimal starting policy -- see COPP-CLASS-* findings below to build "
                              "out per-protocol classes rather than relying on class-default alone."))

    if not service_policy:
        out.append(F("COPP-02", d, "Per-traffic-class CoPP coverage",
                      Status.NA, Severity.INFO,
                      detail="Skipped -- no CoPP policy is applied at all (see COPP-01)."))
        ctx.set("copp_configured", False)
        ctx.set("copp_class_coverage", 0)
        return out

    policy_blk = None
    for blk in cfg.get_blocks("policy-map"):
        if blk.name() == service_policy or blk.header.split(None, 1)[-1] == service_policy:
            policy_blk = blk
            break

    covered = set()
    if policy_blk:
        class_refs = re.findall(r"class (\S+)", policy_blk.body(), re.I)
        class_bodies = []
        acl_names_used = set()
        for cname in class_refs:
            for cm in cfg.get_blocks("class-map"):
                if cm.name().split()[-1] == cname or cname in cm.header:
                    class_bodies.append(cm.header + "\n" + cm.body())
                    acl_names_used.update(re.findall(r"access-group (?:name )?(\S+)", cm.body(), re.I))
        # Class-maps often reference an ACL by name rather than matching a protocol
        # directly (e.g. "match access-group name MGMT-ACL") -- resolve those ACLs
        # and pull their actual match criteria (ports/protocols) into the haystack too,
        # otherwise ACL-based classes are invisible to the keyword matcher below.
        acl_bodies = []
        for acl_blk in cfg.get_blocks("ip access-list", "mac access-list", "ipv6 access-list"):
            acl_name = acl_blk.name().split()[-1] if acl_blk.name() else ""
            if acl_name in acl_names_used:
                acl_bodies.append(acl_blk.body())
        haystack = policy_blk.body() + "\n" + "\n".join(class_bodies) + "\n" + "\n".join(acl_bodies)
        for category, patterns in _COPP_CATEGORY_KEYWORDS.items():
            if any(re.search(p, haystack, re.I) for p in patterns):
                covered.add(category)

    _COPP_FIX_EXAMPLES = {
        "ICMP": "class-map match-any CM-ICMP\n match protocol icmp\n!\n"
                "policy-map COPP-POLICY\n class CM-ICMP\n  police 64000 conform-action transmit exceed-action drop",
        "ROUTING": "ip access-list extended ACL-ROUTING\n permit ospf any any\n permit eigrp any any\n"
                   " permit tcp any any eq 179\n!\nclass-map match-any CM-ROUTING\n match access-group name ACL-ROUTING\n!\n"
                   "policy-map COPP-POLICY\n class CM-ROUTING\n  police 256000 conform-action transmit exceed-action drop",
        "ARP": "class-map CM-ARP\n match protocol arp\n!\n"
               "policy-map COPP-POLICY\n class CM-ARP\n  police rate 10 pps conform-action transmit exceed-action drop",
        "L2CTRL": "ip access-list extended ACL-L2CTRL\n permit udp any any eq 68\n!\n"
                  "class-map match-any CM-L2CTRL\n match access-group name ACL-L2CTRL\n!\n"
                  "policy-map COPP-POLICY\n class CM-L2CTRL\n  police 32000 conform-action transmit exceed-action drop\n"
                  "! CDP/BPDU/LLDP/VTP -- on IOS-XE these often ride the system-defined "
                  "'system-cpp-cdp'/'system-cpp-bpdu-range' classes; check 'show policy-map system-cpp'.",
        "MGMT": "ip access-list extended ACL-MGMT\n permit tcp any any eq 22\n permit udp any any eq 161\n"
                " permit udp any any eq 123\n!\nclass-map match-any CM-MGMT\n match access-group name ACL-MGMT\n!\n"
                "policy-map COPP-POLICY\n class CM-MGMT\n  police 32000 conform-action transmit exceed-action drop",
        "DHCP": "ip access-list extended ACL-DHCP\n permit udp any any eq 67\n permit udp any any eq 68\n!\n"
                "class-map match-all CM-DHCP\n match access-group name ACL-DHCP\n!\n"
                "policy-map COPP-POLICY\n class CM-DHCP\n  police 16000 conform-action transmit exceed-action drop",
        "FHRP": "ip access-list extended ACL-FHRP\n permit udp any host 224.0.0.2 eq 1985\n!\n"
                "class-map match-all CM-FHRP\n match access-group name ACL-FHRP\n!\n"
                "policy-map COPP-POLICY\n class CM-FHRP\n  police 64000 conform-action transmit exceed-action drop",
        "MCAST": "ip access-list extended ACL-MCAST\n permit pim any any\n permit igmp any any\n!\n"
                 "class-map match-any CM-MCAST\n match access-group name ACL-MCAST\n!\n"
                 "policy-map COPP-POLICY\n class CM-MCAST\n  police 64000 conform-action transmit exceed-action drop",
    }

    total_categories = len(_COPP_CATEGORY_KEYWORDS)
    for category in _COPP_CATEGORY_KEYWORDS:
        hit = category in covered
        out.append(F(f"COPP-CLASS-{category}", d, f"CoPP has a distinct traffic class for {category}",
                      Status.PASS if hit else Status.FAIL,
                      Severity.MEDIUM if category in ("ICMP", "ARP", "ROUTING", "MGMT") else Severity.LOW,
                      recommendation=f"Add a class-map/policy-map entry specifically policing {category} traffic "
                                     f"toward the control plane.",
                      fix_command=_COPP_FIX_EXAMPLES.get(category, "")))

    ctx.set("copp_configured", True)
    ctx.set("copp_class_coverage", len(covered))
    return out


def check_cpu_risk(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Control Plane / High CPU Risk Indicators"
    out: list[Finding] = []

    copp_configured = ctx.get("copp_configured", False)
    out.append(F("CPURISK-01", d, "CoPP configured (umbrella CPU-protection control)",
                  Status.PASS if copp_configured else Status.FAIL, Severity.CRITICAL,
                  recommendation="See COPP-01 -- this is the single biggest CPU-exhaustion risk factor."))

    eem_blocks = cfg.get_blocks("event manager applet")
    threshold = policy["eem_applet_count_warn_threshold"]
    out.append(F("CPURISK-02", d, f"EEM applet count within reason ({len(eem_blocks)} found, warn > {threshold})",
                  Status.FAIL if len(eem_blocks) > threshold else Status.PASS, Severity.MEDIUM,
                  evidence=[b.name() for b in eem_blocks],
                  evidence_label="EEM applets configured",
                  recommendation="Review EEM applets for necessity; a large number increases both CPU load and "
                                 "the attack surface if one is compromised/malicious.",
                  fix_command="no event manager applet <name>\n! Remove applets that are no longer needed."))

    dangerous_eem = []
    for blk in eem_blocks:
        if blk.has(r"cli command.*(reload|write erase|no aaa|erase|format)", re.I):
            dangerous_eem.append(blk.name())
    out.append(F("CPURISK-03", d, "No EEM applets with potentially destructive actions",
                  Status.FAIL if dangerous_eem else Status.PASS, Severity.HIGH, evidence=dangerous_eem,
                  evidence_label="EEM applets containing reload/erase/no-aaa/format actions",
                  recommendation="Manually review any EEM applet capable of reload/erase/config-wipe actions.",
                  fix_command="no event manager applet <name>\n"
                              "! Remove or rework the action after manual review; do not leave a destructive "
                              "trigger in place without a documented operational reason."))

    ip_accounting = cfg.search(r"^ip accounting\b")
    out.append(F("CPURISK-04", d, "Legacy 'ip accounting' not in use (deprecated, CPU-intensive)",
                  Status.FAIL if ip_accounting else Status.PASS, Severity.LOW,
                  recommendation="Remove legacy 'ip accounting' in favor of NetFlow/Flexible NetFlow.",
                  fix_command="no ip accounting\n"
                              "! Replace with Flexible NetFlow if traffic accounting is still needed:\n"
                              "flow record MY-RECORD\nflow exporter MY-EXPORTER\nflow monitor MY-MONITOR"))

    large_acl_count = 0
    large_acl_names = []
    for blk in cfg.get_blocks("ip access-list extended", "ip access-list standard"):
        if len(blk.lines) > 100:
            large_acl_count += 1
            large_acl_names.append(f"{blk.name()}  ({len(blk.lines)} entries)")
    out.append(F("CPURISK-05", d, "No unusually large ACLs (>100 entries) on this device",
                  Status.FAIL if large_acl_count else Status.PASS, Severity.LOW,
                  evidence=large_acl_names,
                  evidence_label="ACLs exceeding 100 entries",
                  recommendation="Very large ACLs increase per-packet lookup cost; consider object-groups or "
                                 "hardware TCAM limits review.",
                  fix_command="object-group network <name>\n <member-entries>\n!\n"
                              "object-group service <name>\n <member-ports>\n!\n"
                              "! Rewrite the large ACL using object-groups to reduce entry count and improve "
                              "maintainability."))

    debug_lines = cfg.search_lines(r"^debug ")
    out.append(F("CPURISK-06", d, "No 'debug' commands present in the captured config",
                  Status.FAIL if debug_lines else Status.PASS, Severity.MEDIUM, evidence=debug_lines,
                  evidence_label="Active debug commands found",
                  detail="debug is normally a runtime-only command; its presence in a config capture suggests "
                          "it may have been left running.",
                  recommendation="Disable any active debug output not needed for an active troubleshooting session.",
                  fix_command="undebug all\n! Or the specific 'no debug <feature>' for the debug(s) listed above."))
    return out


COPP_CHECKS = [check_copp, check_cpu_risk]
