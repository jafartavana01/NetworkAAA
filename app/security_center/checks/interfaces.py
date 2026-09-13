"""
app.security_center.checks.interfaces
========================================
The 33-rule interface security engine, migrated from cisco-interface-
security-audit's app/security/engine.py via a direct, byte-for-byte
file copy (confirmed with `diff` against the original at migration
time) -- not retyped, so every rule definition, weight, CLI template,
and narrative field (why/risk/attack/best/performance/operational/
compatibility/references) is exactly what the original project
produces, with zero transcription risk.

Everything below this docstring, up to `to_unified_findings()` near
the end, is that unchanged original file -- its own module docstring
above described only the engine, not this file's place in the larger
migration; this replaces that one paragraph without touching a single
line of actual logic.

`to_unified_findings()` is new: a thin adapter bridging this engine's
own internal assessment-result shape (a dict, from `assess_features()`)
to app.security_center.engine.finding.Finding -- the model this file's
own scoring/rule logic knows nothing about and was never changed to
accommodate. See that function's own docstring for the field mapping.
"""

import re
from copy import deepcopy

from ..engine.finding import Finding, Severity, Status

FEATURE_GROUPS = [
    "Identity",
    "L2 Hardening",
    "Spanning Tree",
    "Port Security",
    "First Hop Security",
    "AAA",
    "Management Plane",
    "IPv6",
    "QoS",
    "Telemetry",
]


def F(key, label, type_, group, options=None):
    item = {"key": key, "label": label, "type": type_, "group": group}
    if options:
        item["options"] = options
    return item


FEATURE_DEFINITIONS = [
    F("description", "Description", "text", "Identity"),
    F("shutdown", "Administratively down", "toggle", "Identity"),
    F("mode", "Switchport mode", "select", "Identity", ["access", "trunk", "routed", "unknown"]),
    F("access_vlan", "Access VLAN", "text", "Identity"),
    F("native_vlan", "Trunk native VLAN", "text", "L2 Hardening"),
    F("allowed_vlans", "Trunk allowed VLANs", "text", "L2 Hardening"),
    F("nonegotiate", "Disable DTP negotiation", "toggle", "L2 Hardening"),
    F("portfast", "PortFast", "toggle", "Spanning Tree"),
    F("bpduguard", "BPDU Guard", "toggle", "Spanning Tree"),
    F("bpdufilter", "BPDU Filter", "toggle", "Spanning Tree"),
    F("rootguard", "Root Guard", "toggle", "Spanning Tree"),
    F("loopguard", "Loop Guard", "toggle", "Spanning Tree"),
    F("udld", "UDLD", "toggle", "L2 Hardening"),
    F("udld_aggressive", "UDLD aggressive", "toggle", "L2 Hardening"),
    F("storm_broadcast", "Broadcast storm control", "toggle", "L2 Hardening"),
    F("storm_multicast", "Multicast storm control", "toggle", "L2 Hardening"),
    F("storm_unicast", "Unknown unicast storm control", "toggle", "L2 Hardening"),
    F("storm_level", "Storm control level", "text", "L2 Hardening"),
    F("port_security", "Port security", "toggle", "Port Security"),
    F("ps_max", "Maximum MAC addresses", "text", "Port Security"),
    F("ps_violation", "Violation mode", "select", "Port Security", ["shutdown", "restrict", "protect"]),
    F("ps_sticky", "Sticky MAC", "toggle", "Port Security"),
    F("dhcp_snoop_trust", "DHCP snooping trust", "toggle", "First Hop Security"),
    F("dhcp_rate_limit", "DHCP rate limit", "text", "First Hop Security"),
    F("dai_trust", "Dynamic ARP inspection trust", "toggle", "First Hop Security"),
    F("arp_rate_limit", "ARP rate limit", "text", "First Hop Security"),
    F("ipsg", "IP Source Guard", "toggle", "First Hop Security"),
    F("acl_in", "Ingress IPv4 ACL", "text", "Management Plane"),
    F("acl_out", "Egress IPv4 ACL", "text", "Management Plane"),
    F("ipv6_acl_in", "Ingress IPv6 ACL", "text", "IPv6"),
    F("ipv6_acl_out", "Egress IPv6 ACL", "text", "IPv6"),
    F("auth_port_control", "802.1X port control", "toggle", "AAA"),
    F("mab", "MAC Authentication Bypass", "toggle", "AAA"),
    F("auth_order", "Authentication order", "text", "AAA"),
    F("auth_priority", "Authentication priority", "text", "AAA"),
    F("host_mode", "Host mode", "text", "AAA"),
    F("guest_vlan", "Guest VLAN", "text", "AAA"),
    F("critical_vlan", "Critical VLAN", "text", "AAA"),
    F("reauth", "Reauthentication", "toggle", "AAA"),
    F("auth_timers", "Authentication timers", "toggle", "AAA"),
    F("cdp", "CDP enabled", "toggle", "Management Plane"),
    F("lldp", "LLDP enabled", "toggle", "Management Plane"),
    F("voice_vlan", "Voice VLAN", "text", "Identity"),
    F("protected_port", "Protected port", "toggle", "L2 Hardening"),
    F("private_vlan", "Private VLAN", "toggle", "L2 Hardening"),
    F("ipv6_ra_guard", "IPv6 RA Guard", "toggle", "IPv6"),
    F("ipv6_snooping", "IPv6 snooping", "toggle", "IPv6"),
    F("qos_input", "QoS input policy", "text", "QoS"),
    F("qos_output", "QoS output policy", "text", "QoS"),
    F("span_destination", "SPAN destination", "toggle", "Telemetry"),
    F("poe", "PoE enabled", "toggle", "Identity"),
    F("eee", "Energy Efficient Ethernet", "toggle", "Identity"),
    F("device_tracking", "Device tracking", "toggle", "First Hop Security"),
    F("sisf", "SISF", "toggle", "First Hop Security"),
]

RULES = []
CHECKS = {}

DEFAULT_WHY = "This control reduces attack surface and improves deterministic policy enforcement."
DEFAULT_RISK = "Without this control, attackers can exploit L2 weaknesses, inject traffic, or bypass network access controls."
DEFAULT_ATTACK = "VLAN hopping, DHCP starvation, ARP spoofing, STP manipulation, MAC flooding, unauthorized device connection."
DEFAULT_BEST = "Apply the recommended Cisco CLI and validate in a maintenance window."
DEFAULT_PERF = "Minimal impact when implemented with hardware offload."
DEFAULT_OPS = "Monitor errdisable and authentication logs after deployment."
DEFAULT_COMPAT = "Supported on Cisco IOS/IOS-XE Catalyst switching platforms; verify platform-specific commands."
DEFAULT_REFS = [
    "Cisco IOS Security Configuration Guide (local)",
    "Cisco Catalyst Security Best Practices (local)",
    "NIST SP 800-115 (local)",
]


def add_rule(rid, title, severity, weight, category, cli, check, why=None, risk=None, attack=None,
             best=None, perf=None, ops=None, compat=None, refs=None):
    RULES.append({
        "id": rid,
        "title": title,
        "severity": severity,
        "weight": weight,
        "category": category,
        "recommended_cli": cli,
        "why": why or DEFAULT_WHY,
        "risk": risk or DEFAULT_RISK,
        "attack": attack or DEFAULT_ATTACK,
        "best": best or DEFAULT_BEST,
        "performance": perf or DEFAULT_PERF,
        "operational": ops or DEFAULT_OPS,
        "compatibility": compat or DEFAULT_COMPAT,
        "references": refs or DEFAULT_REFS,
    })
    CHECKS[rid] = check


def passed(msg="Enabled"):
    return ("pass", msg)


def failed(msg="Missing or unsafe"):
    return ("fail", msg)


def warned(msg="Partial implementation"):
    return ("warn", msg)


def skipped():
    return ("skip", "Not applicable")


add_rule(
    "interface_description", "Interface description", "low", 3, "Documentation", "description <text>",
    lambda f, g: passed("Description present") if f.get("description_present") or f.get("description") else warned("No interface description"),
)
add_rule(
    "explicit_mode", "Explicit interface mode", "medium", 5, "L2 Hardening", "switchport mode access | trunk",
    lambda f, g: passed("Mode is explicit") if f.get("mode") in ("access", "trunk", "routed") else failed("Mode is unknown"),
)
add_rule(
    "access_vlan_not_default", "Non-default access VLAN", "high", 7, "L2 Hardening", "switchport access vlan <vlan>",
    lambda f, g: skipped() if f.get("mode") != "access" else (
        passed("Access VLAN is not default") if f.get("access_vlan") not in ("", "1") else failed("Access VLAN missing or default VLAN 1")
    ),
)
add_rule(
    "trunk_native_vlan", "Non-default trunk native VLAN", "critical", 9, "L2 Hardening", "switchport trunk native vlan <vlan>",
    lambda f, g: skipped() if f.get("mode") != "trunk" else (
        passed("Native VLAN is hardened") if f.get("native_vlan") not in ("", "1") else failed("Native VLAN missing or default VLAN 1")
    ),
)
add_rule(
    "trunk_allowed_vlans", "Explicit trunk allowed VLANs", "critical", 9, "L2 Hardening", "switchport trunk allowed vlan <list>",
    lambda f, g: skipped() if f.get("mode") != "trunk" else (
        passed("Allowed VLANs are explicit") if f.get("allowed_vlans") and f.get("allowed_vlans").lower() != "all"
        else failed("Allowed VLANs missing or set to all")
    ),
)
add_rule(
    "dtp_disabled", "DTP disabled on trunk", "high", 6, "L2 Hardening", "switchport nonegotiate",
    lambda f, g: skipped() if f.get("mode") != "trunk" else (
        passed("DTP negotiation disabled") if f.get("nonegotiate") else failed("DTP negotiation enabled")
    ),
)
add_rule(
    "portfast", "PortFast on access port", "medium", 5, "Spanning Tree", "spanning-tree portfast",
    lambda f, g: skipped() if f.get("mode") != "access" else (
        passed("PortFast enabled") if f.get("portfast") else failed("PortFast missing")
    ),
)
add_rule(
    "bpduguard", "BPDU Guard on access port", "critical", 9, "Spanning Tree", "spanning-tree bpduguard enable",
    lambda f, g: skipped() if f.get("mode") != "access" else (
        passed("BPDU Guard enabled") if f.get("bpduguard") else failed("BPDU Guard missing")
    ),
)
add_rule(
    "rootguard", "Root Guard on trunk", "high", 6, "Spanning Tree", "spanning-tree guard root",
    lambda f, g: skipped() if f.get("mode") != "trunk" else (
        passed("Root Guard enabled") if f.get("rootguard") else failed("Root Guard missing")
    ),
)
add_rule(
    "loopguard", "Loop Guard on trunk", "medium", 4, "Spanning Tree", "spanning-tree guard loop",
    lambda f, g: skipped() if f.get("mode") != "trunk" else (
        passed("Loop Guard enabled") if f.get("loopguard") else warned("Loop Guard missing")
    ),
)
add_rule(
    "udld", "UDLD", "medium", 4, "L2 Hardening", "udld port",
    lambda f, g: skipped() if f.get("mode") != "trunk" else (
        passed("UDLD enabled") if f.get("udld") else warned("UDLD missing")
    ),
)
add_rule(
    "storm_control", "Storm control", "high", 7, "L2 Hardening", "storm-control broadcast level <value>",
    lambda f, g: skipped() if f.get("mode") not in ("access", "trunk") else (
        passed("Storm control enabled") if f.get("storm_broadcast") or f.get("storm_multicast") or f.get("storm_unicast")
        else failed("Storm control missing")
    ),
)
add_rule(
    "port_security", "Port security", "critical", 10, "Port Security", "switchport port-security",
    lambda f, g: skipped() if f.get("mode") != "access" else (
        passed("Port security enabled") if f.get("port_security") else failed("Port security missing")
    ),
)
add_rule(
    "port_security_max", "Port security maximum MACs", "high", 6, "Port Security", "switchport port-security maximum <n>",
    lambda f, g: skipped() if not f.get("port_security") else (
        passed("Maximum MACs constrained") if f.get("ps_max") else failed("Maximum MACs not configured")
    ),
)
add_rule(
    "port_security_violation", "Port security violation mode", "high", 6, "Port Security", "switchport port-security violation restrict|shutdown",
    lambda f, g: skipped() if not f.get("port_security") else (
        passed("Violation mode enforced") if f.get("ps_violation") in ("shutdown", "restrict") else warned("Violation mode weak or missing")
    ),
)
add_rule(
    "port_security_sticky", "Sticky MAC learning", "medium", 4, "Port Security", "switchport port-security mac-address sticky",
    lambda f, g: skipped() if not f.get("port_security") else (
        passed("Sticky MAC enabled") if f.get("ps_sticky") else warned("Sticky MAC missing")
    ),
)
add_rule(
    "dhcp_snooping_access", "DHCP snooping untrusted access", "critical", 8, "First Hop Security", "no ip dhcp snooping trust",
    lambda f, g: skipped() if f.get("mode") != "access" else (
        failed("Global DHCP snooping disabled") if not g.get("dhcp_snooping") else (
            passed("Access port is untrusted") if not f.get("dhcp_snoop_trust") else warned("Access port should not be trusted")
        )
    ),
)
add_rule(
    "dhcp_snooping_trunk", "DHCP snooping trusted trunk", "critical", 8, "First Hop Security", "ip dhcp snooping trust",
    lambda f, g: skipped() if f.get("mode") != "trunk" else (
        failed("Global DHCP snooping disabled") if not g.get("dhcp_snooping") else (
            passed("Trunk is trusted") if f.get("dhcp_snoop_trust") else failed("Trunk should be trusted for DHCP snooping")
        )
    ),
)
add_rule(
    "dai_access", "DAI untrusted access", "critical", 8, "First Hop Security", "no ip arp inspection trust",
    lambda f, g: skipped() if f.get("mode") != "access" else (
        failed("Global ARP inspection disabled") if not g.get("arp_inspection") else (
            passed("Access port is untrusted") if not f.get("dai_trust") else warned("Access port should not be DAI trusted")
        )
    ),
)
add_rule(
    "dai_trunk", "DAI trusted trunk", "critical", 8, "First Hop Security", "ip arp inspection trust",
    lambda f, g: skipped() if f.get("mode") != "trunk" else (
        failed("Global ARP inspection disabled") if not g.get("arp_inspection") else (
            passed("Trunk is DAI trusted") if f.get("dai_trust") else failed("Trunk should be DAI trusted")
        )
    ),
)
add_rule(
    "ip_source_guard", "IP Source Guard", "high", 7, "First Hop Security", "ip verify source",
    lambda f, g: skipped() if f.get("mode") != "access" else (
        passed("IP Source Guard enabled") if f.get("ipsg") else failed("IP Source Guard missing")
    ),
)
add_rule(
    "dot1x", "802.1X port control", "high", 8, "AAA", "authentication port-control auto",
    lambda f, g: skipped() if f.get("mode") not in ("access", "trunk") else (
        passed("802.1X enabled") if f.get("auth_port_control") else warned("802.1X not enabled")
    ),
)
add_rule(
    "mab", "MAC Authentication Bypass", "medium", 5, "AAA", "mab",
    lambda f, g: skipped() if not f.get("auth_port_control") else (
        passed("MAB fallback configured") if f.get("mab") else warned("MAB fallback missing")
    ),
)
add_rule(
    "auth_order", "Authentication order", "medium", 4, "AAA", "authentication order dot1x mab",
    lambda f, g: skipped() if not f.get("auth_port_control") else (
        passed("Authentication order configured") if f.get("auth_order") else warned("Authentication order missing")
    ),
)
add_rule(
    "guest_vlan", "Guest VLAN", "low", 2, "AAA", "authentication guest vlan <vlan>",
    lambda f, g: skipped() if not f.get("auth_port_control") else (
        passed("Guest VLAN configured") if f.get("guest_vlan") else warned("Guest VLAN missing")
    ),
)
add_rule(
    "critical_vlan", "Critical VLAN", "low", 2, "AAA", "authentication critical vlan <vlan>",
    lambda f, g: skipped() if not f.get("auth_port_control") else (
        passed("Critical VLAN configured") if f.get("critical_vlan") else warned("Critical VLAN missing")
    ),
)
add_rule(
    "reauthentication", "Reauthentication", "medium", 3, "AAA", "authentication periodic",
    lambda f, g: skipped() if not f.get("auth_port_control") else (
        passed("Reauthentication enabled") if f.get("reauth") else warned("Reauthentication missing")
    ),
)
add_rule(
    "cdp_control", "CDP control", "low", 2, "Management Plane", "no cdp enable",
    lambda f, g: passed("CDP disabled") if f.get("cdp") is False else warned("CDP remains enabled"),
)
add_rule(
    "lldp_control", "LLDP control", "low", 2, "Management Plane", "no lldp transmit / receive",
    lambda f, g: passed("LLDP controlled") if f.get("lldp") is False else warned("LLDP remains enabled"),
)
add_rule(
    "ipv6_ra_guard", "IPv6 RA Guard", "medium", 4, "IPv6", "ipv6 nd raguard",
    lambda f, g: skipped() if f.get("mode") not in ("access", "trunk") else (
        passed("IPv6 RA Guard enabled") if f.get("ipv6_ra_guard") else warned("IPv6 RA Guard missing")
    ),
)
add_rule(
    "qos_policy", "QoS policy attachment", "low", 2, "QoS", "service-policy input|output <policy>",
    lambda f, g: passed("QoS policy present") if f.get("qos_input") or f.get("qos_output") else warned("No QoS policy attached"),
)
add_rule(
    "acl_presence", "ACL presence", "medium", 4, "Management Plane", "ip access-group <acl> in",
    lambda f, g: passed("ACL present") if f.get("acl_in") or f.get("acl_out") or f.get("ipv6_acl_in") else warned("No ACL attached"),
)
add_rule(
    "protected_port", "Protected port / port isolation", "low", 2, "L2 Hardening", "protected-port",
    lambda f, g: passed("Port isolation enabled") if f.get("protected_port") or f.get("private_vlan") else warned("Port isolation not configured"),
)


def risk_level(score):
    if score >= 95:
        return "Minimal"
    if score >= 85:
        return "Low"
    if score >= 70:
        return "Medium"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Severe"
    return "Critical"


def assess_features(features, global_features=None):
    g = global_features or {}
    findings = []
    earned = 0.0
    total = 0.0
    comp_total = 0.0
    comp_earned = 0.0
    advanced_total = 0.0
    advanced_earned = 0.0

    for rule in RULES:
        check = CHECKS.get(rule["id"])
        if not check:
            continue
        status, detail = check(features, g)
        if status == "skip":
            continue

        weight = float(rule["weight"])
        total += weight
        if rule["severity"] in ("critical", "high"):
            comp_total += weight
        if rule["category"] in ("AAA", "IPv6", "QoS", "Telemetry", "First Hop Security"):
            advanced_total += weight

        finding = dict(rule)
        finding["status"] = status
        finding["detail"] = detail
        findings.append(finding)

        if status == "pass":
            earned += weight
            if rule["severity"] in ("critical", "high"):
                comp_earned += weight
            if rule["category"] in ("AAA", "IPv6", "QoS", "Telemetry", "First Hop Security"):
                advanced_earned += weight
        elif status == "warn":
            earned += weight * 0.5
            if rule["severity"] in ("critical", "high"):
                comp_earned += weight * 0.5
            if rule["category"] in ("AAA", "IPv6", "QoS", "Telemetry", "First Hop Security"):
                advanced_earned += weight * 0.5

    score = round((earned / total * 100.0), 1) if total else 0.0
    compliance = round((comp_earned / comp_total * 100.0), 1) if comp_total else score
    advanced = round((advanced_earned / advanced_total * 100.0), 1) if advanced_total else score
    maturity = round(min(100.0, score * 0.65 + advanced * 0.35), 1)

    return {
        "score": score,
        "compliance": compliance,
        "maturity": maturity,
        "risk_level": risk_level(score),
        "findings": findings,
        "summary": {
            "pass": len([x for x in findings if x["status"] == "pass"]),
            "warn": len([x for x in findings if x["status"] == "warn"]),
            "fail": len([x for x in findings if x["status"] == "fail"]),
        },
    }


def secure_features(features, global_features=None, name=""):
    f = deepcopy(features)
    g = global_features or {}

    physical_prefixes = (
        "FastEthernet",
        "GigabitEthernet",
        "TenGigabitEthernet",
        "TwentyFiveGigE",
        "FortyGigE",
        "HundredGigE",
    )
    if name.startswith(physical_prefixes) and f.get("mode") not in ("access", "trunk", "routed"):
        f["mode"] = "access"

    if f.get("mode") == "access":
        if not f.get("description"):
            f["description"] = "Secure access port"
        if not f.get("access_vlan") or f.get("access_vlan") == "1":
            f["access_vlan"] = "10"
        f["switchport"] = True
        f["portfast"] = True
        f["bpduguard"] = True
        f["bpdufilter"] = False
        f["port_security"] = True
        f["ps_max"] = f.get("ps_max") or "2"
        f["ps_violation"] = f.get("ps_violation") or "restrict"
        f["ps_sticky"] = True
        f["storm_broadcast"] = True
        f["storm_multicast"] = True
        f["storm_unicast"] = True
        f["storm_level"] = f.get("storm_level") or "10"
        if g.get("dhcp_snooping"):
            f["dhcp_snoop_trust"] = False
            f["dhcp_rate_limit"] = f.get("dhcp_rate_limit") or "100"
        if g.get("arp_inspection"):
            f["dai_trust"] = False
            f["arp_rate_limit"] = f.get("arp_rate_limit") or "100"
        f["ipsg"] = True
        if g.get("aaa"):
            f["auth_port_control"] = True
            f["mab"] = True
            f["auth_order"] = f.get("auth_order") or "dot1x mab"
            f["host_mode"] = f.get("host_mode") or "multi-auth"
            f["reauth"] = True
            f["guest_vlan"] = f.get("guest_vlan") or "20"
            f["critical_vlan"] = f.get("critical_vlan") or "30"
        f["cdp"] = False

    elif f.get("mode") == "trunk":
        if not f.get("description"):
            f["description"] = "Hardened trunk"
        if not f.get("native_vlan") or f.get("native_vlan") == "1":
            f["native_vlan"] = "999"
        if not f.get("allowed_vlans") or str(f.get("allowed_vlans")).lower() == "all":
            f["allowed_vlans"] = "10,20"
        f["switchport"] = True
        f["nonegotiate"] = True
        f["rootguard"] = True
        f["loopguard"] = True
        f["udld"] = True
        f["storm_broadcast"] = True
        f["storm_multicast"] = True
        f["storm_unicast"] = True
        if g.get("dhcp_snooping"):
            f["dhcp_snoop_trust"] = True
        if g.get("arp_inspection"):
            f["dai_trust"] = True

    if not f.get("description"):
        f["description"] = "Managed by Cisco Hardening Platform"
    f["shutdown"] = False
    return f


def generate_commands(features):
    f = features or {}
    commands = []

    if f.get("description"):
        commands.append("description " + str(f["description"]))
    if f.get("shutdown"):
        commands.append("shutdown")
    else:
        commands.append("no shutdown")

    mode = f.get("mode")
    if mode in ("access", "trunk"):
        commands.append("switchport")
        if mode == "access":
            commands.append("switchport mode access")
            if f.get("access_vlan"):
                commands.append("switchport access vlan " + str(f["access_vlan"]))
            if f.get("voice_vlan"):
                commands.append("voice vlan " + str(f["voice_vlan"]))
        elif mode == "trunk":
            commands.append("switchport mode trunk")
            if f.get("native_vlan"):
                commands.append("switchport trunk native vlan " + str(f["native_vlan"]))
            if f.get("allowed_vlans"):
                commands.append("switchport trunk allowed vlan " + str(f["allowed_vlans"]))
            if f.get("nonegotiate"):
                commands.append("switchport nonegotiate")

    if f.get("portfast"):
        commands.append("spanning-tree portfast")
    if f.get("bpduguard"):
        commands.append("spanning-tree bpduguard enable")
    if f.get("bpdufilter"):
        commands.append("spanning-tree bpdufilter enable")
    if f.get("rootguard"):
        commands.append("spanning-tree guard root")
    if f.get("loopguard"):
        commands.append("spanning-tree guard loop")
    if f.get("udld"):
        commands.append("udld port aggressive" if f.get("udld_aggressive") else "udld port")

    if f.get("storm_broadcast"):
        commands.append("storm-control broadcast level " + str(f.get("storm_level") or "10"))
    if f.get("storm_multicast"):
        commands.append("storm-control multicast level " + str(f.get("storm_level") or "10"))
    if f.get("storm_unicast"):
        commands.append("storm-control unicast level " + str(f.get("storm_level") or "10"))

    if f.get("port_security"):
        commands.append("switchport port-security")
        if f.get("ps_max"):
            commands.append("switchport port-security maximum " + str(f["ps_max"]))
        if f.get("ps_violation"):
            commands.append("switchport port-security violation " + str(f["ps_violation"]))
        if f.get("ps_sticky"):
            commands.append("switchport port-security mac-address sticky")

    if f.get("ipsg"):
        commands.append("ip verify source")
    if f.get("dhcp_snoop_trust"):
        commands.append("ip dhcp snooping trust")
    elif f.get("dhcp_rate_limit"):
        commands.append("ip dhcp snooping limit rate " + str(f["dhcp_rate_limit"]))
    if f.get("dai_trust"):
        commands.append("ip arp inspection trust")
    elif f.get("arp_rate_limit"):
        commands.append("ip arp inspection limit rate " + str(f["arp_rate_limit"]))

    if f.get("auth_port_control"):
        commands.append("authentication port-control auto")
    if f.get("mab"):
        commands.append("mab")
    if f.get("auth_order"):
        commands.append("authentication order " + str(f["auth_order"]))
    if f.get("auth_priority"):
        commands.append("authentication priority " + str(f["auth_priority"]))
    if f.get("host_mode"):
        commands.append("authentication host-mode " + str(f["host_mode"]))
    if f.get("reauth"):
        commands.append("authentication periodic")
    if f.get("guest_vlan"):
        commands.append("authentication guest vlan " + str(f["guest_vlan"]))
    if f.get("critical_vlan"):
        commands.append("authentication critical vlan " + str(f["critical_vlan"]))

    if f.get("acl_in"):
        commands.append("ip access-group " + str(f["acl_in"]) + " in")
    if f.get("acl_out"):
        commands.append("ip access-group " + str(f["acl_out"]) + " out")
    if f.get("ipv6_acl_in"):
        commands.append("ipv6 traffic-filter " + str(f["ipv6_acl_in"]) + " in")
    if f.get("ipv6_acl_out"):
        commands.append("ipv6 traffic-filter " + str(f["ipv6_acl_out"]) + " out")
    if f.get("ipv6_ra_guard"):
        commands.append("ipv6 nd raguard")

    if f.get("protected_port"):
        commands.append("protected-port")
    if f.get("private_vlan"):
        commands.append("private-vlan port-isolation")
    if f.get("qos_input"):
        commands.append("service-policy input " + str(f["qos_input"]))
    if f.get("qos_output"):
        commands.append("service-policy output " + str(f["qos_output"]))
    if f.get("cdp") is False:
        commands.append("no cdp enable")
    if f.get("lldp") is False:
        commands.append("no lldp transmit")
        commands.append("no lldp receive")

    return commands


def diff_commands(current_commands, recommended_commands):
    current_set = {re.sub(r"\s+", " ", x.strip().lower()) for x in current_commands if x.strip()}
    return [cmd for cmd in recommended_commands if re.sub(r"\s+", " ", cmd.strip().lower()) not in current_set]


# ---------------------------------------------------------------------------
# app.security_center adapter -- new code, not part of the original engine.
# ---------------------------------------------------------------------------

_STATUS_MAP = {
    "pass": Status.PASS,
    "fail": Status.FAIL,
    "warn": Status.WARN,
    # "skip" never reaches here -- assess_features() already excludes
    # skipped rules from its own `findings` list (see the `continue`
    # right after `if status == "skip"`), so NA is never actually
    # produced by this adapter today; included only so an unmapped
    # status fails loudly (KeyError) rather than silently mis-tagging.
}

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def to_unified_findings(interface_name: str, assessment: dict) -> list:
    """Converts one interface's assess_features() result into a list of
    app.security_center.engine.finding.Finding objects.

    Field mapping (left = this engine's own rule/result dict key, right =
    unified Finding field):
      id -> check_id            title -> title
      category -> domain (prefixed "Interface Security / ")
      severity -> severity (mapped through _SEVERITY_MAP)
      status -> status (mapped through _STATUS_MAP)
      detail -> detail           recommended_cli -> fix_command
      why/risk/attack/best/performance/operational/compatibility/references
        -> same-named Finding fields, unchanged

    `evidence`/`evidence_label`/`recommendation` have no equivalent in this
    engine's own finding shape (it never produced them -- `detail` already
    carries what evidence/recommendation split apart on the device-level
    side), so they're left at Finding's own defaults rather than invented.
    """
    out = []
    for item in assessment["findings"]:
        out.append(Finding(
            check_id=item["id"],
            domain=f"Interface Security / {item['category']}",
            title=item["title"],
            status=_STATUS_MAP[item["status"]],
            severity=_SEVERITY_MAP[item["severity"]],
            detail=item.get("detail", ""),
            fix_command=item.get("recommended_cli", ""),
            interface_name=interface_name,
            why=item.get("why", ""),
            risk=item.get("risk", ""),
            attack=item.get("attack", ""),
            best=item.get("best", ""),
            performance=item.get("performance", ""),
            operational=item.get("operational", ""),
            compatibility=item.get("compatibility", ""),
            references=item.get("references", []),
        ))
    return out
