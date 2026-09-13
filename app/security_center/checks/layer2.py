"""
app.security_center.checks.layer2
=================================
Layer 2 Security domain. Migrated verbatim from cisco-ios-security-auditor's
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
from ..parser.cisco_config import CiscoConfig, ifname


def check_port_security(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / Port Security"
    out: list[Finding] = []
    access_ports = [b for b in cfg.physical_interfaces()
                     if cfg.is_access_port(b) and not cfg.looks_like_uplink(b)]

    no_portsec = []
    bad_max = []
    no_sticky = []
    weak_violation = []
    any_portsec_enabled = False

    for blk in access_ports:
        if not blk.has(r"switchport port-security\b"):
            no_portsec.append(ifname(blk.header))
            continue
        any_portsec_enabled = True
        has_voice = blk.has(r"switchport voice vlan")
        max_allowed = policy["port_security_max_hosts_voice"] if has_voice else policy["port_security_max_hosts_data"]
        max_m = blk.find(r"switchport port-security maximum (\d+)")
        if max_m and int(max_m.group(1)) > max_allowed:
            bad_max.append(f"{ifname(blk.header)}  (maximum {max_m.group(1)}, policy allows <= {max_allowed})")
        if not blk.has(r"switchport port-security mac-address sticky"):
            no_sticky.append(ifname(blk.header))
        if blk.has(r"switchport port-security violation protect\b"):
            weak_violation.append(ifname(blk.header))

    out.append(F("L2PS-01", d, "Port Security enabled on access ports",
                  Status.FAIL if no_portsec else (Status.PASS if access_ports else Status.NA),
                  Severity.HIGH, evidence=no_portsec,
                  evidence_label="Port Security DISABLED on these access interfaces",
                  detail="Heuristic: excludes trunk ports and ports whose description suggests an uplink; "
                          "verify any remaining false positives manually." if access_ports else "",
                  recommendation="Enable 'switchport port-security' on every genuine access port.",
                  fix_command="interface <interface>\n"
                              " switchport port-security\n"
                              " switchport port-security maximum 1\n"
                              " switchport port-security violation restrict\n"
                              " switchport port-security mac-address sticky\n"
                              "! Repeat for each interface listed above.\n"
                              "! Use 'maximum 2' instead of 1 on ports with a voice VLAN configured."))

    out.append(F("L2PS-02", d, "Port Security maximum MAC count within policy",
                  Status.FAIL if bad_max else (Status.PASS if any_portsec_enabled else Status.NA),
                  Severity.MEDIUM, evidence=bad_max,
                  evidence_label="Interfaces with maximum MAC count above policy",
                  recommendation=f"Set maximum to {policy['port_security_max_hosts_data']} on data-only ports, "
                                 f"{policy['port_security_max_hosts_voice']} where a voice VLAN is present.",
                  fix_command=f"interface <interface>\n"
                              f" switchport port-security maximum {policy['port_security_max_hosts_data']}\n"
                              f"! Use {policy['port_security_max_hosts_voice']} instead if a voice VLAN is present on that port."))

    out.append(F("L2PS-03", d, "Port Security uses sticky MAC learning",
                  Status.FAIL if no_sticky else (Status.PASS if any_portsec_enabled else Status.NA),
                  Severity.LOW, evidence=no_sticky,
                  evidence_label="Interfaces without sticky MAC learning",
                  recommendation="Use 'switchport port-security mac-address sticky' where static learning is appropriate.",
                  fix_command="interface <interface>\n"
                              " switchport port-security mac-address sticky\n"
                              "! Repeat for each interface listed above."))

    out.append(F("L2PS-04", d, "Port Security violation action is not 'protect' (silent)",
                  Status.FAIL if weak_violation else (Status.PASS if any_portsec_enabled else Status.NA),
                  Severity.LOW, evidence=weak_violation,
                  evidence_label="Interfaces using the silent 'protect' violation action",
                  recommendation="Prefer 'shutdown' or 'restrict' (both log/alert) over 'protect' (silently drops, no log).",
                  fix_command="interface <interface>\n"
                              " switchport port-security violation restrict\n"
                              "! Use 'shutdown' instead of 'restrict' if you want the port err-disabled on violation."))

    ctx.set("port_security_any_without_sticky", bool(no_sticky) and any_portsec_enabled)
    return out


def check_stp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / Spanning Tree"
    out: list[Finding] = []
    access_ports = [b for b in cfg.physical_interfaces() if cfg.is_access_port(b)]
    global_bpduguard = cfg.search(r"^spanning-tree portfast bpduguard default")

    no_bpduguard = []
    for blk in access_ports:
        if global_bpduguard:
            continue
        if not blk.has(r"spanning-tree bpduguard enable"):
            no_bpduguard.append(ifname(blk.header))
    out.append(F("STP-01", d, "BPDU Guard enabled on access/edge ports",
                  Status.FAIL if (no_bpduguard and not global_bpduguard) else Status.PASS,
                  Severity.HIGH, evidence=no_bpduguard,
                  evidence_label="Access interfaces without BPDU Guard",
                  recommendation="Enable 'spanning-tree portfast bpduguard default' globally, or per-port "
                                 "'spanning-tree bpduguard enable' on every access port.",
                  fix_command="! Global (simplest, applies to every PortFast-enabled port):\n"
                              "spanning-tree portfast bpduguard default\n"
                              "!\n"
                              "! OR per-interface, repeated for each interface listed above:\n"
                              "interface <interface>\n"
                              " spanning-tree bpduguard enable"))

    root_guard_count = len(cfg.search_lines(r"spanning-tree guard root"))
    out.append(F("STP-02", d, "Root Guard present on at least one interface",
                  Status.PASS if root_guard_count else Status.FAIL, Severity.MEDIUM,
                  recommendation="Apply 'spanning-tree guard root' on uplinks toward the root bridge to prevent "
                                 "an unauthorized switch from taking over as root.",
                  fix_command="interface <uplink-interface>\n"
                              " spanning-tree guard root\n"
                              "! Apply on every uplink facing the root bridge, not access ports."))

    loop_guard = cfg.search(r"^spanning-tree loopguard default") or cfg.search(r"spanning-tree guard loop")
    out.append(F("STP-03", d, "Loop Guard configured (global default or per-interface)",
                  Status.PASS if loop_guard else Status.FAIL, Severity.MEDIUM,
                  recommendation="Configure 'spanning-tree loopguard default' globally where root/loop guard "
                                 "aren't both needed on the same ports.",
                  fix_command="spanning-tree loopguard default"))

    stp_mode = re.search(r"^spanning-tree mode (\S+)", cfg.text, re.M | re.I)
    out.append(F("STP-04", d, f"Spanning-tree mode: {stp_mode.group(1) if stp_mode else 'default (PVST+)'}",
                  Status.PASS, Severity.INFO,
                  recommendation="Rapid-PVST+ or MST recommended over legacy PVST+ for faster convergence."))

    return out


def check_udld(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / UDLD"
    out: list[Finding] = []
    global_udld = cfg.search(r"^udld (enable|aggressive)")
    per_intf_udld = cfg.search(r"udld port aggressive")
    out.append(F("UDLD-01", d, "UDLD enabled (globally or per fiber interface)",
                  Status.PASS if (global_udld or per_intf_udld) else Status.FAIL,
                  Severity.LOW,
                  recommendation="Enable 'udld aggressive' globally, or 'udld port aggressive' on fiber uplinks, "
                                 "to detect unidirectional link failures.",
                  fix_command="udld aggressive\n"
                              "! Global setting; applies to all fiber-capable interfaces."))
    return out


def check_storm_control(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / Storm Control"
    out: list[Finding] = []
    access_ports = [b for b in cfg.physical_interfaces() if cfg.is_access_port(b)]
    missing = [ifname(b.header) for b in access_ports if not b.has(r"storm-control (broadcast|multicast|unicast)")]
    out.append(F("STORM-01", d, "Storm control configured on access ports",
                  Status.FAIL if missing else (Status.PASS if access_ports else Status.NA),
                  Severity.MEDIUM, evidence=missing,
                  evidence_label="Access interfaces without storm control",
                  recommendation="Configure 'storm-control broadcast|multicast|unicast level <x>' on access ports.",
                  fix_command="interface <interface>\n"
                              " storm-control broadcast level 1.00\n"
                              " storm-control multicast level 1.00\n"
                              " storm-control action trap\n"
                              "! Repeat for each interface listed above; tune the level to your traffic baseline."))
    return out


def check_dhcp_snooping(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / DHCP Snooping"
    out: list[Finding] = []
    enabled = cfg.search(r"^ip dhcp snooping\b(?! vlan)") or cfg.search(r"^ip dhcp snooping$")
    vlan_scoped = cfg.search_lines(r"^ip dhcp snooping vlan\b")
    out.append(F("DHCPSNOOP-01", d, "DHCP Snooping enabled globally",
                  Status.PASS if enabled else Status.FAIL, Severity.CRITICAL,
                  recommendation="Configure 'ip dhcp snooping' globally.",
                  fix_command="ip dhcp snooping"))
    out.append(F("DHCPSNOOP-02", d, "DHCP Snooping scoped to specific VLANs",
                  Status.PASS if vlan_scoped else Status.FAIL, Severity.MEDIUM, evidence=vlan_scoped,
                  evidence_label="Current VLAN-scoping lines found",
                  recommendation="Configure 'ip dhcp snooping vlan <list>' to scope enforcement.",
                  fix_command="ip dhcp snooping vlan <vlan-list>\n! e.g. ip dhcp snooping vlan 10,20,30"))

    access_ports = [b for b in cfg.physical_interfaces() if cfg.is_access_port(b)]
    trusted_ports = [b for b in cfg.physical_interfaces() if b.has(r"ip dhcp snooping trust")]
    bad_rate = []
    missing_rate = []
    lo = policy["dhcp_snooping_rate_limit_min"]
    rec_hi = policy["dhcp_snooping_rate_limit_recommended_max"]
    hard_hi = policy["dhcp_snooping_rate_limit_hard_max"]
    for blk in access_ports:
        if blk in trusted_ports:
            continue
        m = blk.find(r"ip dhcp snooping limit rate (\d+)")
        if not m:
            if enabled:
                missing_rate.append(ifname(blk.header))
            continue
        rate = int(m.group(1))
        if rate < lo or rate > hard_hi:
            bad_rate.append(f"{ifname(blk.header)}  (rate {rate}, policy: {lo}-{hard_hi}, recommended <= {rec_hi})")
        elif rate > rec_hi:
            bad_rate.append(f"{ifname(blk.header)}  (rate {rate}, above recommended {rec_hi}, within hard max {hard_hi})")

    out.append(F("DHCPSNOOP-03", d, "Untrusted ports have a rate limit configured",
                  Status.FAIL if missing_rate else (Status.PASS if (access_ports and enabled) else Status.NA),
                  Severity.MEDIUM, evidence=missing_rate,
                  evidence_label="Untrusted interfaces with no DHCP Snooping rate limit",
                  recommendation=f"Configure 'ip dhcp snooping limit rate <n>' ({lo}-{rec_hi} recommended) on untrusted access ports.",
                  fix_command=f"interface <interface>\n"
                              f" ip dhcp snooping limit rate {rec_hi}\n"
                              f"! Repeat for each interface listed above. Keep within {lo}-{rec_hi} pps "
                              f"({hard_hi} is a hard ceiling)."))
    out.append(F("DHCPSNOOP-04", d, "DHCP Snooping rate limit within policy range",
                  Status.FAIL if bad_rate else (Status.PASS if (access_ports and enabled) else Status.NA),
                  Severity.LOW, evidence=bad_rate,
                  evidence_label="Interfaces with a rate limit outside policy",
                  recommendation=f"Keep rate limit between {lo} and {rec_hi} pps; {hard_hi} is a hard ceiling.",
                  fix_command=f"interface <interface>\n ip dhcp snooping limit rate {rec_hi}"))

    trust_count = len(trusted_ports)
    total_physical = len(cfg.physical_interfaces())
    out.append(F("DHCPSNOOP-05", d, f"Trusted-port count is small relative to total interfaces ({trust_count}/{total_physical})",
                  Status.FAIL if (total_physical and trust_count > max(2, total_physical // 4)) else Status.PASS,
                  Severity.LOW,
                  evidence=[ifname(b.header) for b in trusted_ports] if (total_physical and trust_count > max(2, total_physical // 4)) else [],
                  evidence_label="Currently trusted interfaces",
                  recommendation="Only uplinks toward the legitimate DHCP server should be trusted; "
                                 "a large trusted-port count usually indicates over-trusting.",
                  fix_command="interface <non-uplink-interface>\n no ip dhcp snooping trust\n"
                              "! Remove trust from any interface that isn't a genuine uplink toward the DHCP server."))

    ctx.set("dhcp_snooping_enabled", enabled)
    return out


def check_dai(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / Dynamic ARP Inspection"
    out: list[Finding] = []
    dai_vlans = cfg.search_lines(r"^ip arp inspection vlan\b")
    enabled = bool(dai_vlans)
    out.append(F("DAI-01", d, "DAI enabled on at least one VLAN",
                  Status.PASS if enabled else Status.FAIL, Severity.HIGH, evidence=dai_vlans,
                  evidence_label="Current DAI VLAN lines found",
                  recommendation="Configure 'ip arp inspection vlan <list>' on VLANs where DHCP Snooping is active.",
                  fix_command="ip arp inspection vlan <vlan-list>\n! e.g. ip arp inspection vlan 10,20,30"))

    dai_trust = {b.header for b in cfg.physical_interfaces() if b.has(r"ip arp inspection trust")}
    snoop_trust = {b.header for b in cfg.physical_interfaces() if b.has(r"ip dhcp snooping trust")}
    mismatch = [ifname(h) for h in dai_trust.symmetric_difference(snoop_trust)]
    out.append(F("DAI-02", d, "DAI trust state matches DHCP Snooping trust state",
                  Status.FAIL if mismatch else (Status.PASS if enabled else Status.NA),
                  Severity.MEDIUM, evidence=mismatch,
                  evidence_label="Interfaces where DAI trust and DHCP Snooping trust disagree",
                  recommendation="Trusted ports for DAI and DHCP Snooping should normally be identical (uplinks only).",
                  fix_command="interface <interface>\n"
                              " ip dhcp snooping trust\n"
                              " ip arp inspection trust\n"
                              "! Align both settings on genuine uplinks; remove both from anywhere else."))

    validation = cfg.search(r"^ip arp inspection validate")
    out.append(F("DAI-03", d, "DAI additional validation checks enabled (src-mac/dst-mac/ip)",
                  Status.PASS if validation else Status.FAIL, Severity.LOW,
                  recommendation="Configure 'ip arp inspection validate src-mac dst-mac ip'.",
                  fix_command="ip arp inspection validate src-mac dst-mac ip"))

    rate_missing = []
    hard_hi = policy["arp_inspection_rate_limit_hard_max"]
    bad_rate = []
    for blk in cfg.physical_interfaces():
        if blk.header in snoop_trust:
            continue
        m = blk.find(r"ip arp inspection limit rate (\d+)")
        if enabled and cfg.is_access_port(blk) and not m:
            rate_missing.append(ifname(blk.header))
        elif m and int(m.group(1)) > hard_hi:
            bad_rate.append(f"{ifname(blk.header)}  (rate {m.group(1)}, policy hard max {hard_hi})")
    out.append(F("DAI-04", d, "ARP inspection rate limit configured on untrusted ports",
                  Status.FAIL if rate_missing else (Status.PASS if enabled else Status.NA),
                  Severity.LOW, evidence=rate_missing,
                  evidence_label="Untrusted interfaces with no ARP inspection rate limit",
                  recommendation="Configure 'ip arp inspection limit rate <n>' on untrusted access ports.",
                  fix_command="interface <interface>\n ip arp inspection limit rate 15"))

    device_tracking = cfg.search(r"^device-tracking policy") or cfg.search(r"device-tracking attach-policy")
    ctx.set("dai_enabled", enabled)
    ctx.set("device_tracking_configured", bool(device_tracking))
    out.append(F("DAI-05", d, "Device Tracking (SISF) policy configured",
                  Status.PASS if device_tracking else Status.FAIL, Severity.LOW,
                  recommendation="Configure a 'device-tracking policy' and attach it where IPSG/DAI rely on the "
                                 "binding table.",
                  fix_command="device-tracking policy IPDT-POLICY\n"
                              " limit address-count 4\n"
                              " security-level glean\n"
                              "!\n"
                              "interface <interface>\n"
                              " device-tracking attach-policy IPDT-POLICY"))
    return out


def check_ip_source_guard(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / IP Source Guard"
    out: list[Finding] = []
    access_ports = [b for b in cfg.physical_interfaces() if cfg.is_access_port(b)]
    missing = [ifname(b.header) for b in access_ports if not b.has(r"ip verify source")]
    dhcp_snoop_enabled = ctx.get("dhcp_snooping_enabled", False)
    out.append(F("IPSG-01", d, "IP Source Guard enabled on untrusted access ports",
                  Status.FAIL if (missing and dhcp_snoop_enabled) else (Status.PASS if access_ports else Status.NA),
                  Severity.MEDIUM, evidence=missing,
                  evidence_label="Access interfaces without IP Source Guard",
                  recommendation="Configure 'ip verify source' on untrusted access ports (requires DHCP Snooping).",
                  fix_command="interface <interface>\n ip verify source\n! Repeat for each interface listed above."))
    return out


def check_trunk_native_vtp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / Trunk, Native VLAN & VTP"
    out: list[Finding] = []
    trunks = [b for b in cfg.physical_interfaces() if cfg.is_trunk_port(b)]

    native_default = []
    native_changed = False
    for blk in trunks:
        m = blk.find(r"switchport trunk native vlan (\d+)")
        if not m or m.group(1) == "1":
            native_default.append(blk.header)
        else:
            native_changed = True
    out.append(F("TRUNK-01", d, "Native VLAN changed from default (VLAN 1)",
                  Status.FAIL if native_default else (Status.PASS if trunks else Status.NA),
                  Severity.MEDIUM, evidence=[ifname(h) for h in native_default],
                  evidence_label="Trunk interfaces still on native VLAN 1",
                  recommendation="Set an explicit, non-default native VLAN with 'switchport trunk native vlan <n>' "
                                 "(and ideally an unused VLAN).",
                  fix_command="interface <trunk-interface>\n"
                              " switchport trunk native vlan <unused-vlan-id>\n"
                              "! Repeat for each trunk listed above; use a dedicated unused VLAN, not VLAN 1."))

    allows_all = [ifname(b.header) for b in trunks if not b.has(r"switchport trunk allowed vlan")]
    out.append(F("TRUNK-02", d, "Trunk allowed-VLAN list explicitly pruned",
                  Status.FAIL if allows_all else (Status.PASS if trunks else Status.NA),
                  Severity.MEDIUM, evidence=allows_all,
                  evidence_label="Trunks with no pruned allowed-VLAN list (implicitly allowing all)",
                  recommendation="Configure 'switchport trunk allowed vlan <pruned-list>' on every trunk.",
                  fix_command="interface <trunk-interface>\n"
                              " switchport trunk allowed vlan <comma-separated-list>\n"
                              "! e.g. switchport trunk allowed vlan 10,20,30"))

    dtp_on = [ifname(b.header) for b in trunks if not b.has(r"switchport nonegotiate")]
    out.append(F("TRUNK-03", d, "DTP disabled on trunks (switchport nonegotiate)",
                  Status.FAIL if dtp_on else (Status.PASS if trunks else Status.NA),
                  Severity.LOW, evidence=dtp_on,
                  evidence_label="Trunks still negotiating via DTP",
                  recommendation="Configure 'switchport nonegotiate' on statically-configured trunks.",
                  fix_command="interface <trunk-interface>\n switchport nonegotiate"))

    vtp_mode = re.search(r"^vtp mode (\S+)", cfg.text, re.M | re.I)
    mode_val = vtp_mode.group(1).lower() if vtp_mode else "server"  # server is IOS default
    out.append(F("VTP-01", d, f"VTP mode is transparent/off (found: {mode_val})",
                  Status.PASS if mode_val in ("transparent", "off") else Status.FAIL,
                  Severity.MEDIUM,
                  recommendation="Set 'vtp mode transparent' unless VTP is deliberately and carefully managed.",
                  fix_command="vtp mode transparent"))

    ctx.set("native_vlan_changed", native_changed)
    ctx.set("trunk_allows_all_vlans", bool(allows_all))
    return out


def check_etherchannel(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 2 / EtherChannel"
    out: list[Finding] = []
    static_on = cfg.search_lines(r"channel-group \d+ mode on\b")
    out.append(F("ECHAN-01", d, "EtherChannel members use LACP (not static 'mode on')",
                  Status.FAIL if static_on else Status.PASS, Severity.LOW, evidence=static_on,
                  evidence_label="Member interfaces using static 'mode on'",
                  recommendation="Prefer 'channel-group <n> mode active' (LACP) over static 'mode on' so "
                                 "misconfiguration is detected instead of silently forwarding/looping.",
                  fix_command="interface <member-interface>\n"
                              " channel-group <n> mode active\n"
                              "! Apply on every member of the port-channel, matching on both ends."))
    return out


LAYER2_CHECKS = [check_port_security, check_stp, check_udld, check_storm_control, check_dhcp_snooping, check_dai, check_ip_source_guard, check_trunk_native_vtp, check_etherchannel]
