"""
app.security_center.parser.interface_config
===============================================
Per-interface Cisco IOS/IOS-XE feature extraction. Migrated from the
legacy `cisco-interface-security-audit` project's `app/parser/cisco_ios.py`
(verified against the real, complete generated source, not the README's
summary of it) -- a simple line-by-line state machine, deliberately
kept distinct from app.security_center.parser.cisco_config's block-tree
parser, since the two projects' parsers solve different problems: this
one tracks ~50 named feature attributes per interface plus 14 global
context flags, purpose-built for the interface engine's weighted rule
model (app.security_center.checks.interfaces); the device-wide parser
tracks arbitrary config stanzas for the 9 device-level domains.

Both parsers run over the same raw config text independently -- see
app.security_center.parser's own docstring for why this is a
deliberate design choice, not an oversight.
"""
from __future__ import annotations

import re

PHYSICAL_PREFIXES = (
    "FastEthernet",
    "GigabitEthernet",
    "TenGigabitEthernet",
    "TwentyFiveGigE",
    "FortyGigE",
    "HundredGigE",
)


def default_global() -> dict:
    return {
        "aaa": False,
        "radius_servers": [],
        "dhcp_snooping": False,
        "dhcp_snooping_vlans": "",
        "arp_inspection": False,
        "arp_inspection_vlans": "",
        "spanning_tree_mode": "",
        "snmp_communities": [],
        "service_password_encryption": False,
        "enable_secret": False,
        "vtp_mode": "",
        "errdisable_recovery": False,
        "ntp_servers": [],
        "logging_servers": [],
        "control_plane": False,
    }


def default_features() -> dict:
    return {
        "description": "",
        "description_present": False,
        "shutdown": False,
        "switchport": False,
        "mode": "unknown",
        "access_vlan": "",
        "native_vlan": "",
        "allowed_vlans": "",
        "nonegotiate": False,
        "portfast": False,
        "bpduguard": False,
        "bpdufilter": False,
        "rootguard": False,
        "loopguard": False,
        "udld": False,
        "udld_aggressive": False,
        "storm_broadcast": False,
        "storm_multicast": False,
        "storm_unicast": False,
        "storm_level": "",
        "port_security": False,
        "ps_max": "",
        "ps_violation": "",
        "ps_sticky": False,
        "dhcp_snoop_trust": False,
        "dhcp_rate_limit": "",
        "dai_trust": False,
        "arp_rate_limit": "",
        "ipsg": False,
        "acl_in": "",
        "acl_out": "",
        "ipv6_acl_in": "",
        "ipv6_acl_out": "",
        "auth_port_control": False,
        "mab": False,
        "auth_order": "",
        "auth_priority": "",
        "host_mode": "",
        "guest_vlan": "",
        "critical_vlan": "",
        "reauth": False,
        "auth_timers": False,
        "cdp": True,
        "lldp": True,
        "voice_vlan": "",
        "protected_port": False,
        "private_vlan": False,
        "ipv6_ra_guard": False,
        "ipv6_snooping": False,
        "qos_input": "",
        "qos_output": "",
        "span_destination": False,
        "poe": False,
        "eee": False,
        "errdisable_recovery": False,
        "device_tracking": False,
        "sisf": False,
    }


def parse_global_line(line: str, g: dict) -> None:
    s = line.strip()
    if s.startswith("aaa new-model"):
        g["aaa"] = True
    elif s.startswith("radius server "):
        g["radius_servers"].append(s.split()[-1])
    elif s == "ip dhcp snooping":
        g["dhcp_snooping"] = True
    elif s.startswith("ip dhcp snooping vlan"):
        g["dhcp_snooping"] = True
        g["dhcp_snooping_vlans"] = s.split("vlan", 1)[1].strip()
    elif s.startswith("ip arp inspection vlan"):
        g["arp_inspection"] = True
        g["arp_inspection_vlans"] = s.split("vlan", 1)[1].strip()
    elif s.startswith("spanning-tree mode"):
        g["spanning_tree_mode"] = s.split("mode", 1)[1].strip()
    elif s.startswith("snmp-server community"):
        parts = s.split()
        if len(parts) > 2:
            g["snmp_communities"].append(parts[2])
    elif s == "service password-encryption":
        g["service_password_encryption"] = True
    elif s.startswith("enable secret"):
        g["enable_secret"] = True
    elif s.startswith("vtp mode"):
        g["vtp_mode"] = s.split()[-1]
    elif s.startswith("errdisable recovery"):
        g["errdisable_recovery"] = True
    elif s.startswith("ntp server "):
        g["ntp_servers"].append(s.split()[-1])
    elif s.startswith("logging host"):
        g["logging_servers"].append(s.split()[-1])
    elif s.startswith("control-plane"):
        g["control_plane"] = True


def parse_interface_line(line: str, iface: dict) -> None:
    s = line.strip()
    f = iface["features"]

    if s.startswith("description "):
        f["description"] = s[12:].strip()
        f["description_present"] = True
        iface["description"] = f["description"]
    elif s == "shutdown":
        f["shutdown"] = True
    elif s == "no shutdown":
        f["shutdown"] = False
    elif s.startswith("switchport mode access"):
        f["switchport"] = True
        f["mode"] = "access"
    elif s.startswith("switchport mode trunk"):
        f["switchport"] = True
        f["mode"] = "trunk"
    elif s.startswith("switchport access vlan"):
        f["access_vlan"] = s.split()[-1]
    elif s.startswith("switchport trunk native vlan"):
        f["native_vlan"] = s.split()[-1]
    elif s.startswith("switchport trunk allowed vlan"):
        f["allowed_vlans"] = s.split("vlan", 1)[1].strip()
    elif s == "switchport nonegotiate":
        f["nonegotiate"] = True
    elif s == "switchport port-security":
        f["port_security"] = True
    elif s.startswith("switchport port-security maximum"):
        f["ps_max"] = s.split()[-1]
    elif s.startswith("switchport port-security violation"):
        f["ps_violation"] = s.split()[-1]
    elif s.startswith("switchport port-security mac-address sticky"):
        f["ps_sticky"] = True
    elif s.startswith("spanning-tree portfast"):
        f["portfast"] = True
    elif s.startswith("spanning-tree bpduguard enable"):
        f["bpduguard"] = True
    elif s.startswith("spanning-tree bpdufilter enable"):
        f["bpdufilter"] = True
    elif s.startswith("spanning-tree guard root"):
        f["rootguard"] = True
    elif s.startswith("spanning-tree guard loop"):
        f["loopguard"] = True
    elif s.startswith("udld port"):
        f["udld"] = True
        if "aggressive" in s:
            f["udld_aggressive"] = True
    elif s.startswith("storm-control broadcast"):
        f["storm_broadcast"] = True
        if "level" in s:
            f["storm_level"] = s.split()[-1]
    elif s.startswith("storm-control multicast"):
        f["storm_multicast"] = True
    elif s.startswith("storm-control unicast"):
        f["storm_unicast"] = True
    elif s == "ip verify source":
        f["ipsg"] = True
    elif s.startswith("ip arp inspection trust"):
        f["dai_trust"] = True
    elif s.startswith("ip arp inspection limit rate"):
        f["arp_rate_limit"] = s.split()[-1]
    elif s == "ip dhcp snooping trust":
        f["dhcp_snoop_trust"] = True
    elif s.startswith("ip dhcp snooping limit rate"):
        f["dhcp_rate_limit"] = s.split()[-1]
    elif s.startswith("ip access-group"):
        parts = s.split()
        if len(parts) >= 4 and parts[-1] == "in":
            f["acl_in"] = parts[2]
        elif len(parts) >= 4 and parts[-1] == "out":
            f["acl_out"] = parts[2]
    elif s.startswith("ipv6 traffic-filter"):
        parts = s.split()
        if len(parts) >= 4 and parts[-1] == "in":
            f["ipv6_acl_in"] = parts[2]
        elif len(parts) >= 4 and parts[-1] == "out":
            f["ipv6_acl_out"] = parts[2]
    elif s.startswith("authentication port-control"):
        f["auth_port_control"] = True
    elif s == "mab":
        f["mab"] = True
    elif s.startswith("authentication order"):
        f["auth_order"] = s.split("order", 1)[1].strip()
    elif s.startswith("authentication priority"):
        f["auth_priority"] = s.split("priority", 1)[1].strip()
    elif s.startswith("authentication host-mode"):
        f["host_mode"] = s.split()[-1]
    elif s.startswith("authentication timer reauthenticate"):
        f["reauth"] = True
        f["auth_timers"] = True
    elif s.startswith("authentication periodic"):
        f["reauth"] = True
    elif s.startswith("authentication guest vlan"):
        f["guest_vlan"] = s.split()[-1]
    elif s.startswith("authentication critical vlan"):
        f["critical_vlan"] = s.split()[-1]
    elif s == "no cdp enable":
        f["cdp"] = False
    elif s == "cdp enable":
        f["cdp"] = True
    elif s.startswith("no lldp"):
        f["lldp"] = False
    elif s.startswith("lldp"):
        f["lldp"] = True
    elif s.startswith("voice vlan"):
        f["voice_vlan"] = s.split()[-1]
    elif s == "protected-port":
        f["protected_port"] = True
    elif s.startswith("private-vlan"):
        f["private_vlan"] = True
    elif s.startswith("ipv6 nd raguard"):
        f["ipv6_ra_guard"] = True
    elif s.startswith("service-policy input"):
        f["qos_input"] = s.split()[-1]
    elif s.startswith("service-policy output"):
        f["qos_output"] = s.split()[-1]
    elif s.startswith("span monitor"):
        f["span_destination"] = True
    elif s.startswith("power inline"):
        f["poe"] = True
    elif s.startswith("eeep energy-efficient-ethernet"):
        f["eee"] = True
    elif s.startswith("device-tracking"):
        f["device_tracking"] = True
    elif s.startswith("sisf"):
        f["sisf"] = True


def finalize_interface(iface: dict) -> None:
    name = iface["name"]
    f = iface["features"]

    if any(name.startswith(prefix) for prefix in PHYSICAL_PREFIXES):
        iface["kind"] = "physical"
        iface["port_type"] = name.split("/")[0] if "/" in name else name
    elif name.startswith("Port-channel"):
        iface["kind"] = "port-channel"
        iface["port_type"] = "Port-channel"
    elif name.startswith(("Loopback", "Vlan", "Management")):
        iface["kind"] = "logical"
        iface["port_type"] = name.split()[0]
    else:
        iface["kind"] = "other"
        iface["port_type"] = "other"

    if not f["mode"] or f["mode"] == "unknown":
        if f["switchport"]:
            f["mode"] = "access"
        elif any(x.startswith("ip address") for x in iface.get("raw", [])):
            f["mode"] = "routed"
        elif iface["kind"] == "physical":
            f["mode"] = "access"
        else:
            f["mode"] = "routed" if iface["kind"] == "logical" else "unknown"

    if not f["description"]:
        iface["description"] = ""


def parse_interface_config(content: str, filename: str = "") -> dict:
    """Parse a full running-config text into hostname/global/interfaces/vlans.

    Equivalent to the original project's `CiscoIosRunningConfigParser.parse()`
    without the plugin-registry indirection (`can_parse`/`@register`) --
    this module is the only Cisco IOS parser in this codebase, so the
    plugin dispatch layer the original used to support future vendors
    is deliberately not migrated; if multi-vendor support is genuinely
    wanted later, add it back as its own decision, not implicitly.
    """
    device = {
        "hostname": "unknown",
        "platform": "cisco-ios",
        "source": filename,
        "global": default_global(),
        "interfaces": [],
        "vlans": [],
        "raw": content,
    }
    current = None
    current_vlan = None

    for raw_line in content.splitlines():
        line = raw_line.rstrip()
        if not line.strip():
            continue

        if not line.startswith(" "):
            s = line.strip()
            current_vlan = None
            if s.startswith("interface "):
                name = s.split()[1]
                current = {
                    "name": name,
                    "description": "",
                    "raw": [],
                    "features": default_features(),
                }
                device["interfaces"].append(current)
            elif s.startswith("vlan "):
                vid = s.split()[1]
                current_vlan = {"id": vid, "name": "", "interfaces": []}
                device["vlans"].append(current_vlan)
                current = None
            else:
                current = None
                if s.startswith("hostname "):
                    device["hostname"] = s.split()[1]
                parse_global_line(s, device["global"])
        else:
            s = line.strip()
            if current:
                current["raw"].append(s)
                parse_interface_line(s, current)
            elif current_vlan and s.startswith("name "):
                current_vlan["name"] = s[5:].strip()

    for iface in device["interfaces"]:
        finalize_interface(iface)

    return device
