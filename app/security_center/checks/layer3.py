"""
app.security_center.checks.layer3
=================================
Layer 3 Security domain. Migrated verbatim from cisco-ios-security-auditor's
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


def check_urpf(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / uRPF"
    out: list[Finding] = []
    urpf_lines = cfg.search_lines(r"ip verify unicast source reachable-via")
    out.append(F("URPF-01", d, "uRPF configured on at least one interface",
                  Status.PASS if urpf_lines else Status.FAIL, Severity.MEDIUM, evidence=urpf_lines,
                  evidence_label="Current uRPF lines found",
                  recommendation="Configure uRPF (strict on single-homed edge interfaces, loose on multi-homed) "
                                 "to prevent source-IP spoofing.",
                  fix_command="interface <edge-interface>\n"
                              " ip verify unicast source reachable-via rx\n"
                              "! Use 'reachable-via any' instead on multi-homed/asymmetric-routed interfaces."))
    loose = [l for l in urpf_lines if "any" in l]
    if loose:
        out.append(F("URPF-02", d, "Loose-mode uRPF in use -- confirm this is intentional",
                      Status.MANUAL, Severity.LOW, evidence=loose,
                      evidence_label="Interfaces using loose-mode uRPF",
                      recommendation="Loose mode is appropriate for multi-homed/asymmetric routing; strict mode "
                                     "is stronger where the topology allows it."))
    return out


def check_routing_auth(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / Routing Protocol Authentication"
    out: list[Finding] = []

    ospf_blocks = cfg.get_blocks("router ospf")
    if ospf_blocks:
        area_auth = any(b.has(r"area \S+ authentication") for b in ospf_blocks)
        intf_auth = cfg.search(r"ip ospf authentication")
        passive_default = any(b.has(r"passive-interface default") for b in ospf_blocks)
        out.append(F("RTAUTH-OSPF-01", d, "OSPF authentication configured (area or per-interface)",
                      Status.PASS if (area_auth or intf_auth) else Status.FAIL, Severity.HIGH,
                      recommendation="Configure OSPF MD5/SHA authentication at the area or interface level.",
                      fix_command="router ospf <process-id>\n"
                                  " area <area-id> authentication message-digest\n"
                                  "!\n"
                                  "interface <ospf-interface>\n"
                                  " ip ospf message-digest-key 1 md5 <key>\n"
                                  "! Prefer SHA where supported: 'ip ospf authentication key-chain <chain>' with a "
                                  "key chain configured for hmac-sha-256."))
        out.append(F("RTAUTH-OSPF-02", d, "OSPF 'passive-interface default' hygiene",
                      Status.PASS if passive_default else Status.FAIL, Severity.LOW,
                      recommendation="Use 'passive-interface default' + explicit 'no passive-interface' on real "
                                     "OSPF-speaking links, so new interfaces don't form adjacencies by accident.",
                      fix_command="router ospf <process-id>\n"
                                  " passive-interface default\n"
                                  " no passive-interface <interface-that-should-speak-ospf>"))

    eigrp_blocks = cfg.get_blocks("router eigrp")
    if eigrp_blocks:
        eigrp_auth = cfg.search(r"ip authentication (mode|key-chain) eigrp") or cfg.search(r"authentication mode (md5|hmac-sha-256)")
        out.append(F("RTAUTH-EIGRP-01", d, "EIGRP authentication configured",
                      Status.PASS if eigrp_auth else Status.FAIL, Severity.HIGH,
                      recommendation="Configure EIGRP HMAC/key-chain authentication on all EIGRP-speaking interfaces.",
                      fix_command="key chain EIGRP-KEYS\n"
                                  " key 1\n"
                                  "  key-string <strong-key>\n"
                                  "!\n"
                                  "interface <eigrp-interface>\n"
                                  " ip authentication mode eigrp <as-number> md5\n"
                                  " ip authentication key-chain eigrp <as-number> EIGRP-KEYS"))

    rip_blocks = cfg.get_blocks("router rip")
    if rip_blocks:
        rip_auth = cfg.search(r"ip rip authentication mode md5")
        out.append(F("RTAUTH-RIP-01", d, "RIP authentication configured",
                      Status.PASS if rip_auth else Status.FAIL, Severity.MEDIUM,
                      recommendation="Configure 'ip rip authentication mode md5' + key-chain on RIP interfaces.",
                      fix_command="key chain RIP-KEYS\n"
                                  " key 1\n"
                                  "  key-string <strong-key>\n"
                                  "!\n"
                                  "interface <rip-interface>\n"
                                  " ip rip authentication mode md5\n"
                                  " ip rip authentication key-chain RIP-KEYS"))

    bgp_blocks = cfg.get_blocks("router bgp")
    if bgp_blocks:
        neighbor_lines = cfg.search_lines(r"^\s*neighbor \S+ ")
        no_pw = [l.strip() for l in cfg.search_lines(r"neighbor \S+ remote-as")
                 if not any(re.search(re.escape(l.split()[1]) + r" password", x) for x in cfg.search_lines(r"neighbor \S+ password"))]
        ttl_sec = cfg.search(r"neighbor \S+ ttl-security hops")
        max_prefix = cfg.search(r"neighbor \S+ maximum-prefix")
        dampening = any(b.has(r"bgp dampening") for b in bgp_blocks)
        out.append(F("RTAUTH-BGP-01", d, "BGP neighbors use TCP MD5 authentication",
                      Status.FAIL if no_pw else (Status.PASS if neighbor_lines else Status.NA),
                      Severity.HIGH, evidence=no_pw,
                      evidence_label="BGP neighbor statements with no password configured",
                      recommendation="Configure 'neighbor <ip> password <secret>' on every eBGP/iBGP session.",
                      fix_command="router bgp <as-number>\n neighbor <peer-ip> password <strong-secret>"))
        out.append(F("RTAUTH-BGP-02", d, "BGP TTL Security (GTSM) in use",
                      Status.PASS if ttl_sec else Status.FAIL, Severity.MEDIUM,
                      recommendation="Configure 'neighbor <ip> ttl-security hops <n>' on eBGP sessions.",
                      fix_command="router bgp <as-number>\n neighbor <peer-ip> ttl-security hops 1"))
        out.append(F("RTAUTH-BGP-03", d, "BGP maximum-prefix limits configured",
                      Status.PASS if max_prefix else Status.FAIL, Severity.MEDIUM,
                      recommendation="Configure 'neighbor <ip> maximum-prefix <n>' to bound route-table impact "
                                     "of a misbehaving/compromised peer.",
                      fix_command="router bgp <as-number>\n neighbor <peer-ip> maximum-prefix <n> 80 restart 15"))
        out.append(F("RTAUTH-BGP-04", d, "BGP route flap dampening reviewed",
                      Status.MANUAL, Severity.LOW,
                      detail=f"Dampening is {'configured' if dampening else 'not configured'}.",
                      recommendation="Route dampening is a tradeoff (can suppress legitimate flapping routes); "
                                     "confirm this matches your operational intent rather than treating it as a "
                                     "simple pass/fail."))

    isis_blocks = cfg.get_blocks("router isis")
    if isis_blocks:
        isis_auth = cfg.search(r"isis authentication mode")
        out.append(F("RTAUTH-ISIS-01", d, "IS-IS authentication configured",
                      Status.PASS if isis_auth else Status.FAIL, Severity.HIGH,
                      recommendation="Configure 'isis authentication mode md5' (or key-chain based) globally/per-interface.",
                      fix_command="router isis\n"
                                  " authentication mode md5\n"
                                  " authentication key-chain ISIS-KEYS"))

    if not any([ospf_blocks, eigrp_blocks, rip_blocks, bgp_blocks, isis_blocks]):
        out.append(F("RTAUTH-00", d, "No dynamic routing protocol detected in running-config",
                      Status.NA, Severity.INFO))
    return out


def check_fhrp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / FHRP (HSRP/VRRP/GLBP)"
    out: list[Finding] = []
    hsrp_intfs = [b for b in cfg.interfaces() if b.has(r"standby \d+ ")]
    if hsrp_intfs:
        no_auth = [ifname(b.header) for b in hsrp_intfs if not b.has(r"standby \d+ authentication")]
        plaintext = [ifname(b.header) for b in hsrp_intfs
                     if b.has(r"standby \d+ authentication") and not b.has(r"standby \d+ authentication md5")]
        out.append(F("FHRP-HSRP-01", d, "HSRP authentication configured",
                      Status.FAIL if no_auth else Status.PASS, Severity.HIGH, evidence=no_auth,
                      evidence_label="HSRP interfaces without authentication",
                      recommendation="Configure 'standby <grp> authentication md5 key-string <key>' on every HSRP group.",
                      fix_command="interface <interface>\n"
                                  " standby <group> authentication md5 key-string <strong-key>\n"
                                  "! Repeat for each interface/group listed above."))
        out.append(F("FHRP-HSRP-02", d, "HSRP authentication uses MD5 (not plaintext)",
                      Status.FAIL if plaintext else (Status.PASS if not no_auth else Status.NA),
                      Severity.MEDIUM, evidence=plaintext,
                      evidence_label="HSRP interfaces using plaintext authentication",
                      recommendation="Replace plaintext HSRP authentication strings with MD5-based authentication.",
                      fix_command="interface <interface>\n"
                                  " standby <group> authentication md5 key-string <strong-key>"))

    vrrp_intfs = [b for b in cfg.interfaces() if b.has(r"vrrp \d+ ")]
    if vrrp_intfs:
        no_auth_v = [ifname(b.header) for b in vrrp_intfs if not b.has(r"vrrp \d+ authentication")]
        out.append(F("FHRP-VRRP-01", d, "VRRP authentication configured",
                      Status.FAIL if no_auth_v else Status.PASS, Severity.MEDIUM, evidence=no_auth_v,
                      evidence_label="VRRP interfaces without authentication",
                      recommendation="Configure VRRP authentication where the platform/version supports it "
                                     "(note: authentication was removed from later VRRPv3 RFCs -- rely on "
                                     "network segmentation if unsupported).",
                      fix_command="interface <interface>\n vrrp <group> authentication text <key>"))

    if not hsrp_intfs and not vrrp_intfs:
        out.append(F("FHRP-00", d, "No FHRP (HSRP/VRRP) detected in running-config", Status.NA, Severity.INFO))
    return out


def check_icmp_hardening(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / ICMP & IP Hardening"
    out: list[Finding] = []
    external_intfs = [b for b in cfg.physical_interfaces() if b.has(r"ip address")]

    no_redirects = [ifname(b.header) for b in external_intfs if not b.has(r"no ip redirects")]
    out.append(F("ICMP-01", d, "ICMP redirects disabled on routed interfaces",
                  Status.FAIL if no_redirects else (Status.PASS if external_intfs else Status.NA),
                  Severity.MEDIUM, evidence=no_redirects,
                  evidence_label="Routed interfaces still sending ICMP redirects",
                  recommendation="Configure 'no ip redirects' on routed interfaces (especially external-facing).",
                  fix_command="interface <interface>\n no ip redirects"))

    no_proxyarp = [ifname(b.header) for b in external_intfs if not b.has(r"no ip proxy-arp")]
    out.append(F("ICMP-02", d, "Proxy ARP disabled on routed interfaces (default is ON)",
                  Status.FAIL if no_proxyarp else (Status.PASS if external_intfs else Status.NA),
                  Severity.MEDIUM, evidence=no_proxyarp,
                  evidence_label="Routed interfaces still running Proxy ARP",
                  recommendation="Configure 'no ip proxy-arp' -- Proxy ARP defaults to enabled on Cisco IOS.",
                  fix_command="interface <interface>\n no ip proxy-arp"))

    no_unreach = [ifname(b.header) for b in external_intfs if not b.has(r"no ip unreachables")]
    out.append(F("ICMP-03", d, "ICMP unreachables disabled where appropriate",
                  Status.FAIL if no_unreach else (Status.PASS if external_intfs else Status.NA),
                  Severity.LOW, evidence=no_unreach,
                  evidence_label="Routed interfaces still sending ICMP unreachables",
                  recommendation="Configure 'no ip unreachables' on internet-facing interfaces to reduce recon/DoS surface.",
                  fix_command="interface <interface>\n no ip unreachables"))

    src_route = cfg.search(r"^no ip source-route\b")
    out.append(F("ICMP-04", d, "IP source-routing disabled globally",
                  Status.PASS if src_route else Status.FAIL, Severity.MEDIUM,
                  recommendation="Configure 'no ip source-route' globally.",
                  fix_command="no ip source-route"))

    tcp_intercept = cfg.search(r"^ip tcp intercept")
    out.append(F("ICMP-05", d, "TCP Intercept / SYN-flood protection reviewed",
                  Status.MANUAL, Severity.LOW,
                  detail=f"{'Configured' if tcp_intercept else 'Not configured'} -- only relevant on devices "
                          "actually fronting server subnets.",
                  recommendation="Configure 'ip tcp intercept' where this device protects server-side TCP endpoints."))
    return out


def check_acl_analysis(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / ACL Analysis"
    out: list[Finding] = []

    named_acls = cfg.get_blocks("ip access-list extended", "ip access-list standard")
    if not named_acls:
        out.append(F("ACL-00", d, "No named IP ACLs found in running-config", Status.NA, Severity.INFO))
        return out

    # Build the set of ACL names referenced anywhere else in the config.
    # This is necessarily a heuristic -- an ACL can be referenced from many
    # contexts (route-maps, NAT, crypto maps, ip tcp intercept, etc.) and this
    # list won't be exhaustive; false "unused" positives are possible, which
    # is why this check is LOW severity rather than HIGH/CRITICAL.
    referenced_names = set()
    ref_patterns = [
        r"ip access-group (\S+)", r"access-class (\S+)", r"match access-group name (\S+)",
        r"match access-group (\d+)", r"match address (\S+)", r"distribute-list (\S+)",
        r"ip tcp intercept list (\S+)", r"ip nat \S+ source list (\S+)",
        r"crypto map \S+ \d+ ipsec-isakmp[\s\S]{0,80}?match address (\S+)",
    ]
    for pat in ref_patterns:
        for m in re.finditer(pat, cfg.text, re.I):
            referenced_names.add(m.group(1))

    unused = []
    permissive = []
    dup_rules = []
    missing_log = []

    for blk in named_acls:
        name = blk.name().split()[-1] if blk.name() else blk.header
        if name not in referenced_names:
            unused.append(name)

        seen = set()
        for line in blk.lines:
            norm = re.sub(r"\s+", " ", line.strip().lower())
            if norm in seen:
                dup_rules.append(f"{name}:  {line.strip()}")
            seen.add(norm)
            if re.search(r"^permit ip any any\s*$", line.strip(), re.I):
                permissive.append(f"{name}:  {line.strip()}")
            if re.match(r"^deny ", line.strip(), re.I) and "log" not in line.lower():
                missing_log.append(f"{name}:  {line.strip()}")

    out.append(F("ACL-01", d, "Named ACLs are referenced somewhere in the config (not orphaned)",
                  Status.FAIL if unused else Status.PASS, Severity.LOW, evidence=unused,
                  evidence_label="ACLs defined but not referenced anywhere else in the config",
                  recommendation="Remove unused ACLs, or apply them if they were meant to be in use.",
                  fix_command="no ip access-list extended <acl-name>\n"
                              "! Remove if genuinely unused, or apply it where intended, e.g.:\n"
                              "interface <interface>\n ip access-group <acl-name> in"))
    out.append(F("ACL-02", d, "No unrestricted 'permit ip any any' entries",
                  Status.FAIL if permissive else Status.PASS, Severity.HIGH, evidence=permissive,
                  evidence_label="Overly permissive entries found",
                  recommendation="Replace broad 'permit ip any any' with the minimum necessary scope.",
                  fix_command="ip access-list extended <acl-name>\n"
                              " no permit ip any any\n"
                              " permit <protocol> <specific-source> <specific-destination> [eq <port>]\n"
                              "! Replace with the narrowest rule that satisfies the actual requirement."))
    out.append(F("ACL-03", d, "No exact-duplicate ACL entries",
                  Status.FAIL if dup_rules else Status.PASS, Severity.LOW, evidence=dup_rules,
                  evidence_label="Duplicate rules found",
                  recommendation="Remove duplicate ACEs -- they add no value and complicate review.",
                  fix_command="ip access-list extended <acl-name>\n"
                              " no <sequence-number-of-duplicate-line>\n"
                              "! Use 'show access-list <acl-name>' to get sequence numbers, then remove the duplicate(s)."))
    out.append(F("ACL-04", d, "Deny entries include 'log' where visibility is expected",
                  Status.MANUAL, Severity.LOW, evidence=missing_log,
                  evidence_label="Deny entries without 'log'",
                  detail="Flagged for review rather than a hard fail -- logging every deny can itself create a "
                          "CPU/log-volume risk (see Control Plane / High-CPU-Risk section).",
                  recommendation="Add 'log' selectively to deny rules where you specifically want visibility, "
                                 "not universally."))
    out.append(F("ACL-05", d, "Shadowed / fully-unreachable rule detection",
                  Status.MANUAL, Severity.INFO,
                  detail="Full shadow/unreachable-rule analysis requires wildcard-to-CIDR conversion and "
                          "protocol/port range overlap logic -- not implemented in this version. Roadmap item.",
                  recommendation="Review ACL rule order manually, most-specific-first, until this is automated."))
    return out


def check_object_tracking(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Layer 3 / Object Tracking"
    out: list[Finding] = []
    track_blocks = cfg.get_blocks("track ")
    if not track_blocks:
        out.append(F("TRACK-00", d, "No object tracking configured", Status.NA, Severity.INFO))
        return out

    sla_defs = {m for m in re.findall(r"^ip sla (\d+)", cfg.text, re.M | re.I)}
    broken = []
    unused = []
    all_refs = cfg.text
    for blk in track_blocks:
        track_id_m = re.match(r"track (\d+)", blk.header, re.I)
        track_id = track_id_m.group(1) if track_id_m else "?"
        sla_ref = blk.find(r"ip sla (\d+)") or re.match(r"track \d+ ip sla (\d+)", blk.header, re.I)
        if sla_ref:
            sla_num = sla_ref.group(1)
            if sla_num not in sla_defs:
                broken.append(f"{blk.header}: references non-existent 'ip sla {sla_num}'")
        if not re.search(rf"\btrack {re.escape(track_id)}\b", all_refs.replace(blk.header, "", 1)):
            unused.append(blk.header)

    out.append(F("TRACK-01", d, "Tracked objects reference an existing IP SLA entry",
                  Status.FAIL if broken else Status.PASS, Severity.HIGH, evidence=broken,
                  evidence_label="Track objects with a broken IP SLA reference",
                  recommendation="Fix or remove track objects pointing at a non-existent IP SLA -- the dependent "
                                 "FHRP/routing failover silently will not work.",
                  fix_command="ip sla <sla-number>\n"
                              " icmp-echo <target-ip>\n"
                              " frequency 10\n"
                              "ip sla schedule <sla-number> life forever start-time now\n"
                              "! Create the missing IP SLA entry referenced by the track object, or remove the track object."))
    out.append(F("TRACK-02", d, "No unused/orphaned track objects",
                  Status.FAIL if unused else Status.PASS, Severity.INFO, evidence=unused,
                  evidence_label="Track objects not referenced anywhere",
                  recommendation="Remove track objects that nothing (HSRP/VRRP/route) actually references.",
                  fix_command="no track <track-id>"))
    return out


LAYER3_CHECKS = [check_urpf, check_routing_auth, check_fhrp, check_icmp_hardening, check_acl_analysis, check_object_tracking]
