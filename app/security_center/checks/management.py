"""
app.security_center.checks.management
========================================
Management Plane domain: AAA, local users, SSH/VTY, HTTP(S), SNMP,
NTP, logging, banners, DNS, MPP, the service exposure matrix, and
password security. Migrated verbatim from cisco-ios-security-auditor's
cisco_audit.py (12 check functions, 49 individual `F(...)` findings),
verified against the real, complete source -- not a summary of it.

Every check function keeps the exact signature the original registry
expects: `(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]`.
"""
from __future__ import annotations

import re

from ..engine.context import Context
from ..engine.finding import F, Finding, Severity, Status
from ..parser.cisco_config import CiscoConfig


def check_aaa_and_users(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / AAA"
    out: list[Finding] = []

    aaa_new_model = cfg.search(r"^aaa new-model\b")
    out.append(F("AAA-01", d, "AAA framework enabled (aaa new-model)",
                  Status.PASS if aaa_new_model else Status.FAIL,
                  Severity.CRITICAL,
                  recommendation="Enable 'aaa new-model' as the foundation for centralized AuthN/AuthZ/Acct.",
                  fix_command="aaa new-model"))

    login_lines = cfg.search_lines(r"^aaa authentication login")
    uses_group = any(re.search(r"group (tacacs\+|radius)", l, re.I) for l in login_lines)
    has_local_fallback = any(re.search(r"\blocal\b", l, re.I) for l in login_lines)
    out.append(F("AAA-02", d, "Login authentication uses centralized AAA (TACACS+/RADIUS)",
                  Status.PASS if uses_group else Status.FAIL,
                  Severity.HIGH, evidence=login_lines,
                  evidence_label="Current 'aaa authentication login' lines",
                  recommendation="Use 'aaa authentication login default group tacacs+ local' (or radius).",
                  fix_command="aaa authentication login default group tacacs+ local"))

    if uses_group:
        out.append(F("AAA-03", d, "Local fallback configured for AAA login",
                      Status.PASS if has_local_fallback else Status.FAIL,
                      Severity.MEDIUM, evidence=login_lines,
                      evidence_label="Current 'aaa authentication login' lines",
                      recommendation="Add 'local' as a fallback method in case TACACS+/RADIUS servers are unreachable.",
                      fix_command="aaa authentication login default group tacacs+ local"))

    authz_cmds = cfg.search(r"^aaa authorization commands")
    out.append(F("AAA-04", d, "Command authorization configured",
                  Status.PASS if authz_cmds else Status.FAIL,
                  Severity.LOW,
                  recommendation="Configure 'aaa authorization commands <level> default group tacacs+ local'.",
                  fix_command="aaa authorization commands 15 default group tacacs+ local"))

    authz_cfg_cmds = cfg.search(r"^aaa authorization config-commands")
    out.append(F("AAA-05", d, "Config-command authorization configured",
                  Status.PASS if authz_cfg_cmds else Status.FAIL,
                  Severity.LOW,
                  recommendation="Configure 'aaa authorization config-commands' to gate configuration changes.",
                  fix_command="aaa authorization config-commands"))

    acct_cmds = cfg.search(r"^aaa accounting commands")
    out.append(F("AAA-06", d, "Command accounting configured",
                  Status.PASS if acct_cmds else Status.FAIL,
                  Severity.LOW,
                  recommendation="Configure command accounting for audit trail of privileged actions.",
                  fix_command="aaa accounting commands 15 default start-stop group tacacs+"))

    acct_exec = cfg.search(r"^aaa accounting exec")
    out.append(F("AAA-07", d, "EXEC accounting configured",
                  Status.PASS if acct_exec else Status.FAIL,
                  Severity.LOW,
                  recommendation="Configure 'aaa accounting exec default start-stop group tacacs+'.",
                  fix_command="aaa accounting exec default start-stop group tacacs+"))

    lockout = cfg.search(r"^aaa local authentication attempts max-fail")
    out.append(F("AAA-08", d, "Local account lockout after repeated failures",
                  Status.PASS if lockout else Status.FAIL,
                  Severity.MEDIUM,
                  recommendation="Configure 'aaa local authentication attempts max-fail <n>'.",
                  fix_command="aaa local authentication attempts max-fail 5"))

    weak_secrets = policy["weak_shared_secrets"]
    suspect_keys = []
    for blk in cfg.get_blocks("tacacs server", "radius server"):
        m = blk.find(r"key\s+(?:\d\s+)?(\S+)")
        if m:
            secret = m.group(1)
            if secret.lower() in weak_secrets or len(secret) < policy["tacacs_radius_key_min_length"]:
                suspect_keys.append(f"{blk.name()}: key length/strength looks weak")
    legacy_key_lines = cfg.search_lines(r"^(tacacs-server|radius-server) key\s")
    out.append(F("AAA-09", d, "TACACS+/RADIUS shared secret strength",
                  Status.FAIL if (suspect_keys or legacy_key_lines) else Status.PASS,
                  Severity.HIGH,
                  evidence=suspect_keys + legacy_key_lines,
                  evidence_label="Weak or legacy-style shared secrets found",
                  recommendation="Use long, random shared secrets; avoid legacy global 'tacacs-server key' / "
                                 "'radius-server key' in favor of per-server keys under 'tacacs server'/'radius server'.",
                  fix_command="tacacs server <name>\n"
                              " address ipv4 <ip>\n"
                              " key <long-random-secret>\n"
                              "! Migrate off any global 'tacacs-server key' / 'radius-server key' lines."))

    has_enable_password = cfg.search(r"^enable password\b")
    has_enable_secret = cfg.search(r"^enable secret\b")
    out.append(F("AAA-10", d, "No legacy 'enable password' in use",
                  Status.FAIL if has_enable_password else Status.PASS,
                  Severity.CRITICAL,
                  recommendation="Remove 'enable password'; use 'enable secret' with a strong hash algorithm.",
                  fix_command="no enable password\nenable algorithm-type scrypt secret <strong-secret>"))

    if has_enable_secret:
        weak_secret = cfg.search(r"^enable secret 5\b") or cfg.search(r"^enable secret 0\b")
        out.append(F("AAA-11", d, "Enable secret uses a strong hash algorithm (Type 8/9)",
                      Status.FAIL if weak_secret else Status.PASS,
                      Severity.HIGH,
                      recommendation="Use 'enable algorithm-type scrypt secret ...' (Type 9) or SHA-256 (Type 8) "
                                     "instead of Type 5 (MD5) or plaintext.",
                      fix_command="enable algorithm-type scrypt secret <strong-secret>"))

    ctx.set("aaa_new_model", aaa_new_model)
    return out


def check_local_users(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / Local Users"
    out: list[Finding] = []

    user_lines = cfg.search_lines(r"^username \S+ ")
    weak_type_users = []
    generic_users = []
    priv15_users = []
    generic_list = policy["generic_usernames"]

    for line in user_lines:
        m = re.match(r"^username (\S+)", line, re.I)
        if not m:
            continue
        uname = m.group(1)
        if uname.lower() in generic_list:
            generic_users.append(uname)
        type_m = re.search(r"(secret|password)\s+(\d+)\s", line, re.I)
        if type_m and type_m.group(2) in ("0", "5", "7"):
            weak_type_users.append(f"{uname}  (type {type_m.group(2)})")
        if re.search(r"privilege 15", line, re.I):
            priv15_users.append(uname)

    out.append(F("USR-01", d, "Local accounts use strong secret type (Type 8/9, not 0/5/7)",
                  Status.FAIL if weak_type_users else (Status.PASS if user_lines else Status.NA),
                  Severity.HIGH, evidence=weak_type_users,
                  evidence_label="Accounts using a weak/reversible secret type",
                  recommendation="Recreate accounts with 'username <name> privilege <n> algorithm-type scrypt secret <pw>'.",
                  fix_command="no username <name>\n"
                              "username <name> privilege <n> algorithm-type scrypt secret <strong-password>\n"
                              "! Repeat for each account listed above."))
    out.append(F("USR-02", d, "No generic/default local usernames (admin, cisco, test, ...)",
                  Status.FAIL if generic_users else (Status.PASS if user_lines else Status.NA),
                  Severity.HIGH, evidence=generic_users,
                  evidence_label="Generic/default account names found",
                  recommendation="Rename generic accounts to named, individually-attributable accounts.",
                  fix_command="no username <generic-name>\n"
                              "username <first.last> privilege <n> algorithm-type scrypt secret <strong-password>"))
    out.append(F("USR-03", d, f"Privilege-15 local account count ({len(priv15_users)})",
                  Status.PASS,
                  Severity.INFO, evidence=priv15_users,
                  evidence_label="Privilege-15 accounts found",
                  recommendation="Review whether every privilege-15 local account is still required; "
                                 "prefer AAA-based authorization over broad local privilege 15."))
    return out


def check_ssh_and_vty(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / SSH & VTY"
    out: list[Finding] = []

    ssh_v2 = cfg.search(r"^ip ssh version 2\b")
    out.append(F("SSH-01", d, "SSH version 2 explicitly configured",
                  Status.PASS if ssh_v2 else Status.FAIL,
                  Severity.HIGH,
                  recommendation="Configure 'ip ssh version 2'.",
                  fix_command="ip ssh version 2"))

    vty_blocks = cfg.get_blocks("line vty")
    telnet_allowed = False
    telnet_allowed_lines = []
    vty_without_acl = []
    vty_no_timeout = []
    ssh_enabled_anywhere = ssh_v2 or cfg.search(r"^ip ssh ")

    for blk in vty_blocks:
        transport = blk.find(r"transport input (\S.*)")
        if transport and re.search(r"\btelnet\b", transport.group(1), re.I):
            telnet_allowed = True
            telnet_allowed_lines.append(blk.header)
        if not blk.has(r"access-class \S+ in"):
            vty_without_acl.append(blk.header)
        timeout_m = blk.find(r"exec-timeout (\d+) (\d+)")
        if not timeout_m or (timeout_m.group(1) == "0" and timeout_m.group(2) == "0"):
            vty_no_timeout.append(blk.header)

    out.append(F("SSH-02", d, "Telnet disabled on all VTY lines",
                  Status.FAIL if telnet_allowed else Status.PASS,
                  Severity.CRITICAL, evidence=telnet_allowed_lines,
                  evidence_label="VTY line blocks that still allow Telnet",
                  recommendation="Set 'transport input ssh' only on every VTY line block.",
                  fix_command="line vty 0 15\n transport input ssh\n! Repeat for each VTY block listed above."))

    vty_acl_present = bool(vty_blocks) and not vty_without_acl
    out.append(F("SSH-03", d, "VTY lines restricted by access-class ACL",
                  Status.FAIL if vty_without_acl else (Status.PASS if vty_blocks else Status.NA),
                  Severity.HIGH, evidence=vty_without_acl,
                  evidence_label="VTY line blocks with no access-class ACL",
                  recommendation="Apply 'access-class <mgmt-acl> in' to every VTY line block.",
                  fix_command="ip access-list standard MGMT-ACL\n"
                              " permit <trusted-mgmt-subnet> <wildcard-mask>\n"
                              "!\n"
                              "line vty 0 15\n"
                              " access-class MGMT-ACL in\n"
                              "! Repeat the access-class line for each VTY block listed above."))
    out.append(F("SSH-04", d, "VTY exec-timeout configured (not 0 0 / infinite)",
                  Status.FAIL if vty_no_timeout else (Status.PASS if vty_blocks else Status.NA),
                  Severity.MEDIUM, evidence=vty_no_timeout,
                  evidence_label="VTY line blocks with no bounded exec-timeout",
                  recommendation=f"Set 'exec-timeout' on VTY lines to <= {policy['vty_exec_timeout_max_minutes']} minutes.",
                  fix_command=f"line vty 0 15\n exec-timeout {policy['vty_exec_timeout_max_minutes']} 0"))

    ssh_timeout_m = re.search(r"^ip ssh time-out (\d+)", cfg.text, re.M | re.I)
    ssh_timeout_ok = bool(ssh_timeout_m) and int(ssh_timeout_m.group(1)) <= policy["ssh_timeout_max_seconds"]
    out.append(F("SSH-05", d, "SSH session timeout configured and bounded",
                  Status.PASS if ssh_timeout_ok else Status.FAIL,
                  Severity.LOW,
                  recommendation=f"Configure 'ip ssh time-out <= {policy['ssh_timeout_max_seconds']}'.",
                  fix_command=f"ip ssh time-out {policy['ssh_timeout_max_seconds']}"))

    retries_m = re.search(r"^ip ssh authentication-retries (\d+)", cfg.text, re.M | re.I)
    retries_ok = bool(retries_m) and int(retries_m.group(1)) <= policy["ssh_auth_retries_max"]
    out.append(F("SSH-06", d, "SSH authentication retry limit configured",
                  Status.PASS if retries_ok else Status.FAIL,
                  Severity.LOW,
                  recommendation=f"Configure 'ip ssh authentication-retries <= {policy['ssh_auth_retries_max']}'.",
                  fix_command=f"ip ssh authentication-retries {policy['ssh_auth_retries_max']}"))

    out.append(F("SSH-07", d, "RSA/ECDSA key size >= policy minimum",
                  Status.MANUAL, Severity.MEDIUM,
                  detail="Key modulus is generally set via the interactive 'crypto key generate rsa modulus <n>' "
                          "exec command and is usually NOT reflected in running-config text. Verify separately with "
                          "'show crypto key mypubkey rsa' on the live device.",
                  recommendation=f"Confirm RSA key size is >= {policy['min_rsa_key_bits']} bits (or ECDSA in use)."))

    algo_restricted = cfg.search(r"^ip ssh server algorithm (kex|encryption|mac)")
    out.append(F("SSH-08", d, "SSH KEX/cipher/MAC algorithms explicitly restricted",
                  Status.PASS if algo_restricted else Status.FAIL,
                  Severity.LOW,
                  recommendation="Restrict 'ip ssh server algorithm kex|encryption|mac' to modern, strong algorithms only.",
                  fix_command="ip ssh server algorithm kex ecdh-sha2-nistp256 diffie-hellman-group16-sha512\n"
                              "ip ssh server algorithm encryption aes256-ctr aes256-gcm\n"
                              "ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-512"))

    ctx.set("ssh_enabled", ssh_enabled_anywhere)
    ctx.set("telnet_enabled", telnet_allowed)
    ctx.set("vty_acl_present", vty_acl_present)
    return out


def check_http(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / HTTP(S)"
    out: list[Finding] = []

    http_disabled = cfg.search(r"^no ip http server\b")
    http_enabled = cfg.search(r"^ip http server\b")
    out.append(F("HTTP-01", d, "HTTP server disabled",
                  Status.FAIL if (http_enabled and not http_disabled) else Status.PASS,
                  Severity.HIGH,
                  recommendation="Configure 'no ip http server'; use HTTPS only if a WebUI is required.",
                  fix_command="no ip http server"))

    https_enabled = cfg.search(r"^ip http secure-server\b")
    if https_enabled:
        acl_ref = re.search(r"^ip http access-class \S+", cfg.text, re.M | re.I)
        out.append(F("HTTP-02", d, "HTTPS server restricted by ACL",
                      Status.PASS if acl_ref else Status.FAIL,
                      Severity.MEDIUM,
                      recommendation="Apply 'ip http access-class <mgmt-acl>' when HTTPS/WebUI is enabled.",
                      fix_command="ip http access-class MGMT-ACL"))
    return out


def check_snmp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / SNMP"
    out: list[Finding] = []

    default_comm = cfg.search_lines(r"^snmp-server community (public|private)\b")
    out.append(F("SNMP-01", d, "No default community strings (public/private)",
                  Status.FAIL if default_comm else Status.PASS,
                  Severity.CRITICAL, evidence=default_comm,
                  evidence_label="Default community strings found",
                  recommendation="Remove default community strings immediately; migrate to SNMPv3.",
                  fix_command="no snmp-server community public\nno snmp-server community private"))

    v3_groups = cfg.search_lines(r"^snmp-server group \S+ v3")
    any_v2c_community = cfg.search(r"^snmp-server community \S+")
    community_lines = cfg.search_lines(r"^snmp-server community \S+")
    snmpv3_configured = bool(v3_groups)
    out.append(F("SNMP-02", d, "SNMPv3 in use (not v1/v2c community strings)",
                  Status.PASS if (snmpv3_configured and not any_v2c_community) else
                  (Status.FAIL if any_v2c_community else Status.NA),
                  Severity.HIGH, evidence=community_lines,
                  evidence_label="Remaining v1/v2c community strings",
                  recommendation="Migrate fully to SNMPv3 with auth+priv; remove all v1/v2c community strings.",
                  fix_command="no snmp-server community <string>\n"
                              "snmp-server group SNMP-ADMINS v3 priv\n"
                              "snmp-server user <name> SNMP-ADMINS v3 auth sha <auth-pass> priv aes 256 <priv-pass>"))

    noauth_users = cfg.search_lines(r"^snmp-server user \S+ \S+ v3 noauth")
    out.append(F("SNMP-03", d, "SNMPv3 users configured with auth+priv (not noauth)",
                  Status.FAIL if noauth_users else (Status.PASS if v3_groups else Status.NA),
                  Severity.HIGH, evidence=noauth_users,
                  evidence_label="SNMPv3 users configured without auth/priv",
                  recommendation="Configure SNMPv3 users with 'auth <algo> ... priv <algo> ...', avoid 'noauth'.",
                  fix_command="no snmp-server user <name> <group> v3\n"
                              "snmp-server user <name> <group> v3 auth sha <auth-pass> priv aes 256 <priv-pass>"))

    snmp_lines = cfg.search_lines(r"^snmp-server (community|host)")
    out.append(F("SNMP-04", d, "SNMP access restricted by ACL",
                  Status.MANUAL, Severity.MEDIUM, evidence=snmp_lines,
                  evidence_label="Current SNMP community/host lines (verify ACL binding manually)",
                  detail="Heuristic only -- verify manually whether an access-list is bound to the "
                          "community/group/host lines above.",
                  recommendation="Bind an ACL to 'snmp-server community'/'group'/'host' restricting source hosts.",
                  fix_command="ip access-list standard SNMP-ACL\n permit <trusted-nms-subnet> <wildcard-mask>\n!\n"
                              "snmp-server community <string> RO SNMP-ACL"))

    ctx.set("snmpv3_configured", snmpv3_configured and not any_v2c_community)
    ctx.set("snmp_acl_present", None)  # left as manual review; not used in a hard correlation rule
    return out


def check_ntp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / NTP"
    out: list[Finding] = []

    ntp_auth = cfg.search(r"^ntp authenticate\b")
    out.append(F("NTP-01", d, "NTP authentication enabled", Status.PASS if ntp_auth else Status.FAIL,
                  Severity.MEDIUM, recommendation="Configure 'ntp authenticate' with a trusted key.",
                  fix_command="ntp authenticate"))

    ntp_key = cfg.search(r"^ntp authentication-key \d+ md5")
    out.append(F("NTP-02", d, "NTP authentication key configured", Status.PASS if ntp_key else Status.FAIL,
                  Severity.MEDIUM, recommendation="Configure 'ntp authentication-key <id> md5 <key>' + 'ntp trusted-key <id>'.",
                  fix_command="ntp authentication-key 1 md5 <strong-key>\nntp trusted-key 1"))

    ntp_servers = cfg.search_lines(r"^ntp server \S+")
    out.append(F("NTP-03", d, "At least one NTP server configured",
                  Status.PASS if ntp_servers else Status.FAIL, Severity.LOW, evidence=ntp_servers,
                  evidence_label="Current NTP server lines",
                  recommendation="Configure at least two trusted NTP servers for accurate log correlation.",
                  fix_command="ntp server <trusted-ntp-server-1>\nntp server <trusted-ntp-server-2>"))

    ntp_acl = cfg.search(r"^ntp access-group")
    out.append(F("NTP-04", d, "NTP access restricted by ACL", Status.PASS if ntp_acl else Status.FAIL,
                  Severity.LOW, recommendation="Configure 'ntp access-group peer|query-only <acl>'.",
                  fix_command="ip access-list standard NTP-ACL\n permit <trusted-ntp-server>\n!\nntp access-group peer NTP-ACL"))
    return out


def check_logging(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / Logging"
    out: list[Finding] = []

    log_host = cfg.search_lines(r"^logging (host )?\S+")
    out.append(F("LOG-01", d, "Remote syslog host(s) configured",
                  Status.PASS if log_host else Status.FAIL, Severity.HIGH, evidence=log_host,
                  evidence_label="Current logging destination lines",
                  recommendation="Configure 'logging host <syslog-server>'.",
                  fix_command="logging host <syslog-server-ip>"))

    ts = cfg.search(r"^service timestamps")
    out.append(F("LOG-02", d, "Timestamps enabled on log/debug messages",
                  Status.PASS if ts else Status.FAIL, Severity.LOW,
                  recommendation="Configure 'service timestamps log datetime msec localtime show-timezone'.",
                  fix_command="service timestamps log datetime msec localtime show-timezone\n"
                              "service timestamps debug datetime msec localtime show-timezone"))

    on_fail = cfg.search(r"^login on-failure log")
    on_success = cfg.search(r"^login on-success log")
    out.append(F("LOG-03", d, "Failed login attempts logged", Status.PASS if on_fail else Status.FAIL,
                  Severity.MEDIUM, recommendation="Configure 'login on-failure log'.",
                  fix_command="login on-failure log"))
    out.append(F("LOG-04", d, "Successful login attempts logged", Status.PASS if on_success else Status.FAIL,
                  Severity.LOW, recommendation="Configure 'login on-success log'.",
                  fix_command="login on-success log"))
    return out


def check_banners(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / Banners"
    out: list[Finding] = []

    has_login_or_motd = "login" in cfg.banners or "motd" in cfg.banners
    out.append(F("BAN-01", d, "Login/MOTD banner present",
                  Status.PASS if has_login_or_motd else Status.FAIL, Severity.LOW,
                  recommendation="Configure a login/MOTD banner with an appropriate legal notice.",
                  fix_command="banner login ^\n"
                              "Authorized access only. All activity may be monitored and reported.\n"
                              "^"))
    return out


def check_dns(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / DNS"
    out: list[Finding] = []

    lookup_enabled = cfg.search(r"^ip domain lookup\b") and not cfg.search(r"^no ip domain lookup\b")
    name_servers = cfg.search_lines(r"^ip name-server\b")
    if not lookup_enabled:
        out.append(F("DNS-01", d, "DNS lookup posture", Status.PASS, Severity.INFO,
                      detail="'ip domain lookup' is disabled (or not enabled) -- lowest-risk posture.",
                      recommendation="No action needed unless DNS resolution is actually required."))
    elif name_servers:
        out.append(F("DNS-01", d, "DNS lookup enabled with explicit trusted name-server(s)",
                      Status.PASS, Severity.INFO, evidence=name_servers,
                      evidence_label="Configured name-servers",
                      recommendation="Confirm the configured name-servers are trusted, internal resolvers."))
    else:
        out.append(F("DNS-01", d, "DNS lookup enabled without an explicit trusted name-server",
                      Status.FAIL, Severity.MEDIUM,
                      recommendation="Either disable 'ip domain lookup' or configure explicit trusted 'ip name-server' entries.",
                      fix_command="ip name-server <trusted-internal-dns-server>\n"
                                  "! OR, if DNS resolution isn't actually needed:\n"
                                  "no ip domain lookup"))
    return out


def check_mpp(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / MPP"
    out: list[Finding] = []

    mpp = cfg.search(r"^management-interface \S+ allow")
    out.append(F("MPP-01", d, "Management Plane Protection (MPP) configured",
                  Status.PASS if mpp else Status.NA, Severity.LOW,
                  recommendation="Optional hardening: restrict management protocols to a specific interface via MPP.",
                  fix_command="control-plane host\n"
                              " management-interface <mgmt-interface> allow ssh https snmp"))
    return out


def check_mgmt_exposure_matrix(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Management Plane / Exposure Matrix"
    out: list[Finding] = []

    probes = [
        ("EXP-RESTCONF", "RESTCONF", r"^restconf\b", Severity.MEDIUM, "no restconf"),
        ("EXP-NETCONF", "NETCONF-YANG", r"^netconf-yang\b", Severity.MEDIUM, "no netconf-yang"),
        ("EXP-GNMI", "gNMI", r"\bgnmi-yang\b|\bgnmi\s", Severity.MEDIUM, "no gnmi-yang"),
        ("EXP-IOX", "IOx / App-Hosting", r"^iox\b", Severity.LOW, "no iox"),
        ("EXP-TFTP", "TFTP server", r"^tftp-server\b", Severity.HIGH, "no tftp-server"),
        ("EXP-FTP", "FTP server", r"^ftp-server enable\b", Severity.HIGH, "no ftp-server enable"),
        ("EXP-SCP", "SCP server", r"^ip scp server enable\b", Severity.LOW, "no ip scp server enable"),
    ]

    iox_present = False
    for check_id, label, pattern, sev, disable_cmd in probes:
        found = cfg.search(pattern)
        if check_id == "EXP-IOX":
            iox_present = found
        if not found:
            out.append(F(check_id, d, f"{label}: not enabled", Status.PASS, Severity.INFO))
            continue
        out.append(F(check_id, d, f"{label} is enabled -- confirm ACL/VRF/AuthN/Encryption are all in place",
                      Status.FAIL, sev,
                      recommendation=f"If {label} is required, restrict it with an ACL/VRF and strong authentication; "
                                     f"disable it otherwise.",
                      fix_command=f"{disable_cmd}\n! Only if {label} is not actually required on this device."))

    guestshell_hint = cfg.search(r"\bguestshell\b")
    out.append(F("EXP-GUESTSHELL", d, "GuestShell reference found in config",
                  Status.MANUAL if guestshell_hint else Status.PASS,
                  Severity.LOW,
                  detail="GuestShell is normally enabled via an exec-level command, not persisted in running-config; "
                          "this only flags incidental references (e.g. app-hosting resource profiles).",
                  recommendation="Verify GuestShell status live with 'show guestshell'; disable if unused."))

    ctx.set("guestshell_iox_present", bool(guestshell_hint) and iox_present)
    return out


def check_password_security(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Password Security"
    out: list[Finding] = []

    svc_enc = cfg.search(r"^service password-encryption\b")
    out.append(F("PWD-01", d, "service password-encryption enabled",
                  Status.PASS if svc_enc else Status.FAIL, Severity.MEDIUM,
                  recommendation="Configure 'service password-encryption' as a baseline (Type 7 is weak but "
                                 "better than plaintext for legacy password types).",
                  fix_command="service password-encryption"))

    type7 = cfg.search_lines(r"password 7 \S+")
    out.append(F("PWD-02", d, "No Type 7 (reversible) passwords in use",
                  Status.FAIL if type7 else Status.PASS, Severity.HIGH, evidence=type7,
                  evidence_label="Lines using Type 7 (reversible) passwords",
                  recommendation="Migrate any Type 7 passwords to Type 8/9 secrets or Type 6 (AES) where applicable.",
                  fix_command="! For local user accounts:\n"
                              "username <name> algorithm-type scrypt secret <strong-password>\n"
                              "! For protocol keys (routing/NTP/etc.), use Type 6 instead:\n"
                              "key config-key password-encrypt <master-key>\npassword encryption aes"))

    type5 = cfg.search_lines(r"(secret|password) 5 \S+")
    out.append(F("PWD-03", d, "No Type 5 (MD5, weak) secrets in use",
                  Status.FAIL if type5 else Status.PASS, Severity.MEDIUM, evidence=type5,
                  evidence_label="Lines using Type 5 (MD5) secrets",
                  recommendation="Migrate Type 5 secrets to Type 8/9 (scrypt/SHA-256).",
                  fix_command="enable algorithm-type scrypt secret <strong-secret>\n"
                              "username <name> algorithm-type scrypt secret <strong-password>"))

    min_len = cfg.search(r"^security passwords min-length")
    out.append(F("PWD-04", d, "Minimum password length policy enforced",
                  Status.PASS if min_len else Status.FAIL, Severity.LOW,
                  recommendation="Configure 'security passwords min-length <n>' (e.g. 12+).",
                  fix_command="security passwords min-length 12"))
    return out


MANAGEMENT_CHECKS = [
    check_aaa_and_users, check_local_users, check_ssh_and_vty, check_http, check_snmp,
    check_ntp, check_logging, check_banners, check_dns, check_mpp,
    check_mgmt_exposure_matrix, check_password_security,
]
