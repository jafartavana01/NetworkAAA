"""
app.security_center.engine.correlation
=========================================
The 10-rule correlation engine, migrated verbatim from cisco-ios-
security-auditor's cisco_audit.py 's run_correlation_engine()
(function body extracted programmatically, byte-for-byte from source
-- see app.security_center.checks.management's own module docstring
for why this project migrates by extraction rather than retyping).

Reads facts populated as a side effect by the device-level domain
checks (app.security_center.engine.context.Context) and, where a
rule's precondition facts are all present and true, emits an
additional, higher-level Finding whose check_id starts with 'CORR-'
-- distinct from and layered on top of the individual findings that
fed it, never replacing them. See this project's own migration
architecture notes on why correlated findings are surfaced separately
from their contributing individual findings in the GUI, not merged
into them.
"""
from __future__ import annotations

from .context import Context
from .finding import F, Finding, Severity, Status


def run_correlation_engine(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    """
    Reasons over the shared fact-sheet populated by domain checks above.
    Each rule here corresponds to a row in the "Rule Correlation Engine" table
    from the design discussion. Rules that depend on domains not yet implemented
    (e.g. 802.1X/MAB) are intentionally omitted rather than faked -- see MISC-07.
    """
    d = "Correlation Engine"
    out: list[Finding] = []

    if ctx.get("dhcp_snooping_enabled") and not ctx.get("dai_enabled"):
        out.append(F("CORR-01", d, "DHCP Snooping enabled without Dynamic ARP Inspection",
                      Status.FAIL, Severity.HIGH,
                      detail="Snooping without DAI is half a control -- the binding table exists but ARP traffic "
                              "isn't validated against it.",
                      recommendation="Enable DAI on the same VLANs where DHCP Snooping is active."))

    if ctx.get("dai_enabled") and not ctx.get("device_tracking_configured"):
        out.append(F("CORR-02", d, "DAI enabled without Device Tracking (SISF) policy",
                      Status.FAIL, Severity.MEDIUM,
                      recommendation="Configure and attach a device-tracking policy so DAI/IPSG have a "
                                     "populated, current binding table to validate against."))

    if ctx.get("ssh_enabled") and not ctx.get("vty_acl_present"):
        out.append(F("CORR-03", d, "SSH enabled with no VTY access-class ACL",
                      Status.FAIL, Severity.HIGH,
                      detail="Management plane is reachable from anywhere that can route to this device.",
                      recommendation="Apply a restrictive 'access-class' ACL to every VTY line."))

    if ctx.get("snmpv3_configured") is False and ctx.get("snmp_acl_present") is False:
        # snmp_acl_present is left as None (manual) in check_snmp; only fires if explicitly False in future versions
        out.append(F("CORR-04", d, "SNMP configured with no ACL restriction",
                      Status.FAIL, Severity.HIGH,
                      recommendation="Bind an ACL restricting SNMP access to known management hosts."))

    if ctx.get("native_vlan_changed") and ctx.get("trunk_allows_all_vlans"):
        out.append(F("CORR-05", d, "Native VLAN hardened but trunk still allows all VLANs",
                      Status.FAIL, Severity.MEDIUM,
                      detail="The native-VLAN fix was only half completed.",
                      recommendation="Prune 'switchport trunk allowed vlan' on every trunk where the native "
                                     "VLAN has already been changed."))

    if ctx.get("port_security_any_without_sticky"):
        out.append(F("CORR-06", d, "Port Security enabled without sticky MAC learning on some ports",
                      Status.FAIL, Severity.LOW,
                      recommendation="Enable sticky learning where static/dynamic learning isn't specifically required."))

    if ctx.get("copp_configured") and (ctx.get("copp_class_coverage") or 0) <= 1:
        out.append(F("CORR-07", d, "CoPP is applied but covers almost no traffic classes",
                      Status.FAIL, Severity.HIGH,
                      detail=f"Only {ctx.get('copp_class_coverage')}/8 tracked traffic categories matched.",
                      recommendation="A CoPP policy that doesn't actually classify ICMP/ARP/routing/mgmt traffic "
                                     "provides little real protection -- treat this as 'CoPP present but "
                                     "ineffective' rather than a pass."))

    pki_no_revocation = ctx.get("pki_revocation_none_or_missing") or set()
    if ctx.get("vpn_configured") and pki_no_revocation:
        out.append(F("CORR-08", d, "VPN configured with PKI trustpoint(s) lacking revocation checking",
                      Status.FAIL, Severity.HIGH,
                      evidence=list(pki_no_revocation),
                      detail="A compromised or revoked peer certificate would not be caught if the VPN's "
                              "authentication relies on one of these trustpoints.",
                      recommendation="Confirm which trustpoint(s) authenticate VPN peers and ensure "
                                     "'revocation-check crl ocsp' (not 'none' or unset) on those specifically."))

    if ctx.get("password_recovery_disabled") and ctx.get("config_register_break_enabled"):
        out.append(F("CORR-09", d, "Contradictory boot-security settings",
                      Status.FAIL, Severity.MEDIUM,
                      detail="'no service password-recovery' is set, but the config-register value still "
                              "appears to allow a console break to ROMMON.",
                      recommendation="Reconcile these two settings -- as configured they work against each other."))

    if ctx.get("guestshell_iox_present"):
        out.append(F("CORR-10", d, "Both GuestShell and IOx app-hosting surfaces appear present",
                      Status.FAIL, Severity.LOW,
                      recommendation="Review whether both application-hosting surfaces are actually needed; "
                                     "disable whichever is unused."))

    return out


