"""
app.security_center.checks.vpn
==============================
IPsec / VPN domain. Migrated verbatim from cisco-ios-security-auditor's
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


_WEAK_ENCRYPTION = re.compile(r"\b(des|3des)\b", re.I)
_WEAK_INTEGRITY = re.compile(r"\b(md5|sha1|sha)\b", re.I)  # bare 'sha' without a bit-size = SHA-1 on IOS
_WEAK_DH = re.compile(r"\bgroup (1|2|5)\b", re.I)


def check_vpn(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "IPsec VPN"
    out: list[Finding] = []

    vpn_present = (cfg.get_blocks("crypto ikev2") or cfg.get_blocks("crypto map") or
                   any(b.has(r"tunnel mode ipsec") for b in cfg.interfaces()))
    ctx.set("vpn_configured", bool(vpn_present))
    if not vpn_present:
        out.append(F("VPN-00", d, "No IPsec/VPN configuration detected in running-config",
                      Status.NA, Severity.INFO))
        return out

    proposals = cfg.get_blocks("crypto ikev2 proposal")
    weak_proposals = [b.name() for b in proposals
                       if b.has(_WEAK_ENCRYPTION) or b.has(_WEAK_INTEGRITY) or b.has(_WEAK_DH)]
    out.append(F("VPN-01", d, "IKEv2 proposals use strong encryption/integrity/DH-group",
                  Status.FAIL if weak_proposals else (Status.PASS if proposals else Status.MANUAL),
                  Severity.HIGH, evidence=weak_proposals,
                  evidence_label="IKEv2 proposals using weak algorithms",
                  recommendation="Use AES-GCM (or AES-CBC-256 + SHA-256/384/512), SHA-256+ integrity/PRF, and "
                                 "DH group 14+ (19/20/21 preferred). Avoid DES/3DES, MD5/SHA-1, and DH groups 1/2/5.",
                  fix_command="crypto ikev2 proposal <proposal-name>\n"
                              " encryption aes-gcm-256\n"
                              " prf sha384\n"
                              " group 20\n"
                              "! Replace the weak encryption/integrity/PRF/group lines shown above."))

    profiles = cfg.get_blocks("crypto ikev2 profile")
    no_dpd = [b.name() for b in profiles if not b.has(r"\bdpd\b")]
    out.append(F("VPN-02", d, "IKEv2 profiles have Dead Peer Detection (DPD) enabled",
                  Status.FAIL if no_dpd else (Status.PASS if profiles else Status.NA),
                  Severity.MEDIUM, evidence=no_dpd,
                  evidence_label="IKEv2 profiles without DPD",
                  recommendation="Configure 'dpd <interval> <retry> on-demand|periodic' in every IKEv2 profile.",
                  fix_command="crypto ikev2 profile <profile-name>\n dpd 10 5 on-demand"))

    transforms = cfg.get_blocks("crypto ipsec transform-set")
    weak_transforms = [b.name() for b in transforms
                        if b.has(_WEAK_ENCRYPTION) or b.has(r"esp-null") or b.has(r"esp-md5-hmac")]
    out.append(F("VPN-03", d, "IPsec transform-sets use strong encryption/HMAC",
                  Status.FAIL if weak_transforms else (Status.PASS if transforms else Status.MANUAL),
                  Severity.HIGH, evidence=weak_transforms,
                  evidence_label="Transform-sets using weak encryption/HMAC",
                  recommendation="Use esp-gcm (preferred) or esp-aes 256 with esp-sha256-hmac+. Avoid DES/3DES, "
                                 "esp-null, and MD5-based HMAC.",
                  fix_command="crypto ipsec transform-set <name> esp-gcm 256\nmode tunnel"))

    ipsec_profiles = cfg.get_blocks("crypto ipsec profile")
    no_pfs = [b.name() for b in ipsec_profiles if not b.has(r"set pfs")]
    out.append(F("VPN-04", d, "IPsec profiles have PFS enabled",
                  Status.FAIL if no_pfs else (Status.PASS if ipsec_profiles else Status.NA),
                  Severity.MEDIUM, evidence=no_pfs,
                  evidence_label="IPsec profiles without PFS",
                  recommendation="Configure 'set pfs group19' (or stronger) in every IPsec profile.",
                  fix_command="crypto ipsec profile <profile-name>\n set pfs group19"))

    keyring_psks = re.findall(r"pre-shared-key\s+(?:address\s+\S+\s+)?(\S+)", cfg.text, re.I)
    dup_psks = {p for p in keyring_psks if keyring_psks.count(p) > 1}
    out.append(F("VPN-05", d, "No pre-shared key reused across multiple VPN peers",
                  Status.FAIL if dup_psks else (Status.PASS if keyring_psks else Status.NA),
                  Severity.HIGH,
                  detail=f"{len(dup_psks)} PSK value(s) appear to be reused." if dup_psks else "",
                  recommendation="Use a unique PSK per peer, or migrate to certificate-based authentication.",
                  fix_command="crypto ikev2 keyring <keyring-name>\n"
                              " peer <peer-name>\n"
                              "  address <peer-ip>\n"
                              "  pre-shared-key <unique-strong-key-for-this-peer>\n"
                              "! Or migrate to 'authentication local/remote rsa-sig' with a PKI trustpoint."))

    legacy_maps = cfg.get_blocks("crypto map")
    out.append(F("VPN-06", d, "Legacy policy-based crypto-map VPN usage reviewed",
                  Status.MANUAL if legacy_maps else Status.PASS, Severity.LOW,
                  evidence=[b.name() for b in legacy_maps],
                  evidence_label="Legacy crypto maps in use",
                  recommendation="Legacy crypto-map VPNs still work but are harder to scale/troubleshoot than "
                                 "VTI/FlexVPN; consider migrating." if legacy_maps else ""))

    # Facts for correlation: does any IKEv2 profile reference a PKI trustpoint used with weak/no revocation checking?
    vpn_trustpoints = set(re.findall(r"pki trustpoint (\S+)", cfg.text, re.I))
    ctx.set("vpn_trustpoints_used", vpn_trustpoints)

    out.append(F("VPN-07", d, "Certificate expiration / CRL / OCSP reachability",
                  Status.MANUAL, Severity.INFO,
                  detail="Not visible in running-config text -- see the PKI domain and verify live with "
                          "'show crypto pki certificates'.",
                  recommendation="Cross-reference with the PKI section; supplement with a live cert dump if possible."))
    return out


VPN_CHECKS = [check_vpn]
