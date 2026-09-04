"""
app.security_center.checks.pki
==============================
Cryptography / PKI domain. Migrated verbatim from cisco-ios-security-auditor's
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


def check_pki(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Cryptography & PKI"
    out: list[Finding] = []
    trustpoints = cfg.get_blocks("crypto pki trustpoint")
    if not trustpoints:
        out.append(F("PKI-00", d, "No PKI trustpoints configured", Status.NA, Severity.INFO))
        return out

    no_revocation = []
    revocation_none = []
    self_signed = []
    weak_hash = []
    weak_key = []
    no_enrollment = []

    for blk in trustpoints:
        rc = blk.find(r"revocation-check (\S+)")
        if not rc:
            no_revocation.append(blk.name())
        elif "none" in rc.group(1).lower():
            revocation_none.append(blk.name())

        if blk.has(r"enrollment selfsigned"):
            self_signed.append(blk.name())
        elif not blk.has(r"enrollment (url|terminal|mode ra)"):
            no_enrollment.append(blk.name())

        hash_m = blk.find(r"hash (\S+)")
        if hash_m and hash_m.group(1).lower() in ("md5", "sha1"):
            weak_hash.append(f"{blk.name()}: hash {hash_m.group(1)}")

        key_m = blk.find(r"rsakeypair \S+ (\d+)")
        if key_m and int(key_m.group(1)) < policy["min_rsa_key_bits"]:
            weak_key.append(f"{blk.name()}: RSA {key_m.group(1)}-bit (< {policy['min_rsa_key_bits']})")

    out.append(F("PKI-01", d, "Revocation checking explicitly disabled (revocation-check none)",
                  Status.FAIL if revocation_none else Status.PASS, Severity.HIGH, evidence=revocation_none,
                  evidence_label="Trustpoints with revocation-check none",
                  recommendation="Avoid 'revocation-check none'; use 'crl' and/or 'ocsp' (with a sane fallback).",
                  fix_command="crypto pki trustpoint <trustpoint-name>\n revocation-check crl ocsp"))
    out.append(F("PKI-02", d, "Revocation checking explicitly configured (not left to default)",
                  Status.FAIL if no_revocation else Status.PASS, Severity.MEDIUM, evidence=no_revocation,
                  evidence_label="Trustpoints with no explicit revocation-check",
                  recommendation="Explicitly configure 'revocation-check crl ocsp' rather than relying on platform default.",
                  fix_command="crypto pki trustpoint <trustpoint-name>\n revocation-check crl ocsp"))
    out.append(F("PKI-03", d, "Self-signed certificates reviewed (expected only for internal/test use)",
                  Status.MANUAL if self_signed else Status.PASS, Severity.MEDIUM, evidence=self_signed,
                  evidence_label="Trustpoints using self-signed certificates",
                  recommendation="Confirm self-signed usage is intentional; production-facing services should use "
                                 "a CA-issued certificate."))
    out.append(F("PKI-04", d, "Trustpoints have an enrollment method configured",
                  Status.FAIL if no_enrollment else Status.PASS, Severity.LOW, evidence=no_enrollment,
                  evidence_label="Trustpoints with no enrollment method",
                  recommendation="Configure 'enrollment url/terminal/mode ra' explicitly.",
                  fix_command="crypto pki trustpoint <trustpoint-name>\n enrollment url http://<ca-server>:80"))
    out.append(F("PKI-05", d, "No weak hash algorithm (MD5/SHA-1) on trustpoints",
                  Status.FAIL if weak_hash else Status.PASS, Severity.MEDIUM, evidence=weak_hash,
                  evidence_label="Trustpoints using a weak hash algorithm",
                  recommendation="Use 'hash sha256' or stronger.",
                  fix_command="crypto pki trustpoint <trustpoint-name>\n hash sha256"))
    out.append(F("PKI-06", d, "RSA key size meets policy minimum",
                  Status.FAIL if weak_key else Status.PASS, Severity.HIGH, evidence=weak_key,
                  evidence_label="Trustpoints with an undersized RSA key",
                  recommendation=f"Use RSA >= {policy['min_rsa_key_bits']} bits, or ECDSA keypairs.",
                  fix_command=f"crypto pki trustpoint <trustpoint-name>\n rsakeypair <keypair-name> {policy['min_rsa_key_bits']}\n"
                              f"! Or use ECDSA instead: 'ecdsakeypair <keypair-name>'"))

    for item, label in ((None, "PKI-07 Certificate expiration"), (None, "PKI-08 CRL reachability"),
                         (None, "PKI-09 OCSP reachability"), (None, "PKI-10 Certificate chain completeness"),
                         (None, "PKI-11 Weak CA (issuing CA key size / signature algorithm)")):
        check_id, title = label.split(" ", 1)
        out.append(F(check_id, d, title, Status.MANUAL, Severity.INFO,
                      detail="Not visible in a running-config text export -- requires "
                              "'show crypto pki certificates [verbose]' from the live device.",
                      recommendation="Capture and review 'show crypto pki certificates verbose' alongside this audit."))

    ctx.set("pki_trustpoints", {b.name() for b in trustpoints})
    ctx.set("pki_revocation_none_or_missing", set(revocation_none) | set(no_revocation))
    return out


PKI_CHECKS = [check_pki]
