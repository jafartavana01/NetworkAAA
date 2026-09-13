"""
app.security_center.checks.physical
===================================
Physical / Boot Security domain. Migrated verbatim from cisco-ios-security-auditor's
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


def check_physical(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Physical Security"
    out: list[Finding] = []

    pw_recovery_disabled = cfg.search(r"^no service password-recovery\b")
    out.append(F("PHYS-01", d, "Password recovery disabled",
                  Status.PASS if pw_recovery_disabled else Status.FAIL, Severity.MEDIUM,
                  detail="High-impact / irreversible on some platforms without a full re-image -- confirm this "
                          "is an intentional, documented decision either way.",
                  recommendation="Configure 'no service password-recovery' if physical security cannot be "
                                 "otherwise guaranteed; ensure this is a deliberate, documented decision.",
                  fix_command="no service password-recovery\n! Confirm this is intentional before applying -- see the note above."))

    con_blocks = cfg.get_blocks("line con")
    if con_blocks:
        m = con_blocks[0].find(r"exec-timeout (\d+) (\d+)")
        never = m and m.group(1) == "0" and m.group(2) == "0"
        max_min = policy["console_exec_timeout_max_minutes"]
        bad = never or not m or int(m.group(1)) > max_min
        out.append(F("PHYS-02", d, "Console exec-timeout configured and bounded",
                      Status.FAIL if bad else Status.PASS,
                      Severity.HIGH if never else Severity.MEDIUM,
                      recommendation=f"Set console 'exec-timeout' to a bounded value (<= {max_min} min), never 0 0.",
                      fix_command=f"line con 0\n exec-timeout {max_min} 0"))

    aux_blocks = cfg.get_blocks("line aux")
    if aux_blocks:
        aux_disabled = aux_blocks[0].has(r"no exec") and aux_blocks[0].has(r"transport input none")
        out.append(F("PHYS-03", d, "AUX port disabled if unused",
                      Status.PASS if aux_disabled else Status.MANUAL, Severity.MEDIUM,
                      recommendation="If the AUX port is not in active use, configure 'no exec' + "
                                     "'transport input none' on 'line aux 0'.",
                      fix_command="line aux 0\n no exec\n transport input none"))

    zeroize_capable = cfg.search(r"crypto key\b") or cfg.search(r"crypto pki trustpoint")
    out.append(F("PHYS-04", d, "Key zeroization practice on disposal/RMA",
                  Status.MANUAL, Severity.INFO,
                  detail="Procedural control, not a config-file check -- confirm 'crypto key zeroize' + "
                          "'write erase' + reload is standard practice before device disposal/RMA."
                          if zeroize_capable else "No cryptographic keys detected in this config.",
                  recommendation="Document and follow a zeroization procedure for any device holding key material."))

    out.append(F("PHYS-05", d, "Physical tamper indicators (alarm relay, tamper-evident hardware)",
                  Status.MANUAL, Severity.INFO,
                  detail="Not derivable from running-config -- hardware/physical inspection required.",
                  recommendation="Out of scope for a text-based config audit; verify physically if required by policy."))

    ctx.set("password_recovery_disabled", pw_recovery_disabled)
    return out


def check_boot_and_secure_boot(cfg: CiscoConfig, policy: dict, ctx: Context) -> list[Finding]:
    d = "Boot Configuration & Secure Boot"
    out: list[Finding] = []

    boot_lines = cfg.search_lines(r"^boot system\b")
    out.append(F("BOOT-01", d, "Explicit 'boot system' statement present",
                  Status.PASS if boot_lines else Status.FAIL, Severity.MEDIUM, evidence=boot_lines,
                  evidence_label="Current boot system lines",
                  recommendation="Configure an explicit 'boot system flash:<image>' rather than relying on the "
                                 "platform's default search order.",
                  fix_command="boot system flash:<image-filename>"))
    if len(boot_lines) > 1:
        out.append(F("BOOT-02", d, f"Multiple boot-system entries present ({len(boot_lines)}) -- review",
                      Status.MANUAL, Severity.LOW, evidence=boot_lines,
                      evidence_label="Boot system entries found",
                      recommendation="Confirm multiple entries are intentional redundancy, not stale/forgotten "
                                     "fallback images pointing at an old/vulnerable version."))

    usb_boot = cfg.search(r"boot system usb")
    out.append(F("BOOT-03", d, "USB boot not in use",
                  Status.FAIL if usb_boot else Status.PASS, Severity.MEDIUM,
                  recommendation="Avoid booting from USB media in production; disable if not explicitly required.",
                  fix_command="no boot system usb<...>\nboot system flash:<image-filename>"))

    reg_m = re.search(r"^config-register (0x[0-9A-Fa-f]+)", cfg.text, re.M | re.I)
    config_register_break_enabled = False
    if reg_m:
        try:
            reg_val = int(reg_m.group(1), 16)
            # Bit 6 (0x0040) = "ignore NVRAM config" behavior in some contexts; the classic console-break related
            # setting is the low nibble != 0x2 default boot field combined with bit 8 (0x0100, terminal break).
            config_register_break_enabled = bool(reg_val & 0x0100) or (reg_val & 0x000F) == 0
            out.append(F("BOOT-04", d, f"Config-register value reviewed ({reg_m.group(1)})",
                          Status.FAIL if config_register_break_enabled else Status.PASS, Severity.MEDIUM,
                          detail="Non-default config-register values can enable console-break-to-ROMMON or "
                                  "unpredictable boot behavior.",
                          recommendation="Use the standard 0x2102 unless there is a specific, documented reason "
                                          "for a different value.",
                          fix_command="config-register 0x2102\n! Requires a reload to take effect."))
        except ValueError:
            out.append(F("BOOT-04", d, "Config-register value reviewed", Status.MANUAL, Severity.LOW,
                          detail=f"Could not parse value: {reg_m.group(1)}"))
    else:
        out.append(F("BOOT-04", d, "Config-register value present in running-config",
                      Status.MANUAL, Severity.INFO,
                      detail="Not found -- some exports omit this line even when it's at the platform default (0x2102).",
                      recommendation="Verify with 'show version | include register' if not shown here."))

    out.append(F("BOOT-05", d, "Secure Boot / image signature verification enabled",
                  Status.MANUAL, Severity.INFO,
                  detail="Secure Boot state is platform-verified (Trust Anchor module), not visible in running-config.",
                  recommendation="Verify with 'show platform sudi certificate' / 'show software authenticity' on the live device."))
    out.append(F("BOOT-06", d, "SELinux / platform Mandatory Access Control (IOS-XE Linux underlay)",
                  Status.MANUAL, Severity.INFO,
                  detail="Platform-verified only.",
                  recommendation="Verify enforcing mode via 'show platform software security-briefing' "
                                  "(or applicable platform command) if this level of assurance is required."))
    out.append(F("BOOT-07", d, "Hardware-backed secure storage / configuration-at-rest encryption",
                  Status.MANUAL, Severity.INFO,
                  detail="Platform-verified only.",
                  recommendation="Confirm platform capability and enablement status out of band."))
    out.append(F("BOOT-08", d, "ROMMON password set",
                  Status.MANUAL, Severity.MEDIUM,
                  detail="ROMMON password state is not reflected in running-config.",
                  recommendation="Verify ROMMON password is set via direct console access during a maintenance window."))
    out.append(F("BOOT-09", d, "Bootloader version reviewed against known-vulnerable versions",
                  Status.MANUAL, Severity.INFO,
                  recommendation="Cross-reference bootloader/ROMMON version with Cisco PSIRT once the IOS-XE "
                                  "version check (see Software/PSIRT domain) is extended to cover it."))

    ctx.set("config_register_break_enabled", config_register_break_enabled)
    return out


PHYSICAL_CHECKS = [check_physical, check_boot_and_secure_boot]
