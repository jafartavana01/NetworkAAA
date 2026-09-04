"""
app.security_center.engine.finding
=====================================
The unified finding model both check systems emit into. Designed as a
superset of the two legacy projects' own finding shapes, not a
lowest-common-denominator subset:

- cisco-ios-security-auditor's `Finding` (device-level): check_id,
  domain, title, status, severity, evidence, evidence_label,
  recommendation, detail, fix_command.
- cisco-interface-security-audit's per-rule finding dict (interface-
  level): the above PLUS why/risk/attack/best/performance/operational/
  compatibility/references -- a genuinely richer narrative than the
  device-level engine ever produced.

Rather than dropping the interface engine's richer fields to match the
device engine's simpler ones (or the reverse), every field from both is
present here; the extra narrative fields default to empty and are only
populated by interface-level checks, exactly matching what each system
actually produces today. `interface_name` is None for device-level
findings and set for interface-level ones -- one shared shape, not two
parallel finding classes that GUI/API code would have to branch on.

Status/Severity enums and SEVERITY_WEIGHT are migrated verbatim from
cisco-ios-security-auditor's cisco_audit.py (values confirmed against
its real source, not summarized).
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

SEVERITY_WEIGHT = {
    Severity.CRITICAL: 12,
    Severity.HIGH: 7,
    Severity.MEDIUM: 3,
    Severity.LOW: 1,
    Severity.INFO: 0,
}


class Status(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    NA = "na"              # not applicable (feature/protocol not in use)
    MANUAL = "manual_review"  # cannot be determined from running-config alone
    WARN = "warn"           # interface engine only: partially implemented,
                             # earns half weight in scoring -- a KNOWN partial
                             # state, not uncertainty, so it is deliberately
                             # NOT folded into MANUAL. No device-level check
                             # ever produces this status.


@dataclass
class Finding:
    check_id: str
    domain: str
    title: str
    status: Status
    severity: Severity

    # The finding's TRUE severity, preserved from BEFORE F()'s own
    # PASS/NA-downgrade-to-INFO (see F()'s docstring below). Needed
    # because app.security_center.engine.scoring's normalized-weight
    # model must know what a passing check's severity would have been
    # had it failed, to compute a fair applicable-weight denominator --
    # `severity` alone can't answer that once it's been downgraded to
    # INFO, and `severity` itself is left exactly as the original
    # project produces it (already verified byte-identical against
    # real source), not changed to accommodate this. Defaults to
    # `severity` for any Finding constructed directly (bypassing F()),
    # e.g. every interface-engine finding via to_unified_findings(),
    # where no such downgrade ever happens in the first place.
    true_severity: Optional[Severity] = None

    # Present on both device- and interface-level findings.
    evidence: list[str] = field(default_factory=list)
    evidence_label: str = "Affected items"
    recommendation: str = ""
    detail: str = ""
    fix_command: str = ""  # copy-paste-ready CLI remediation, may contain <placeholders>

    # Set only for an interface-scoped finding; None for a device-wide one.
    interface_name: Optional[str] = None

    # Interface-engine-only narrative fields (see module docstring) --
    # empty for every device-level finding, exactly matching what that
    # engine actually produces.
    why: str = ""
    risk: str = ""
    attack: str = ""
    best: str = ""
    performance: str = ""
    operational: str = ""
    compatibility: str = ""
    references: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if self.true_severity is None:
            self.true_severity = self.severity

    # Populated later, by app.security_center.engine.correlation and
    # app.security_center.compliance respectively -- never set by an
    # individual check function itself.
    correlation_id: Optional[str] = None
    compliance_refs: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["status"] = self.status.value
        d["severity"] = self.severity.value
        return d


def F(check_id: str, domain: str, title: str, status: Status, severity: Severity,
      evidence: Optional[list[str]] = None, recommendation: str = "", detail: str = "",
      evidence_label: str = "Affected items", fix_command: str = "",
      interface_name: Optional[str] = None) -> Finding:
    """Shorthand constructor for device-level checks -- signature matches
    cisco-ios-security-auditor's own `F()` helper exactly (plus the
    optional `interface_name`, unused by every migrated device-level
    check but available for a future check that wants to attribute a
    device-wide finding to a specific interface), so migrated check
    functions need no call-site changes beyond the import path.

    Severity is downgraded to INFO for PASS/NA findings, same as the
    original -- only a FAIL or MANUAL_REVIEW finding keeps its
    declared severity, since an INFO-tagged pass/n-a doesn't
    meaningfully compete for attention against a real gap."""
    downgraded = severity if status == Status.FAIL else (
        Severity.INFO if status in (Status.PASS, Status.NA) else severity
    )
    return Finding(
        check_id=check_id,
        domain=domain,
        title=title,
        status=status,
        severity=downgraded,
        true_severity=severity,  # the caller's ORIGINAL, undowngraded severity
        evidence=evidence or [],
        evidence_label=evidence_label,
        recommendation=recommendation,
        detail=detail,
        fix_command=fix_command,
        interface_name=interface_name,
    )
