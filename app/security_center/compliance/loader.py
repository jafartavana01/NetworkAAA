"""
app.security_center.compliance.loader
========================================
Loads the 4 compliance framework mapping files (migrated verbatim,
byte-identical checksums confirmed against the original
cisco-ios-security-auditor mappings/*.json) and cross-references them
against a finding list. Adapted from cisco_audit.py's
`load_compliance_mappings()`/`write_compliance_framework_file()`: the
loading and check-id-to-control lookup logic is preserved exactly;
the *output* is restructured from that function's text-report-writing
into structured dicts, since this project's compliance results are
consumed by the Security Center API/GUI and stored as
AuditComplianceResult rows, not written to a text file.

IMPORTANT SCOPE NOTE, carried over unchanged from the original (see
its own comment above COMPLIANCE_FRAMEWORKS): NIST 800-53 Rev. 5 and
ISO/IEC 27002:2022 are populated with a substantial, deliberately-
reasoned mapping across most checks. The CIS IOS-XE Benchmark mapping
only contains entries directly verified against real benchmark text --
everything else is deliberately left unmapped rather than guessed,
since CIS numbering differs across benchmark versions and the full
document is gated behind a CIS SecureSuite login. The DISA STIG
mapping ships with real V-IDs but may not cover every check. This
unevenness is intentional, not a bug to "fix" by inventing mappings.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..engine.finding import Finding, Status

MAPPINGS_DIR = Path(__file__).parent / "mappings"

COMPLIANCE_FRAMEWORKS = [
    ("nist_800_53_rev5.json", "nist_800_53"),
    ("iso27002_2022.json", "iso27002"),
    ("cis_ios_xe_benchmark.json", "cis_ios_xe_benchmark"),
    ("disa_stig_cisco_iosxe.json", "disa_stig_cisco_iosxe"),
]


def load_compliance_mappings(mappings_dir: Path = MAPPINGS_DIR) -> list[dict]:
    """Load every available framework mapping file. Missing files are
    skipped silently -- compliance mapping is an optional layer on top
    of the core audit, not a hard dependency of it, same as the
    original."""
    loaded = []
    for filename, framework_key in COMPLIANCE_FRAMEWORKS:
        path = mappings_dir / filename
        if not path.exists():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            data["_framework_key"] = framework_key
            loaded.append(data)
        except Exception:
            continue
    return loaded


def map_findings_to_compliance(findings: list[Finding], framework: dict) -> dict[str, list[dict]]:
    """Cross-references a finding list against one loaded framework,
    grouped by control number -- same grouping logic as the original's
    `write_compliance_framework_file`, restructured to return data
    instead of writing a text report. A mapped check that wasn't part
    of this run's finding list is simply absent from the result (same
    as the original silently skipping it), not reported as a false
    NA."""
    checks_map: dict = framework.get("checks", {})
    findings_by_id: dict[str, Finding] = {f.check_id: f for f in findings}

    by_control: dict[str, list[dict]] = {}
    for check_id, entries in checks_map.items():
        finding = findings_by_id.get(check_id)
        if finding is None:
            continue
        for entry in entries:
            by_control.setdefault(entry["control"], []).append({
                "control": entry["control"],
                "title": entry.get("title", ""),
                "v_id": entry.get("v_id"),
                "check_id": check_id,
                "finding_status": finding.status.value,
                "finding_title": finding.title,
                "finding_severity": finding.severity.value,
            })
    return by_control


def control_status(entries: list[dict]) -> str:
    """A control's overall status when it's backed by more than one
    finding: FAIL if any contributing finding failed, MANUAL_REVIEW if
    any remaining one needs manual review (and none failed), else PASS.
    Not present in the original (which only ever grouped for display,
    never rolled up a single verdict) -- added here because
    AuditComplianceResult needs exactly one status per control row."""
    statuses = {e["finding_status"] for e in entries}
    if Status.FAIL.value in statuses:
        return Status.FAIL.value
    if Status.MANUAL.value in statuses:
        return Status.MANUAL.value
    if statuses == {Status.NA.value}:
        return Status.NA.value
    return Status.PASS.value
