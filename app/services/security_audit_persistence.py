"""
app.services.security_audit_persistence
==========================================
Converts one app.security_center.engine.orchestrator.DeviceAuditResult
into AuditRun/AuditFinding/AuditDomainScore/AuditComplianceResult rows.
Kept as its own thin service (not inlined into the API route) so the
engine's output shape and the database's row shape can each change
independently, matching this project's existing separation between
app.services.config_compiler (produces text) and the routes that
persist a ConfigVersion row from it.
"""
from __future__ import annotations

import hashlib

from sqlalchemy.orm import Session

from ..models.audit_run import AuditComplianceResult, AuditDomainScore, AuditFinding, AuditRun
from ..security_center.engine.finding import Finding
from ..security_center.engine.orchestrator import DeviceAuditResult


def _finding_to_row(finding: Finding, audit_run_id, device_id) -> AuditFinding:
    return AuditFinding(
        audit_run_id=audit_run_id,
        device_id=device_id,
        interface_name=finding.interface_name,
        domain=finding.domain,
        check_id=finding.check_id,
        title=finding.title,
        status=finding.status.value,
        severity=finding.severity.value,
        evidence=finding.evidence,
        evidence_label=finding.evidence_label,
        recommendation=finding.recommendation,
        detail=finding.detail,
        fix_command=finding.fix_command,
        why=finding.why,
        risk=finding.risk,
        attack=finding.attack,
        best=finding.best,
        performance=finding.performance,
        operational=finding.operational,
        compatibility=finding.compatibility,
        references=finding.references,
        correlation_id=finding.correlation_id,
        compliance_refs={},
    )


def persist_audit_result(
    db: Session, *, audit_run: AuditRun, result: DeviceAuditResult,
) -> None:
    """
    Fills in an already-created, in-progress AuditRun row (status
    still "running") with everything the orchestrator produced, then
    marks it "completed". The caller creates and commits the initial
    AuditRun row itself, before calling this -- so a long-running
    audit is visible as "in progress" immediately, not only once
    fully done, the same reasoning app.services.apply_progress exists
    for on the Network Operations side of this project.
    """
    all_findings = result.findings + result.correlation_findings
    for finding in all_findings:
        db.add(_finding_to_row(finding, audit_run.id, audit_run.device_id))

    for domain, breakdown in result.domain_scores.items():
        db.add(AuditDomainScore(
            audit_run_id=audit_run.id,
            domain=domain,
            score=breakdown.score,
            fail_count=breakdown.fail_count,
            manual_count=breakdown.manual_count,
        ))

    for framework_key, controls in result.compliance_status.items():
        for control_id, status in controls.items():
            db.add(AuditComplianceResult(
                audit_run_id=audit_run.id,
                framework=framework_key,
                control_id=control_id,
                status=status,
            ))

    audit_run.overall_score = result.overall.score
    # "Compliance score" is deliberately the SAME normalized overall
    # score for now, not a separate computation -- this project's
    # compliance mapping (migrated from cisco-ios-security-auditor)
    # cross-references findings against framework controls but was
    # never designed to produce its OWN independent 0-100 number (the
    # original wrote a text report, not a score). Inventing a second,
    # differently-computed "compliance score" here would be exactly
    # the "opaque scoring" this migration's own architecture notes
    # warn against. If a real compliance-specific score is wanted
    # later (e.g. weighted by how many of a framework's controls
    # pass), that's a deliberate, separately-justified addition.
    audit_run.compliance_score = result.overall.score
    audit_run.status = "completed"


def hash_config_text(raw_config: str) -> str:
    return hashlib.sha256(raw_config.encode("utf-8")).hexdigest()
