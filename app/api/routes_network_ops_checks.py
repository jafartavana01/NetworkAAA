"""
app.api.routes_network_ops_checks
====================================
Network Operations & Assurance Engine, Phase 3. Runs registered checks
(app.services.network_ops_checks) against a CommandJob's already-
collected CommandExecution output -- never triggers a new SSH
connection; a check can only see what a job already gathered.

Re-running checks against the same job APPENDS new CheckResult rows
rather than overwriting previous ones -- matching this project's
established "never destroy history" discipline (Policy versioning,
Config version history), so a later re-run (e.g. after a check
evaluator itself was improved) doesn't erase what an earlier run
found.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.command_job import CommandExecution, CommandJob, CommandJobTarget
from ..models.network_ops_check import Check, CheckResult
from ..schemas.network_ops_checks import CheckOut, CheckResultOut, RunChecksRequest
from ..services import network_ops_checks
from .deps import require_permission, verify_csrf

router = APIRouter(prefix="/api/network-ops", tags=["network-ops-checks"])


def ensure_seeded(db: Session) -> None:
    """Seeds the starter Check catalog on first boot -- a no-op on
    every subsequent boot once any Check row exists, so it never
    overwrites an admin's edits (e.g. disabling a check) or additions.
    See app.services.network_ops_checks.default_checks."""
    if db.query(Check).first() is not None:
        return
    for entry in network_ops_checks.default_checks():
        db.add(Check(**entry))
    db.commit()


@router.get("/checks", response_model=list[CheckOut])
def list_checks(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:view")),
):
    checks = db.query(Check).order_by(Check.category.asc(), Check.name.asc()).all()
    return [
        CheckOut(
            id=str(c.id), check_key=c.check_key, name=c.name, description=c.description,
            category=c.category, default_severity=c.default_severity,
            required_commands=c.required_commands, enabled=c.enabled,
        ) for c in checks
    ]


def execute_checks_against_job(db: Session, job: CommandJob, checks: list[Check]) -> list[CheckResult]:
    """
    The shared core: evaluates every given Check against every target
    in `job`'s already-collected output, creates and commits the
    resulting CheckResult rows, and returns them (the real SQLAlchemy
    rows, not a schema -- callers that need the generated `.id`
    values, like app.api.routes_network_ops_audits building an
    AuditRun's soft-reference list, need the actual rows). Shared by
    both the ad-hoc "Run Checks" endpoint below and Audit runs, so the
    two can never independently drift on how a check actually gets
    evaluated and recorded. NOT itself a route -- has no decorator,
    called by real route handlers below.
    """
    targets = db.query(CommandJobTarget).filter(CommandJobTarget.job_id == job.id).all()
    new_results: list[CheckResult] = []

    for target in targets:
        executions = db.query(CommandExecution).filter(CommandExecution.job_target_id == target.id).all()
        command_outputs = {e.command: (e.raw_output or "") for e in executions}

        for check in checks:
            eval_result = network_ops_checks.run_check(check.check_key, command_outputs)
            result = CheckResult(
                check_id=check.id, check_key=check.check_key, check_name=check.name,
                job_target_id=target.id, device_name=target.device_name,
                status=eval_result.status, severity=check.default_severity,
                title=eval_result.title, description=eval_result.description,
                evidence=eval_result.evidence, actual_value=eval_result.actual_value,
                expected_value=eval_result.expected_value, recommendation=eval_result.recommendation,
            )
            db.add(result)
            new_results.append(result)

    db.commit()
    for r in new_results:
        db.refresh(r)
    return new_results


@router.post("/jobs/{job_id}/run-checks", response_model=list[CheckResultOut], dependencies=[Depends(verify_csrf)])
def run_checks(
    job_id: str,
    payload: RunChecksRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:execute")),
):
    try:
        parsed_job_id = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Job not found.")
    job = db.query(CommandJob).filter(CommandJob.id == parsed_job_id).first()
    if not job:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Job not found.")

    checks_query = db.query(Check).filter(Check.enabled.is_(True))
    if payload.check_keys:
        checks_query = checks_query.filter(Check.check_key.in_(payload.check_keys))
    checks = checks_query.all()
    if not checks:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="No enabled checks selected.")

    new_results = execute_checks_against_job(db, job, checks)
    return [_result_to_out(r) for r in new_results]


@router.get("/jobs/{job_id}/check-results", response_model=list[CheckResultOut])
def get_check_results(
    job_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:view")),
):
    try:
        parsed_job_id = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Job not found.")
    job = db.query(CommandJob).filter(CommandJob.id == parsed_job_id).first()
    if not job:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Job not found.")

    target_ids = [t.id for t in db.query(CommandJobTarget).filter(CommandJobTarget.job_id == job.id).all()]
    if not target_ids:
        return []
    results = (
        db.query(CheckResult)
        .filter(CheckResult.job_target_id.in_(target_ids))
        .order_by(CheckResult.created_at.desc())
        .all()
    )
    return [_result_to_out(r) for r in results]


def _result_to_out(r: CheckResult) -> CheckResultOut:
    return CheckResultOut(
        id=str(r.id), check_key=r.check_key, check_name=r.check_name, device_name=r.device_name,
        status=r.status, severity=r.severity, title=r.title, description=r.description,
        evidence=r.evidence, actual_value=r.actual_value, expected_value=r.expected_value,
        recommendation=r.recommendation, created_at=r.created_at,
    )
