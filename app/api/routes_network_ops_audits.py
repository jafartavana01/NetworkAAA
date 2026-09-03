"""
app.api.routes_network_ops_audits
====================================
Network Operations & Assurance Engine, Phase 4 (Audit engine). An
Audit is a named, reusable collection of check_keys (spec section 14).
Running one against a Command Job reuses the exact same evaluation
core as the ad-hoc "Run Checks" flow
(app.api.routes_network_ops_checks.execute_checks_against_job) --
Audits are not a separate execution path, just a named grouping on
top of the same engine, so the two can never independently drift on
how a check actually gets evaluated.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.command_job import CommandJob
from ..models.network_ops_audit import Audit, AuditRun
from ..models.network_ops_check import Check, CheckResult
from ..schemas.network_ops_audit import AuditCreate, AuditOut, AuditRunDetailOut, AuditRunOut, ScoreBreakdownOut
from ..services import network_ops_checks
from .deps import require_permission, verify_csrf
from .routes_network_ops_checks import _result_to_out, execute_checks_against_job

router = APIRouter(prefix="/api/network-ops", tags=["network-ops-audits"])


def ensure_seeded(db: Session) -> None:
    """Seeds one starter Audit ("Cisco IOS Management Plane Baseline",
    combining every Phase 3 starter check) on first boot -- a no-op on
    every subsequent boot once any Audit row exists, so it never
    overwrites an admin's edits or additions. Depends on
    app.api.routes_network_ops_checks.ensure_seeded having already run
    (main.py's own boot sequence calls checks' seeding before audits'
    -- see app/main.py), since this only references check_keys that
    must already exist as real Check rows."""
    if db.query(Audit).first() is not None:
        return
    existing_keys = {c.check_key for c in db.query(Check).all()}
    starter_keys = [k for k in ["aaa_new_model", "password_encryption", "vty_ssh_only", "http_server_disabled"] if k in existing_keys]
    if not starter_keys:
        return
    db.add(Audit(
        name="Cisco IOS Management Plane Baseline",
        description="A starting baseline covering AAA, password storage, VTY transport, and HTTP management exposure.",
        check_keys=starter_keys,
    ))
    db.commit()


@router.get("/audits", response_model=list[AuditOut])
def list_audits(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:view")),
):
    audits = db.query(Audit).order_by(Audit.name.asc()).all()
    return [_audit_to_out(a) for a in audits]


@router.post("/audits", response_model=AuditOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_audit(
    payload: AuditCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:templates")),
):
    if db.query(Audit).filter(Audit.name == payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"An audit named '{payload.name}' already exists.")
    unknown_keys = [k for k in payload.check_keys if not db.query(Check).filter(Check.check_key == k).first()]
    if unknown_keys:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Unknown check key(s): {', '.join(unknown_keys)}")
    audit = Audit(name=payload.name, description=payload.description, check_keys=payload.check_keys)
    db.add(audit)
    db.commit()
    db.refresh(audit)
    return _audit_to_out(audit)


@router.put("/audits/{audit_id}", response_model=AuditOut, dependencies=[Depends(verify_csrf)])
def update_audit(
    audit_id: str,
    payload: AuditCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:templates")),
):
    audit = _get_audit_or_404(db, audit_id)
    duplicate = db.query(Audit).filter(Audit.name == payload.name, Audit.id != audit.id).first()
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"An audit named '{payload.name}' already exists.")
    unknown_keys = [k for k in payload.check_keys if not db.query(Check).filter(Check.check_key == k).first()]
    if unknown_keys:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Unknown check key(s): {', '.join(unknown_keys)}")
    audit.name = payload.name
    audit.description = payload.description
    audit.check_keys = payload.check_keys
    db.commit()
    db.refresh(audit)
    return _audit_to_out(audit)


@router.delete("/audits/{audit_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_audit(
    audit_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:templates")),
):
    audit = _get_audit_or_404(db, audit_id)
    db.delete(audit)
    db.commit()


def _get_audit_or_404(db: Session, audit_id: str) -> Audit:
    try:
        parsed = uuid.UUID(audit_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Audit not found.")
    audit = db.query(Audit).filter(Audit.id == parsed).first()
    if not audit:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Audit not found.")
    return audit


def _audit_to_out(a: Audit) -> AuditOut:
    return AuditOut(
        id=str(a.id), name=a.name, description=a.description, check_keys=a.check_keys,
        created_at=a.created_at, updated_at=a.updated_at,
    )


# ---------- Running an Audit against a Job ----------

@router.post("/jobs/{job_id}/run-audit/{audit_id}", response_model=AuditRunDetailOut, dependencies=[Depends(verify_csrf)])
def run_audit(
    job_id: str,
    audit_id: str,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("network_ops:execute")),
):
    try:
        parsed_job_id = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Job not found.")
    job = db.query(CommandJob).filter(CommandJob.id == parsed_job_id).first()
    if not job:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Job not found.")

    audit = _get_audit_or_404(db, audit_id)
    checks = db.query(Check).filter(Check.check_key.in_(audit.check_keys), Check.enabled.is_(True)).all()
    if not checks:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="None of this audit's checks are currently enabled.")

    results = execute_checks_against_job(db, job, checks)

    audit_run = AuditRun(
        audit_id=audit.id, audit_name=audit.name, job_id=job.id, job_name=job.name,
        check_result_ids=[str(r.id) for r in results],
        created_by_admin_username=admin.username,
    )
    db.add(audit_run)
    db.commit()
    db.refresh(audit_run)

    return _audit_run_to_detail_out(audit_run, results)


@router.get("/audit-runs", response_model=list[AuditRunOut])
def list_audit_runs(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:view")),
):
    runs = db.query(AuditRun).order_by(AuditRun.created_at.desc()).limit(200).all()
    out = []
    for run in runs:
        results = _load_results_for_run(db, run)
        out.append(_audit_run_to_out(run, results))
    return out


@router.get("/audit-runs/{audit_run_id}", response_model=AuditRunDetailOut)
def get_audit_run(
    audit_run_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:view")),
):
    try:
        parsed = uuid.UUID(audit_run_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Audit run not found.")
    run = db.query(AuditRun).filter(AuditRun.id == parsed).first()
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Audit run not found.")
    results = _load_results_for_run(db, run)
    return _audit_run_to_detail_out(run, results)


def _load_results_for_run(db: Session, run: AuditRun) -> list[CheckResult]:
    """Resolves the soft-referenced CheckResult ids (see
    app.models.network_ops_audit's module docstring for why this is a
    soft reference, not a hard FK) back into real rows. A referenced
    id that no longer exists (should not normally happen -- CheckResult
    rows are never deleted independently) is simply skipped rather
    than erroring the whole run's display."""
    if not run.check_result_ids:
        return []
    ids = [uuid.UUID(i) for i in run.check_result_ids]
    return db.query(CheckResult).filter(CheckResult.id.in_(ids)).all()


def _audit_run_to_out(run: AuditRun, results: list[CheckResult]) -> AuditRunOut:
    breakdown = network_ops_checks.compute_score(results)
    return AuditRunOut(
        id=str(run.id), audit_name=run.audit_name, job_name=run.job_name,
        created_by_admin_username=run.created_by_admin_username, created_at=run.created_at,
        score=ScoreBreakdownOut(
            score=breakdown.score, total_checks=breakdown.total_checks, passed=breakdown.passed,
            failed=breakdown.failed, not_applicable=breakdown.not_applicable, other=breakdown.other,
            findings_by_severity=breakdown.findings_by_severity, deductions_by_severity=breakdown.deductions_by_severity,
        ),
    )


def _audit_run_to_detail_out(run: AuditRun, results: list[CheckResult]) -> AuditRunDetailOut:
    base = _audit_run_to_out(run, results)
    return AuditRunDetailOut(**base.model_dump(), results=[_result_to_out(r) for r in results])
