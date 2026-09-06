"""
app.api.routes_security
==========================
Security Center API: trigger device-level audits (live SSH or
uploaded config text), retrieve results, list history, compare runs,
and a fleet-wide overview. See app.security_center.engine.orchestrator
for the actual audit pipeline this calls -- every route here is a
thin persistence/HTTP wrapper around run_device_audit(), never
reimplementing any check/scoring logic itself.

Interface-level audit routes are not yet built -- see
run_device_audit()'s own docstring on why device- and interface-level
auditing are deliberately not combined into one call yet.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..models.audit_batch import AuditBatch
from ..models.audit_run import AuditComplianceResult, AuditDomainScore, AuditFinding, AuditRun
from ..models.audit_schedule_settings import AuditScheduleSettings
from ..models.device import NetworkDevice
from ..schemas.security_audit import (
    AuditBatchSummaryListItemOut, AuditBatchSummaryOut, AuditCompareOut, AuditLiveRequest, AuditRunDetailOut,
    AuditRunSummaryOut, AuditScheduleOut,
    AuditScheduleUpdateRequest, AuditUploadRequest, BatchCategoryCountOut, BatchDeviceRowOut, BatchTopFindingOut,
    ActivityEventOut, BulkAuditRequest, BulkAuditResultOut,
    ComplianceControlDetailOut, ComplianceControlOut, ComplianceFindingOut,
    ComplianceFrameworkOut, ComplianceOverviewOut,
    DashboardComplianceOut, DashboardDomainScoreOut, DashboardHeatmapCellOut, DashboardRiskyDeviceOut,
    ManualReviewCategoryOut, ManualReviewOut, ScoreContributionOut, ScoreExplanationOut,
    DashboardSeverityCountOut, DashboardTopRiskOut, DashboardTrendPointOut,
    DomainScoreOut, FindingOut, FleetFindingOut, SecurityDashboardOut, SecurityDeviceOut, SecurityOverviewOut,
)
from ..security_center.engine.finding import Severity, Status
from ..security_center.engine.orchestrator import run_device_audit
from ..services.scheduled_audit import run_scheduled_audit
from ..services.security_audit_persistence import hash_config_text, persist_audit_result
from .deps import get_current_superadmin, require_permission, verify_csrf

router = APIRouter(prefix="/api/security", tags=["security-center"])


def _get_device_or_404(db: Session, device_id: str) -> NetworkDevice:
    try:
        parsed_id = uuid.UUID(device_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")
    device = db.query(NetworkDevice).filter(NetworkDevice.id == parsed_id).first()
    if not device:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Device not found.")
    return device


def _bare_ip(device: NetworkDevice) -> str:
    return device.ip_address.split("/")[0].strip()


def _latest_completed_runs_by_device(db: Session) -> dict:
    """
    The most recent COMPLETED audit run per device, as a dict keyed by
    device_id -- shared by every endpoint that needs "current fleet
    posture" (overview, the device list, and fleet-wide findings) so
    the definition of "current" can't drift between them. Grouped in
    Python rather than a SQL-side subquery+join: this project has no
    existing precedent anywhere for a "give me the full latest ROW per
    group" query (its other group_by usage is always for a COUNT), and
    getting a multi-condition subquery join wrong is a worse failure
    mode than the small extra cost of grouping client-side for what
    is fundamentally summary/reporting data, not a hot path.
    """
    all_completed = (
        db.query(AuditRun)
        .filter(AuditRun.status == "completed", AuditRun.device_id.isnot(None))
        .order_by(AuditRun.started_at.desc())
        .all()
    )
    latest_by_device: dict = {}
    for run in all_completed:
        if run.device_id not in latest_by_device:
            latest_by_device[run.device_id] = run
    return latest_by_device


def _run_to_summary(run: AuditRun) -> AuditRunSummaryOut:
    return AuditRunSummaryOut(
        id=str(run.id), device_id=str(run.device_id) if run.device_id else None,
        device_name=run.device_name, source=run.source, status=run.status,
        overall_score=run.overall_score, compliance_score=run.compliance_score,
        started_at=run.started_at, completed_at=run.completed_at,
    )


def _finding_row_to_out(f: AuditFinding) -> FindingOut:
    return FindingOut(
        check_id=f.check_id, domain=f.domain, title=f.title, status=f.status, severity=f.severity,
        interface_name=f.interface_name, evidence=f.evidence, evidence_label=f.evidence_label,
        recommendation=f.recommendation, detail=f.detail, fix_command=f.fix_command,
        why=f.why, risk=f.risk, attack=f.attack, best=f.best, performance=f.performance,
        operational=f.operational, compatibility=f.compatibility, references=f.references,
        correlation_id=f.correlation_id,
    )


def _run_to_detail(db: Session, run: AuditRun) -> AuditRunDetailOut:
    finding_rows = db.query(AuditFinding).filter(AuditFinding.audit_run_id == run.id).all()
    individual = [_finding_row_to_out(f) for f in finding_rows if not f.correlation_id]
    correlated = [_finding_row_to_out(f) for f in finding_rows if f.correlation_id]

    domain_rows = db.query(AuditDomainScore).filter(AuditDomainScore.audit_run_id == run.id).all()
    domain_scores = [
        DomainScoreOut(domain=d.domain, score=d.score, fail_count=d.fail_count, manual_count=d.manual_count,
                        pass_count=0, warn_count=0)  # per-status pass/warn counts aren't stored per-domain today
        for d in domain_rows
    ]

    compliance_rows = db.query(AuditComplianceResult).filter(AuditComplianceResult.audit_run_id == run.id).all()
    compliance_summary: dict[str, dict] = {}
    for c in compliance_rows:
        bucket = compliance_summary.setdefault(c.framework, {"total": 0, "fail": 0, "controls": {}})
        bucket["total"] += 1
        if c.status == Status.FAIL.value:
            bucket["fail"] += 1
        bucket["controls"][c.control_id] = c.status

    overall_risk = None
    if run.overall_score is not None:
        from ..security_center.engine.scoring import risk_level
        overall_risk = risk_level(run.overall_score)

    return AuditRunDetailOut(
        **_run_to_summary(run).model_dump(),
        risk_level=overall_risk, findings=individual, correlation_findings=correlated,
        domain_scores=domain_scores, compliance_summary=compliance_summary,
    )


def _create_running_audit_row(db: Session, *, device: NetworkDevice | None, device_name: str, source: str,
                               started_by: str, raw_config: str | None = None) -> AuditRun:
    run = AuditRun(
        device_id=device.id if device else None,
        device_name=device_name, source=source, status="running",
        raw_config=raw_config,
        config_snapshot_hash=hash_config_text(raw_config) if raw_config else None,
        started_by_admin_username=started_by,
    )
    db.add(run)
    db.commit()
    db.refresh(run)
    return run


@router.post("/audit/upload", response_model=AuditRunDetailOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def audit_uploaded_config(
    payload: AuditUploadRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("security:audit")),
):
    device = _get_device_or_404(db, payload.device_id) if payload.device_id else None
    device_name = device.name if device else (payload.device_name or "Unnamed device")

    run = _create_running_audit_row(
        db, device=device, device_name=device_name, source="upload",
        started_by=admin.username, raw_config=payload.raw_config,
    )
    try:
        result = run_device_audit(payload.raw_config)
        if not device_name or device_name == "Unnamed device":
            run.device_name = result.hostname
        persist_audit_result(db, audit_run=run, result=result)
        db.commit()
    except Exception as exc:
        run.status = "failed"
        run.error_message = str(exc)
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Audit failed: {exc}")

    db.refresh(run)
    return _run_to_detail(db, run)


@router.post("/devices/{device_id}/audit/live", response_model=AuditRunDetailOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def audit_live_device(
    device_id: str,
    payload: AuditLiveRequest,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("security:audit")),
):
    """
    Gathers 'show running-config' over SSH (reusing
    app.services.network_ops_execution.run_commands_on_device -- the
    same execution path Network Operations' own command jobs use, not
    a second SSH implementation) and audits it.
    """
    from ..services import network_ops_execution

    device = _get_device_or_404(db, device_id)
    run = _create_running_audit_row(db, device=device, device_name=device.name, source="live", started_by=admin.username)

    exec_kwargs = {}
    if payload.connect_timeout_seconds is not None:
        exec_kwargs["connect_timeout_seconds"] = payload.connect_timeout_seconds
    if payload.command_timeout_seconds is not None:
        exec_kwargs["command_timeout_seconds"] = payload.command_timeout_seconds

    exec_result = network_ops_execution.run_commands_on_device(
        _bare_ip(device), payload.ssh_username, payload.ssh_password, ["terminal length 0", "show running-config"],
        **exec_kwargs,
    )
    if not exec_result.success or not exec_result.command_results:
        run.status = "failed"
        run.error_message = exec_result.message
        db.commit()
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, detail=f"Could not reach device: {exec_result.message}")

    raw_config = exec_result.command_results[-1].output
    run.raw_config = raw_config
    run.config_snapshot_hash = hash_config_text(raw_config)

    try:
        result = run_device_audit(raw_config)
        persist_audit_result(db, audit_run=run, result=result)
        db.commit()
    except Exception as exc:
        run.status = "failed"
        run.error_message = str(exc)
        db.commit()
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail=f"Audit failed: {exc}")

    db.refresh(run)
    return _run_to_detail(db, run)


@router.get("/audits/{audit_run_id}", response_model=AuditRunDetailOut)
def get_audit(
    audit_run_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    try:
        parsed_id = uuid.UUID(audit_run_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Audit run not found.")
    run = db.query(AuditRun).filter(AuditRun.id == parsed_id).first()
    if not run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Audit run not found.")
    return _run_to_detail(db, run)


@router.get("/devices/{device_id}/audits", response_model=list[AuditRunSummaryOut])
def list_device_audits(
    device_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    device = _get_device_or_404(db, device_id)
    runs = db.query(AuditRun).filter(AuditRun.device_id == device.id).order_by(AuditRun.started_at.desc()).all()
    return [_run_to_summary(r) for r in runs]


@router.get("/audits/{from_run_id}/compare/{to_run_id}", response_model=AuditCompareOut)
def compare_audits(
    from_run_id: str, to_run_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    def _findings_by_key(run_id: str) -> dict[str, AuditFinding]:
        rows = db.query(AuditFinding).filter(AuditFinding.audit_run_id == uuid.UUID(run_id)).all()
        # Keyed by (check_id, interface_name) -- the same check on a
        # different interface is a DIFFERENT finding, not the same one.
        return {(f.check_id, f.interface_name): f for f in rows}

    try:
        from_run = db.query(AuditRun).filter(AuditRun.id == uuid.UUID(from_run_id)).first()
        to_run = db.query(AuditRun).filter(AuditRun.id == uuid.UUID(to_run_id)).first()
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Audit run not found.")
    if not from_run or not to_run:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Audit run not found.")

    from_findings = _findings_by_key(from_run_id)
    to_findings = _findings_by_key(to_run_id)

    # "New" = failing now, wasn't a failing finding before (whether
    # entirely absent, or present but passing/NA before).
    new_findings = [
        _finding_row_to_out(f) for key, f in to_findings.items()
        if f.status == Status.FAIL.value and (key not in from_findings or from_findings[key].status != Status.FAIL.value)
    ]
    resolved_findings = [
        _finding_row_to_out(f) for key, f in from_findings.items()
        if f.status == Status.FAIL.value and (key not in to_findings or to_findings[key].status != Status.FAIL.value)
    ]
    persistent_findings = [
        _finding_row_to_out(f) for key, f in to_findings.items()
        if f.status == Status.FAIL.value and key in from_findings and from_findings[key].status == Status.FAIL.value
    ]

    score_delta = (to_run.overall_score or 0.0) - (from_run.overall_score or 0.0)
    return AuditCompareOut(
        from_run_id=from_run_id, to_run_id=to_run_id, score_delta=round(score_delta, 1),
        new_findings=new_findings, resolved_findings=resolved_findings, persistent_findings=persistent_findings,
    )


@router.get("/findings", response_model=list[FleetFindingOut])
def list_fleet_findings(
    severity: str | None = None,
    status_filter: str | None = None,
    device_id: str | None = None,
    domain: str | None = None,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    """
    Every finding from each device's own LATEST completed audit only
    -- never older, superseded runs -- so a fixed issue from three
    audits ago can't reappear here just because it's still sitting in
    an old run's rows. Filtered server-side (severity/status/device/
    domain) since the finding volume across a real fleet can be large;
    unlike the sidebar's own search (which filters an already-small,
    already-loaded nav list client-side), this is exactly the kind of
    data search app.security_center's own architecture notes describe
    as needing a real query, not a client-side scan.
    """
    latest_by_device = _latest_completed_runs_by_device(db)
    if not latest_by_device:
        return []

    run_ids = [run.id for run in latest_by_device.values()]
    device_names = {run.device_id: run.device_name for run in latest_by_device.values()}
    run_started_at = {run.id: run.started_at for run in latest_by_device.values()}

    query = db.query(AuditFinding).filter(AuditFinding.audit_run_id.in_(run_ids))
    if severity:
        query = query.filter(AuditFinding.severity == severity)
    if status_filter:
        query = query.filter(AuditFinding.status == status_filter)
    if domain:
        query = query.filter(AuditFinding.domain == domain)
    if device_id:
        try:
            parsed_device_id = uuid.UUID(device_id)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid device_id.")
        query = query.filter(AuditFinding.device_id == parsed_device_id)

    findings = query.order_by(AuditFinding.created_at.desc()).all()

    # Real severity priority (critical first), not alphabetical --
    # "critical" < "high" < "info" < "low" < "medium" alphabetically,
    # which is not remotely the order this list should read in.
    severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings.sort(key=lambda f: severity_rank.get(f.severity, 99))

    out = []
    for f in findings:
        out.append(FleetFindingOut(
            device_id=str(f.device_id) if f.device_id else "",
            device_name=device_names.get(f.device_id, "Unknown device"),
            audit_run_id=str(f.audit_run_id),
            audited_at=run_started_at.get(f.audit_run_id),
            check_id=f.check_id, domain=f.domain, title=f.title,
            status=f.status, severity=f.severity, interface_name=f.interface_name,
            recommendation=f.recommendation, fix_command=f.fix_command,
            correlation_id=f.correlation_id,
            detail=f.detail, why=f.why, risk=f.risk,
            evidence=f.evidence or [], evidence_label=f.evidence_label,
            compliance_refs=f.compliance_refs or {},
        ))
    return out


@router.get("/devices", response_model=list[SecurityDeviceOut])
def list_security_devices(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    """
    Every NetworkAAA device, paired with its own most recent COMPLETED
    audit's summary if it has one -- reusing the existing device
    inventory (app.models.device.NetworkDevice) rather than a second
    one, per this migration's own architecture notes. A device with no
    audit history yet still appears, with every latest_* field null,
    so this page is where an admin discovers "which devices haven't
    been audited," not just where already-audited ones show up.
    """
    from ..models.device_group import DeviceGroup

    devices = db.query(NetworkDevice).order_by(NetworkDevice.name.asc()).all()
    group_names = {g.id: g.name for g in db.query(DeviceGroup).all()}
    latest_by_device = _latest_completed_runs_by_device(db)

    from ..security_center.engine.scoring import risk_level as _risk_level

    out = []
    for device in devices:
        latest = latest_by_device.get(device.id)
        out.append(SecurityDeviceOut(
            id=str(device.id), name=device.name, ip_address=device.ip_address,
            device_group_name=group_names.get(device.device_group_id),
            latest_score=latest.overall_score if latest else None,
            latest_risk_level=_risk_level(latest.overall_score) if latest and latest.overall_score is not None else None,
            latest_audited_at=latest.started_at if latest else None,
            latest_audit_run_id=str(latest.id) if latest else None,
        ))
    return out


@router.get("/overview", response_model=SecurityOverviewOut)
def security_overview(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    # Most recent completed run per device -- the fleet overview
    # reflects each device's CURRENT posture, not every historical run.
    latest_by_device = _latest_completed_runs_by_device(db)
    latest_runs = list(latest_by_device.values())

    scores = [r.overall_score for r in latest_runs if r.overall_score is not None]
    avg_score = round(sum(scores) / len(scores), 1) if scores else None

    severity_counts = {Severity.CRITICAL.value: 0, Severity.HIGH.value: 0, Severity.MEDIUM.value: 0, Severity.LOW.value: 0}
    manual_count = 0
    if latest_runs:
        run_ids = [r.id for r in latest_runs]
        finding_rows = db.query(AuditFinding).filter(AuditFinding.audit_run_id.in_(run_ids)).all()
        for f in finding_rows:
            if f.status == Status.FAIL.value and f.severity in severity_counts:
                severity_counts[f.severity] += 1
            elif f.status == Status.MANUAL.value:
                manual_count += 1

    recent = db.query(AuditRun).order_by(AuditRun.started_at.desc()).limit(10).all()

    return SecurityOverviewOut(
        devices_audited=len(latest_runs), average_score=avg_score,
        critical_findings=severity_counts[Severity.CRITICAL.value],
        high_findings=severity_counts[Severity.HIGH.value],
        medium_findings=severity_counts[Severity.MEDIUM.value],
        low_findings=severity_counts[Severity.LOW.value],
        manual_review_findings=manual_count,
        recent_audits=[_run_to_summary(r) for r in recent],
    )


def _get_or_create_schedule_settings(db: Session) -> AuditScheduleSettings:
    settings = db.query(AuditScheduleSettings).first()
    if settings is None:
        settings = AuditScheduleSettings()
        db.add(settings)
        db.commit()
        db.refresh(settings)
    return settings


@router.get("/schedule", response_model=AuditScheduleOut)
def get_schedule_settings(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    """
    Superadmin-only, same as app.api.routes_ad_settings' own AD
    service-account endpoints -- this stores a shared SSH credential
    capable of reaching every device unattended, the same risk profile
    as an AD bind account, so it gets the same gating.
    """
    s = _get_or_create_schedule_settings(db)
    return AuditScheduleOut(
        enabled=s.enabled, ssh_username=s.ssh_username, has_password=bool(s.ssh_password_encrypted),
        daily_run_time=s.daily_run_time, management_ip_note=s.management_ip_note,
        last_run_at=s.last_run_at, last_run_status=s.last_run_status, last_run_summary=s.last_run_summary,
    )


@router.put("/schedule", response_model=AuditScheduleOut, dependencies=[Depends(verify_csrf)])
def update_schedule_settings(
    payload: AuditScheduleUpdateRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    s = _get_or_create_schedule_settings(db)
    s.enabled = payload.enabled
    s.ssh_username = payload.ssh_username
    if payload.ssh_password:
        s.ssh_password_encrypted = security.encrypt_secret(payload.ssh_password)
    s.daily_run_time = payload.daily_run_time
    s.management_ip_note = payload.management_ip_note
    db.commit()
    db.refresh(s)
    return AuditScheduleOut(
        enabled=s.enabled, ssh_username=s.ssh_username, has_password=bool(s.ssh_password_encrypted),
        daily_run_time=s.daily_run_time, management_ip_note=s.management_ip_note,
        last_run_at=s.last_run_at, last_run_status=s.last_run_status, last_run_summary=s.last_run_summary,
    )


@router.post("/schedule/run-now", response_model=AuditScheduleOut, dependencies=[Depends(verify_csrf)])
def run_schedule_now(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_superadmin),
):
    """
    Runs the exact same fleet-wide audit the daily scheduler itself
    runs (app.services.scheduled_audit.run_scheduled_audit), on
    demand -- primarily so a superadmin can verify the stored
    credential actually works against the real fleet without waiting
    for the next scheduled time.
    """
    s = _get_or_create_schedule_settings(db)
    if not s.ssh_username or not s.ssh_password_encrypted:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Set a username and password first.")

    result = run_scheduled_audit(
        db, ssh_username=s.ssh_username, ssh_password_encrypted=s.ssh_password_encrypted, batch_source="manual",
    )
    s.last_run_at = datetime.now(timezone.utc)
    s.last_run_status = result.status
    s.last_run_summary = result.summary
    db.commit()
    db.refresh(s)
    return AuditScheduleOut(
        enabled=s.enabled, ssh_username=s.ssh_username, has_password=bool(s.ssh_password_encrypted),
        daily_run_time=s.daily_run_time, management_ip_note=s.management_ip_note,
        last_run_at=s.last_run_at, last_run_status=s.last_run_status, last_run_summary=s.last_run_summary,
    )


_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@router.get("/batches", response_model=list[AuditBatchSummaryListItemOut])
def list_audit_batches(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    """Every fleet-wide audit report, newest first -- backs the
    reference design's own "Recent Audit Reports" list."""
    batches = db.query(AuditBatch).order_by(AuditBatch.started_at.desc()).limit(20).all()
    return [
        AuditBatchSummaryListItemOut(
            id=str(b.id), display_number=b.display_number, status=b.status,
            started_at=b.started_at, total_devices=b.total_devices,
        )
        for b in batches
    ]


@router.get("/batches/{display_number}", response_model=AuditBatchSummaryOut)
def get_audit_batch_summary(
    display_number: int,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    """
    Everything the fleet-wide Audit Report dashboard needs, in one
    call -- aggregated here rather than in the browser, per this
    feature's own design note on avoiding N+1 queries and
    recalculating the same aggregates client-side. Grouping/counting
    is done in Python over the batch's own rows rather than SQL-side
    GROUP BY -- the same reasoning as `_latest_completed_runs_by_device`
    above: no existing precedent in this codebase for the more complex
    aggregate queries this would need, and getting one wrong silently
    is a worse failure mode than the modest extra cost here, since a
    single batch's own device count is bounded by the fleet size, not
    an unbounded table scan.
    """
    from ..security_center.engine.scoring import risk_level

    batch = db.query(AuditBatch).filter(AuditBatch.display_number == display_number).first()
    if not batch:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Audit report not found.")

    runs = db.query(AuditRun).filter(AuditRun.batch_id == batch.id).order_by(AuditRun.device_name.asc()).all()
    run_ids = [r.id for r in runs]
    findings = db.query(AuditFinding).filter(AuditFinding.audit_run_id.in_(run_ids)).all() if run_ids else []

    device_ids = [r.device_id for r in runs if r.device_id]
    ip_by_device: dict = {}
    if device_ids:
        for d in db.query(NetworkDevice).filter(NetworkDevice.id.in_(device_ids)).all():
            ip_by_device[d.id] = d.ip_address

    findings_by_run: dict = {}
    for f in findings:
        findings_by_run.setdefault(f.audit_run_id, []).append(f)

    severity_totals = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    category_totals: dict = {}
    top_finding_groups: dict = {}  # (check_id, title, severity) -> set of device_id

    device_rows: list[BatchDeviceRowOut] = []
    scores = []
    for run in runs:
        run_findings = findings_by_run.get(run.id, [])
        run_high = run_medium = run_low = 0
        for f in run_findings:
            if f.status != Status.FAIL.value:
                continue
            if f.severity == Severity.CRITICAL.value or f.severity == Severity.HIGH.value:
                run_high += 1
            elif f.severity == Severity.MEDIUM.value:
                run_medium += 1
            elif f.severity == Severity.LOW.value:
                run_low += 1
            if f.severity in severity_totals:
                severity_totals[f.severity] += 1
            category_totals[f.domain] = category_totals.get(f.domain, 0) + 1
            key = (f.check_id, f.title, f.severity)
            top_finding_groups.setdefault(key, set()).add(run.device_id or run.id)

        if run.overall_score is not None:
            scores.append(run.overall_score)

        device_rows.append(BatchDeviceRowOut(
            device_id=str(run.device_id) if run.device_id else None,
            device_name=run.device_name,
            ip_address=ip_by_device.get(run.device_id) if run.device_id else None,
            high=run_high, medium=run_medium, low=run_low,
            score=run.overall_score,
            risk_level=risk_level(run.overall_score) if run.overall_score is not None else None,
            status=run.status, last_scan_at=run.started_at,
        ))

    category_breakdown = [
        BatchCategoryCountOut(domain=domain, fail_count=count)
        for domain, count in sorted(category_totals.items(), key=lambda kv: kv[1], reverse=True)
    ]

    top_findings = sorted(
        (
            BatchTopFindingOut(check_id=check_id, title=title, severity=severity, device_count=len(device_set))
            for (check_id, title, severity), device_set in top_finding_groups.items()
        ),
        key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), -f.device_count),
    )[:5]

    duration_seconds = None
    if batch.completed_at:
        duration_seconds = int((batch.completed_at - batch.started_at).total_seconds())

    return AuditBatchSummaryOut(
        id=str(batch.id), display_number=batch.display_number, status=batch.status, source=batch.source,
        target_description=batch.target_description, started_by_admin_username=batch.started_by_admin_username,
        started_at=batch.started_at, completed_at=batch.completed_at, duration_seconds=duration_seconds,
        total_devices=batch.total_devices, devices_succeeded=batch.devices_succeeded, devices_failed=batch.devices_failed,
        total_checks=len(findings),
        critical_count=severity_totals["critical"], high_count=severity_totals["high"],
        medium_count=severity_totals["medium"], low_count=severity_totals["low"],
        average_score=round(sum(scores) / len(scores), 1) if scores else None,
        category_breakdown=category_breakdown, top_findings=top_findings, devices=device_rows,
    )


@router.get("/dashboard", response_model=SecurityDashboardOut)
def get_security_dashboard(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    """
    One aggregated call backing the whole redesigned Security Center
    Overview -- score, severity breakdown, domain scores, trend,
    compliance, risky devices, top risks and the device x domain
    heatmap. Built as a single endpoint deliberately: the Overview
    firing one request per widget is exactly the N+1 pattern this
    redesign is meant to avoid.

    Every section is derived from real stored rows. Where nothing has
    been audited yet, the corresponding list comes back EMPTY rather
    than zero-filled or synthesized, so the GUI can render a truthful
    empty state instead of a chart implying data that doesn't exist.
    """
    from ..security_center.engine.scoring import risk_level

    latest_by_device = _latest_completed_runs_by_device(db)
    runs = list(latest_by_device.values())

    if not runs:
        return SecurityDashboardOut(
            devices_audited=0, average_score=None, previous_average_score=None, compliance_score=None,
            severity_counts=[], total_findings=0, manual_review_findings=0, failed_checks=0,
            domain_scores=[], score_trend=[], compliance=[], risky_devices=[], top_risks=[],
            heatmap=[], heatmap_domains=[],
            score_explanation=None, manual_review=ManualReviewOut(total=0, categories=[]),
        )

    run_ids = [r.id for r in runs]
    findings = db.query(AuditFinding).filter(AuditFinding.audit_run_id.in_(run_ids)).all()
    domain_rows = db.query(AuditDomainScore).filter(AuditDomainScore.audit_run_id.in_(run_ids)).all()
    compliance_rows = db.query(AuditComplianceResult).filter(AuditComplianceResult.audit_run_id.in_(run_ids)).all()

    scores = [r.overall_score for r in runs if r.overall_score is not None]
    average_score = round(sum(scores) / len(scores), 1) if scores else None

    compliance_scores = [r.compliance_score for r in runs if r.compliance_score is not None]
    compliance_score = round(sum(compliance_scores) / len(compliance_scores), 1) if compliance_scores else None

    # "Previous" posture = each device's own second-most-recent
    # completed run, averaged the same way. Only computed when such
    # runs actually exist -- a device with a single audit contributes
    # nothing here rather than being compared against itself.
    all_completed = (
        db.query(AuditRun)
        .filter(AuditRun.status == "completed", AuditRun.device_id.isnot(None))
        .order_by(AuditRun.started_at.desc())
        .all()
    )
    seen: dict = {}
    previous_scores = []
    for run in all_completed:
        seen.setdefault(run.device_id, []).append(run)
    for device_runs in seen.values():
        if len(device_runs) > 1 and device_runs[1].overall_score is not None:
            previous_scores.append(device_runs[1].overall_score)
    previous_average_score = round(sum(previous_scores) / len(previous_scores), 1) if previous_scores else None

    severity_totals: dict = {}
    manual_review_findings = 0
    failed_checks = 0
    for f in findings:
        if f.status == Status.MANUAL.value:
            manual_review_findings += 1
        if f.status != Status.FAIL.value:
            continue
        failed_checks += 1
        severity_totals[f.severity] = severity_totals.get(f.severity, 0) + 1

    severity_counts = [
        DashboardSeverityCountOut(severity=sev, count=severity_totals.get(sev, 0))
        for sev in ("critical", "high", "medium", "low", "info")
        if severity_totals.get(sev, 0) > 0
    ]

    # Fleet-wide domain score = the mean of each device's own score for
    # that domain, using the engine's already-computed per-run values
    # rather than recomputing any scoring in this layer.
    domain_acc: dict = {}
    for d in domain_rows:
        acc = domain_acc.setdefault(d.domain, {"scores": [], "fail": 0, "manual": 0})
        acc["scores"].append(d.score)
        acc["fail"] += d.fail_count
        acc["manual"] += d.manual_count
    domain_scores = sorted(
        (
            DashboardDomainScoreOut(
                domain=domain, score=round(sum(a["scores"]) / len(a["scores"]), 1),
                fail_count=a["fail"], manual_count=a["manual"],
            )
            for domain, a in domain_acc.items() if a["scores"]
        ),
        key=lambda d: d.score,
    )

    framework_acc: dict = {}
    for c in compliance_rows:
        acc = framework_acc.setdefault(c.framework, {"pass": 0, "fail": 0, "manual": 0})
        if c.status == "pass":
            acc["pass"] += 1
        elif c.status == "fail":
            acc["fail"] += 1
        elif c.status == "manual_review":
            acc["manual"] += 1
    compliance = []
    for framework, a in sorted(framework_acc.items()):
        scored = a["pass"] + a["fail"]
        compliance.append(DashboardComplianceOut(
            framework=framework, passed=a["pass"], failed=a["fail"], manual_review=a["manual"],
            percentage=round((a["pass"] / scored) * 100, 1) if scored else 0.0,
        ))

    per_run_severity: dict = {}
    for f in findings:
        if f.status != Status.FAIL.value:
            continue
        counts = per_run_severity.setdefault(f.audit_run_id, {"critical": 0, "high": 0, "medium": 0})
        if f.severity in counts:
            counts[f.severity] += 1

    risky_devices = sorted(
        (
            DashboardRiskyDeviceOut(
                device_id=str(r.device_id) if r.device_id else None, device_name=r.device_name,
                score=r.overall_score,
                risk_level=risk_level(r.overall_score) if r.overall_score is not None else None,
                critical=per_run_severity.get(r.id, {}).get("critical", 0),
                high=per_run_severity.get(r.id, {}).get("high", 0),
                medium=per_run_severity.get(r.id, {}).get("medium", 0),
            )
            for r in runs
        ),
        key=lambda d: (d.score if d.score is not None else 999),
    )[:10]

    run_by_id = {r.id: r for r in runs}
    top_risks = sorted(
        (
            DashboardTopRiskOut(
                check_id=f.check_id, title=f.title, severity=f.severity, domain=f.domain,
                device_name=run_by_id[f.audit_run_id].device_name,
                device_id=str(f.device_id) if f.device_id else None,
                risk=f.risk or None, audit_run_id=str(f.audit_run_id),
            )
            for f in findings
            if f.status == Status.FAIL.value and f.audit_run_id in run_by_id
        ),
        key=lambda f: _SEVERITY_RANK.get(f.severity, 99),
    )[:8]

    domain_row_by_run: dict = {}
    for d in domain_rows:
        domain_row_by_run.setdefault(d.audit_run_id, []).append(d)
    heatmap_domains = sorted({d.domain for d in domain_rows})
    heatmap = []
    for r in runs:
        for d in domain_row_by_run.get(r.id, []):
            heatmap.append(DashboardHeatmapCellOut(
                device_name=r.device_name, device_id=str(r.device_id) if r.device_id else None,
                domain=d.domain, score=d.score, fail_count=d.fail_count, manual_count=d.manual_count,
            ))

    # Score explanation: attribute the gap between a perfect score and
    # the actual one across domains. Each domain's shortfall
    # (100 - its own score) is weighted by its equal share of all
    # domains, so the parts sum to the whole gap.
    #
    # This is an ATTRIBUTION of the engine's own domain scores, not a
    # second scoring algorithm -- and it is flagged approximate,
    # because the engine's real denominator (`applicable_weight`) is
    # not persisted per domain, so exact weighted deductions cannot be
    # reconstructed from stored rows. Saying "approximate" is honest;
    # presenting it as exact would not be.
    score_explanation = None
    if domain_scores and average_score is not None:
        share = 1.0 / len(domain_scores)
        contributions = sorted(
            (
                ScoreContributionOut(
                    domain=d.domain, score=d.score,
                    points_lost=round((100.0 - d.score) * share, 1),
                    fail_count=d.fail_count, manual_count=d.manual_count,
                )
                for d in domain_scores
            ),
            key=lambda c: c.points_lost, reverse=True,
        )
        score_explanation = ScoreExplanationOut(
            base_score=100.0, final_score=average_score,
            total_deduction=round(sum(c.points_lost for c in contributions), 1),
            contributions=contributions, is_approximate=True,
        )

    # Manual review, broken down by the domain each item came from --
    # real domains from real findings, never a fixed category list.
    manual_by_domain: dict = {}
    for f in findings:
        if f.status == Status.MANUAL.value:
            manual_by_domain[f.domain] = manual_by_domain.get(f.domain, 0) + 1
    manual_review = ManualReviewOut(
        total=manual_review_findings,
        categories=[
            ManualReviewCategoryOut(domain=k, count=v)
            for k, v in sorted(manual_by_domain.items(), key=lambda kv: kv[1], reverse=True)
        ],
    )

    # Trend points come only from audit runs that really exist and
    # completed with a score -- one point per run, chronological. No
    # interpolation, no synthesized history: with a single audit the
    # chart gets exactly one point and the GUI says so.
    trend_runs = [r for r in reversed(all_completed) if r.overall_score is not None][-12:]
    score_trend = [
        DashboardTrendPointOut(
            label=r.started_at.strftime("%b %d %H:%M"), score=r.overall_score, audit_run_id=str(r.id),
        )
        for r in trend_runs
    ]

    return SecurityDashboardOut(
        devices_audited=len(runs), average_score=average_score,
        previous_average_score=previous_average_score, compliance_score=compliance_score,
        severity_counts=severity_counts, total_findings=len(findings),
        manual_review_findings=manual_review_findings, failed_checks=failed_checks,
        domain_scores=domain_scores, score_trend=score_trend, compliance=compliance,
        risky_devices=risky_devices, top_risks=top_risks,
        heatmap=heatmap, heatmap_domains=heatmap_domains,
        score_explanation=score_explanation, manual_review=manual_review,
    )


# Worst-status-wins ordering: if a control fails on ANY device it is a
# failing control for the fleet, regardless of how many devices pass.
_COMPLIANCE_STATUS_RANK = {"fail": 0, "manual_review": 1, "pass": 2, "na": 3}


@router.get("/compliance", response_model=ComplianceOverviewOut)
def get_compliance_overview(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    """
    Fleet-wide compliance posture, per framework and per control,
    built from each device's own most recent completed audit -- the
    same `_latest_completed_runs_by_device` basis every other Security
    Center view uses, so posture can't disagree between pages.

    Framework display names come from the mapping files' own
    `framework_name` field rather than a hardcoded lookup here, so
    adding or renaming a framework needs no change in this layer.
    Frameworks with no stored results are omitted entirely rather than
    shown at 0% -- an unmapped framework is "not assessed", which is a
    different thing from "assessed and failing", and rendering it as
    the latter would be a real misstatement of posture.
    """
    from ..security_center.compliance.loader import load_compliance_mappings

    latest_by_device = _latest_completed_runs_by_device(db)
    if not latest_by_device:
        return ComplianceOverviewOut(devices_audited=0, frameworks=[])

    run_ids = [r.id for r in latest_by_device.values()]
    rows = db.query(AuditComplianceResult).filter(AuditComplianceResult.audit_run_id.in_(run_ids)).all()

    names = {f["_framework_key"]: f.get("framework_name", f["_framework_key"]) for f in load_compliance_mappings()}

    # framework -> control_id -> {status: device_count}
    acc: dict = {}
    for row in rows:
        control = acc.setdefault(row.framework, {}).setdefault(row.control_id, {"pass": 0, "fail": 0, "manual_review": 0, "na": 0})
        if row.status in control:
            control[row.status] += 1

    frameworks = []
    for framework_key, controls in sorted(acc.items()):
        control_out = []
        passing = failing = manual = 0
        for control_id, counts in sorted(controls.items()):
            if counts["fail"]:
                status = "fail"
                failing += 1
            elif counts["manual_review"]:
                status = "manual_review"
                manual += 1
            elif counts["pass"]:
                status = "pass"
                passing += 1
            else:
                status = "na"
            control_out.append(ComplianceControlOut(
                control_id=control_id, devices_passing=counts["pass"],
                devices_failing=counts["fail"], devices_manual=counts["manual_review"], status=status,
            ))

        control_out.sort(key=lambda c: (_COMPLIANCE_STATUS_RANK.get(c.status, 9), c.control_id))
        scored = passing + failing
        frameworks.append(ComplianceFrameworkOut(
            framework_key=framework_key, framework_name=names.get(framework_key, framework_key),
            total_controls=len(control_out), passing_controls=passing, failing_controls=failing,
            manual_controls=manual,
            percentage=round((passing / scored) * 100, 1) if scored else 0.0,
            controls=control_out,
        ))

    return ComplianceOverviewOut(devices_audited=len(latest_by_device), frameworks=frameworks)


@router.get("/activity", response_model=list[ActivityEventOut])
def list_security_activity(
    limit: int = 25,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    """
    Recent audit activity, newest first -- one event per real AuditRun.

    `score_delta` compares each run against that SAME device's own
    chronologically-previous completed run, so "+8" means this device
    improved by 8 since its last audit, not that it differs from some
    fleet average. Runs with no earlier comparison point (a device's
    very first audit, or a failed run with no score) get a null delta
    and the GUI renders no arrow rather than implying a trend that
    doesn't exist.

    Ordering is done once over all runs rather than per-event queries:
    a naive implementation would issue one "previous run" lookup per
    row, which is the N+1 pattern this redesign exists to avoid.
    """
    limit = max(1, min(limit, 100))

    runs = db.query(AuditRun).order_by(AuditRun.started_at.desc()).limit(200).all()

    # Walk oldest-first per device so each run's predecessor is the run
    # immediately before it, then look deltas up by run id.
    by_device: dict = {}
    for run in sorted(runs, key=lambda r: r.started_at):
        by_device.setdefault(run.device_id, []).append(run)

    delta_by_run: dict = {}
    for device_runs in by_device.values():
        previous_score = None
        for run in device_runs:
            if run.overall_score is not None:
                if previous_score is not None:
                    delta_by_run[run.id] = round(run.overall_score - previous_score, 1)
                previous_score = run.overall_score

    return [
        ActivityEventOut(
            audit_run_id=str(run.id),
            device_id=str(run.device_id) if run.device_id else None,
            device_name=run.device_name, source=run.source, status=run.status,
            overall_score=run.overall_score, score_delta=delta_by_run.get(run.id),
            started_at=run.started_at,
        )
        for run in runs[:limit]
    ]


@router.post("/audit/bulk", response_model=BulkAuditResultOut, dependencies=[Depends(verify_csrf)])
def run_bulk_audit(
    payload: BulkAuditRequest,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:audit")),
):
    """
    Audits a chosen set of devices as one job, producing a single
    numbered Audit Report the same way the scheduled fleet job does --
    same pipeline, same batch model, just a narrower device list.

    Uses the platform's stored service account (Scheduled Audits) for
    SSH rather than prompting per run: that account exists precisely so
    unattended/bulk auditing doesn't require a human to re-enter
    credentials per device. If it isn't configured, this fails with a
    clear message pointing at where to set it up rather than silently
    auditing nothing.

    Gated on `security:audit` (not `security:view`) since this reaches
    out and touches real devices.
    """
    settings = db.query(AuditScheduleSettings).first()
    if not settings or not settings.ssh_username or not settings.ssh_password_encrypted:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            detail="No audit service account is configured. Set one up under Security Center → Scheduled Audits first.",
        )

    try:
        device_uuids = [uuid.UUID(d) for d in payload.device_ids]
    except ValueError:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="One or more device identifiers were malformed.")

    count = len(device_uuids)
    result = run_scheduled_audit(
        db, ssh_username=settings.ssh_username, ssh_password_encrypted=settings.ssh_password_encrypted,
        batch_source="manual", device_ids=device_uuids,
        target_description=f"{count} selected device{'s' if count != 1 else ''}",
    )

    return BulkAuditResultOut(
        batch_display_number=result.batch_display_number,
        total_devices=result.total_devices, succeeded=result.succeeded, failed=result.failed,
        status=result.status, summary=result.summary,
    )


@router.get("/compliance/{framework_key}/{control_id}", response_model=ComplianceControlDetailOut)
def get_compliance_control_detail(
    framework_key: str,
    control_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("security:view")),
):
    """
    Everything behind one compliance control: its real title from the
    framework mapping, and every actual audit finding that determines
    its status across the fleet.

    The mapping file is check_id -> [controls], so this inverts it to
    find which checks feed THIS control, then pulls those findings from
    each device's own latest completed audit. Nothing is generated:
    the recommendation and fix shown are the ones the audit engine
    already produced for that check.
    """
    from ..security_center.compliance.loader import load_compliance_mappings

    framework = next(
        (f for f in load_compliance_mappings() if f["_framework_key"] == framework_key), None
    )
    if framework is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Framework not found.")

    # Invert the mapping: which check_ids reference this control, and
    # with what relationship (direct vs supporting).
    relationship_by_check: dict[str, str] = {}
    control_title = ""
    for check_id, entries in (framework.get("checks") or {}).items():
        for entry in entries:
            if str(entry.get("control")) == control_id:
                relationship_by_check[check_id] = entry.get("relationship", "direct")
                control_title = control_title or entry.get("title", "")

    if not relationship_by_check:
        raise HTTPException(
            status.HTTP_404_NOT_FOUND,
            detail="That control is not referenced by any check in this framework's mapping.",
        )

    latest_runs = _latest_completed_runs_by_device(db)
    run_ids = [r.id for r in latest_runs.values()]
    device_name_by_run = {r.id: r.device_name for r in latest_runs.values()}
    device_id_by_run = {r.id: r.device_id for r in latest_runs.values()}

    findings: list[ComplianceFindingOut] = []
    if run_ids:
        rows = (
            db.query(AuditFinding)
            .filter(
                AuditFinding.audit_run_id.in_(run_ids),
                AuditFinding.check_id.in_(list(relationship_by_check.keys())),
            )
            .all()
        )
        for f in rows:
            findings.append(ComplianceFindingOut(
                check_id=f.check_id, title=f.title, domain=f.domain,
                status=f.status, severity=f.severity,
                device_name=device_name_by_run.get(f.audit_run_id, "Unknown device"),
                device_id=str(device_id_by_run.get(f.audit_run_id)) if device_id_by_run.get(f.audit_run_id) else None,
                recommendation=f.recommendation or "", fix_command=f.fix_command or "",
                why=f.why or "",
                relationship=relationship_by_check.get(f.check_id, "direct"),
            ))

    # Failing first, then manual review -- the order an operator works in.
    findings.sort(key=lambda f: (_COMPLIANCE_STATUS_RANK.get(f.status, 9), f.device_name, f.check_id))

    rows_for_control = (
        db.query(AuditComplianceResult)
        .filter(
            AuditComplianceResult.audit_run_id.in_(run_ids),
            AuditComplianceResult.framework == framework_key,
            AuditComplianceResult.control_id == control_id,
        )
        .all()
        if run_ids else []
    )
    counts = {"pass": 0, "fail": 0, "manual_review": 0}
    for r in rows_for_control:
        if r.status in counts:
            counts[r.status] += 1

    if counts["fail"]:
        overall = "fail"
    elif counts["manual_review"]:
        overall = "manual_review"
    elif counts["pass"]:
        overall = "pass"
    else:
        overall = "na"

    return ComplianceControlDetailOut(
        control_id=control_id, control_title=control_title or control_id,
        framework_key=framework_key, framework_name=framework.get("framework_name", framework_key),
        status=overall, devices_passing=counts["pass"], devices_failing=counts["fail"],
        devices_manual=counts["manual_review"], findings=findings,
    )
