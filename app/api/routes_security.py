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
from ..models.audit_run import AuditComplianceResult, AuditDomainScore, AuditFinding, AuditRun
from ..models.audit_schedule_settings import AuditScheduleSettings
from ..models.device import NetworkDevice
from ..schemas.security_audit import (
    AuditCompareOut, AuditLiveRequest, AuditRunDetailOut, AuditRunSummaryOut, AuditScheduleOut,
    AuditScheduleUpdateRequest, AuditUploadRequest, DomainScoreOut, FindingOut, FleetFindingOut,
    SecurityDeviceOut, SecurityOverviewOut,
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

    result = run_scheduled_audit(db, ssh_username=s.ssh_username, ssh_password_encrypted=s.ssh_password_encrypted)
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
