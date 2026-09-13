"""
app.api.routes_network_ops
=============================
Network Operations & Assurance Engine, Phase 1: command templates and
command jobs. See app.services.network_ops_execution for target
resolution, command classification, and the SSH execution/orchestration
engine this module drives.

Permission gating follows this project's existing RBAC convention
(app.services.permissions) exactly: `network_ops:view` for read
access, `network_ops:execute` for creating/running jobs,
`network_ops:templates` for managing the reusable template library --
three distinct actions because "can see job history" and "can push
commands to live devices" and "can change what a saved template will
run for everyone next time" are genuinely different privilege levels,
the same reasoning that already separates devices:view from
devices:write elsewhere in this catalog.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.command_job import CommandExecution, CommandJob, CommandJobTarget
from ..models.command_template import CommandTemplate
from ..schemas.network_ops import (
    CommandExecutionOut,
    CommandJobCreate,
    CommandJobDetailOut,
    CommandJobOut,
    CommandJobTargetOut,
    CommandTemplateCreate,
    CommandTemplateOut,
    ResolvedTargetOut,
    TargetSelection,
)
from ..services import network_ops_execution
from .deps import require_permission, verify_csrf

router = APIRouter(prefix="/api/network-ops", tags=["network-ops"])


# ---------- Command Templates ----------

@router.get("/templates", response_model=list[CommandTemplateOut])
def list_templates(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:view")),
):
    templates = db.query(CommandTemplate).order_by(CommandTemplate.name.asc()).all()
    return [_template_to_out(t) for t in templates]


@router.post("/templates", response_model=CommandTemplateOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_template(
    payload: CommandTemplateCreate,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("network_ops:templates")),
):
    if db.query(CommandTemplate).filter(CommandTemplate.name == payload.name).first():
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A template named '{payload.name}' already exists.")
    template = CommandTemplate(
        name=payload.name, description=payload.description, vendor=payload.vendor,
        platform=payload.platform, device_role=payload.device_role, commands=payload.commands,
        command_timeout_seconds=payload.command_timeout_seconds, created_by_admin_id=admin.id,
    )
    db.add(template)
    db.commit()
    db.refresh(template)
    return _template_to_out(template)


@router.put("/templates/{template_id}", response_model=CommandTemplateOut, dependencies=[Depends(verify_csrf)])
def update_template(
    template_id: str,
    payload: CommandTemplateCreate,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:templates")),
):
    template = _get_template_or_404(db, template_id)
    duplicate = db.query(CommandTemplate).filter(CommandTemplate.name == payload.name, CommandTemplate.id != template.id).first()
    if duplicate:
        raise HTTPException(status.HTTP_409_CONFLICT, detail=f"A template named '{payload.name}' already exists.")
    template.name = payload.name
    template.description = payload.description
    template.vendor = payload.vendor
    template.platform = payload.platform
    template.device_role = payload.device_role
    template.commands = payload.commands
    template.command_timeout_seconds = payload.command_timeout_seconds
    db.commit()
    db.refresh(template)
    return _template_to_out(template)


@router.delete("/templates/{template_id}", status_code=status.HTTP_204_NO_CONTENT, dependencies=[Depends(verify_csrf)])
def delete_template(
    template_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:templates")),
):
    template = _get_template_or_404(db, template_id)
    db.delete(template)
    db.commit()


def _get_template_or_404(db: Session, template_id: str) -> CommandTemplate:
    try:
        parsed = uuid.UUID(template_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Template not found.")
    template = db.query(CommandTemplate).filter(CommandTemplate.id == parsed).first()
    if not template:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Template not found.")
    return template


def _template_to_out(t: CommandTemplate) -> CommandTemplateOut:
    return CommandTemplateOut(
        id=str(t.id), name=t.name, description=t.description, vendor=t.vendor,
        platform=t.platform, device_role=t.device_role, commands=t.commands,
        command_timeout_seconds=t.command_timeout_seconds, created_at=t.created_at, updated_at=t.updated_at,
    )


# ---------- Target preview ----------

@router.post("/preview-targets", response_model=list[ResolvedTargetOut], dependencies=[Depends(verify_csrf)])
def preview_targets(
    payload: TargetSelection,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:view")),
):
    """Read-only -- resolves and deduplicates a target selection
    without creating anything, backing the "Preview Targets" button
    (spec section 5) so an admin can see exactly which devices a job
    would run against before committing to it."""
    resolved = network_ops_execution.resolve_targets(
        db, device_ids=payload.device_ids, device_group_ids=payload.device_group_ids,
    )
    return [ResolvedTargetOut(device_id=r.device_id, device_name=r.device_name, device_ip_address=r.device_ip_address, resolved_from=r.resolved_from) for r in resolved]


# ---------- Command Jobs ----------

@router.post("/jobs", response_model=CommandJobOut, status_code=status.HTTP_201_CREATED, dependencies=[Depends(verify_csrf)])
def create_job(
    payload: CommandJobCreate,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    admin: AdminUser = Depends(require_permission("network_ops:execute")),
):
    """
    Resolves targets, snapshots the command list (from the raw box or
    a template -- never a live template reference, so editing a
    template later never rewrites an already-run job's history, per
    the same snapshot principle CommandJobTarget applies to device
    group membership), creates the CommandJob/CommandJobTarget rows,
    and immediately starts execution as a background task -- the
    response returns as soon as the rows exist, not when the job
    finishes; the GUI polls GET /jobs/{id} for live progress.
    """
    if payload.template_id:
        try:
            parsed_template_id = uuid.UUID(payload.template_id)
        except ValueError:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Invalid template id.")
        template = db.query(CommandTemplate).filter(CommandTemplate.id == parsed_template_id).first()
        if not template:
            raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="That template doesn't exist.")
        commands = list(template.commands)
        source_template_id = template.id
        source_template_name = template.name
    elif payload.commands:
        commands = payload.commands
        source_template_id = None
        source_template_name = None
    else:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="Provide either a template_id or a commands list.")

    resolved = network_ops_execution.resolve_targets(
        db, device_ids=payload.targets.device_ids, device_group_ids=payload.targets.device_group_ids,
    )
    if not resolved:
        raise HTTPException(status.HTTP_400_BAD_REQUEST, detail="No devices resolved from the given targets.")

    job = CommandJob(
        name=payload.name, description=payload.description, commands=commands,
        source_template_id=source_template_id, source_template_name=source_template_name,
        execution_mode=payload.execution_mode, concurrency=payload.concurrency,
        command_timeout_seconds=payload.command_timeout_seconds,
        connection_timeout_seconds=payload.connection_timeout_seconds,
        status="PENDING", created_by_admin_id=admin.id, created_by_admin_username=admin.username,
    )
    db.add(job)
    db.flush()  # assigns job.id without committing yet, so targets can reference it in the same transaction

    for target in resolved:
        db.add(CommandJobTarget(
            job_id=job.id, device_id=target.device_id, device_name=target.device_name,
            device_ip_address=target.device_ip_address, resolved_from=target.resolved_from, status="PENDING",
        ))
    db.commit()
    db.refresh(job)

    background_tasks.add_task(
        network_ops_execution.run_job, str(job.id),
        ssh_username=payload.ssh_username, ssh_password=payload.ssh_password,
    )

    return _job_to_out(db, job)


@router.get("/jobs", response_model=list[CommandJobOut])
def list_jobs(
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:view")),
):
    jobs = db.query(CommandJob).order_by(CommandJob.created_at.desc()).limit(200).all()
    return [_job_to_out(db, j) for j in jobs]


@router.get("/jobs/{job_id}", response_model=CommandJobDetailOut)
def get_job(
    job_id: str,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(require_permission("network_ops:view")),
):
    job = _get_job_or_404(db, job_id)
    targets = db.query(CommandJobTarget).filter(CommandJobTarget.job_id == job.id).all()
    target_outs = []
    for t in targets:
        executions = (
            db.query(CommandExecution)
            .filter(CommandExecution.job_target_id == t.id)
            .order_by(CommandExecution.command_order.asc())
            .all()
        )
        target_outs.append(CommandJobTargetOut(
            id=str(t.id), device_id=str(t.device_id) if t.device_id else None, device_name=t.device_name,
            device_ip_address=t.device_ip_address, resolved_from=t.resolved_from, status=t.status,
            error_message=t.error_message,
            executions=[
                CommandExecutionOut(
                    id=str(e.id), command=e.command, command_order=e.command_order,
                    command_classification=e.command_classification, status=e.status,
                    raw_output=e.raw_output, error_message=e.error_message, duration_ms=e.duration_ms,
                ) for e in executions
            ],
        ))

    base = _job_to_out(db, job)
    return CommandJobDetailOut(**base.model_dump(), targets=target_outs)


def _get_job_or_404(db: Session, job_id: str) -> CommandJob:
    try:
        parsed = uuid.UUID(job_id)
    except ValueError:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Job not found.")
    job = db.query(CommandJob).filter(CommandJob.id == parsed).first()
    if not job:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Job not found.")
    return job


def _job_to_out(db: Session, job: CommandJob) -> CommandJobOut:
    target_count = db.query(CommandJobTarget).filter(CommandJobTarget.job_id == job.id).count()
    return CommandJobOut(
        id=str(job.id), name=job.name, description=job.description, commands=job.commands,
        source_template_name=job.source_template_name, execution_mode=job.execution_mode,
        concurrency=job.concurrency, status=job.status,
        created_by_admin_username=job.created_by_admin_username, created_at=job.created_at,
        started_at=job.started_at, completed_at=job.completed_at, target_count=target_count,
    )
