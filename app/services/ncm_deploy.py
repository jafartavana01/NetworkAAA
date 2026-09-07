"""
app.services.ncm_deploy
==========================
Candidate lifecycle and configuration deployment -- NCM Phases 6-9.

This is the only part of NCM that WRITES to a device, and it is built
around that fact.

Safety model, in order of execution:

  1. The candidate must be `approved`. An unapproved candidate is
     never deployable, regardless of who asks.
  2. A fresh backup is taken IMMEDIATELY BEFORE the change. That
     snapshot -- not the last scheduled one -- is the rollback point.
     Rolling back to a stale backup would restore a state the device
     was never in at the moment of the change.
  3. If that pre-backup fails, the deployment ABORTS without touching
     the device. Changing a device you cannot roll back is the one
     outcome worth refusing outright.
  4. The commands are sent through the platform's existing
     `ssh_provision.apply_aaa_config`, which returns the device's own
     transcript. No second SSH implementation.
  5. A verification backup is taken after. Whether the device actually
     changed is derived from comparing real archived snapshots, never
     assumed from the commands having been accepted.

Rollback re-applies the pre-deployment configuration. Its limits are
stated plainly in `rollback_deployment` rather than implied.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sqlalchemy import func
from sqlalchemy.orm import Session

from .. import security
from ..models.audit_schedule_settings import AuditScheduleSettings
from ..models.device import NetworkDevice
from ..models.ncm import NcmCandidate, NcmConfiguration, NcmDeployment
from . import ncm_archive, ncm_drivers, ssh_provision

logger = logging.getLogger(__name__)

STATUS_DRAFT = "draft"
STATUS_PENDING = "pending_approval"
STATUS_APPROVED = "approved"
STATUS_REJECTED = "rejected"
STATUS_DEPLOYED = "deployed"
STATUS_CANCELLED = "cancelled"
STATUS_FAILED = "failed"

#: Allowed candidate transitions. Kept as data so the rules are
#: inspectable and testable, rather than scattered across if-statements
#: in the API layer where they could quietly diverge.
ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    STATUS_DRAFT: {STATUS_PENDING, STATUS_CANCELLED},
    STATUS_PENDING: {STATUS_APPROVED, STATUS_REJECTED, STATUS_CANCELLED},
    STATUS_APPROVED: {STATUS_DEPLOYED, STATUS_FAILED, STATUS_CANCELLED},
    STATUS_REJECTED: {STATUS_DRAFT, STATUS_CANCELLED},
    STATUS_FAILED: {STATUS_DRAFT, STATUS_CANCELLED},
    # Terminal.
    STATUS_DEPLOYED: set(),
    STATUS_CANCELLED: set(),
}

#: Commands refused outright. These either sever the platform's own
#: access to the device (leaving no way to roll back), or reload it.
#: This is a backstop against a typo in a reviewed change, not a
#: security boundary -- an operator with deploy rights can still do
#: harm, and the audit trail is what covers that.
DANGEROUS_PATTERNS = [
    (r"^\s*reload\b", "reload"),
    (r"^\s*no\s+aaa\s+new-model\b", "no aaa new-model"),
    (r"^\s*no\s+ip\s+ssh\b", "no ip ssh"),
    (r"^\s*no\s+username\b", "no username"),
    (r"^\s*no\s+line\s+vty\b", "no line vty"),
    (r"^\s*no\s+interface\s+", "no interface"),
    (r"^\s*erase\b", "erase"),
    (r"^\s*format\b", "format"),
    (r"^\s*delete\b", "delete"),
]


def check_dangerous_commands(lines: list[str]) -> list[str]:
    """Returns the human-readable names of refused commands found."""
    found = []
    for line in lines:
        for pattern, label in DANGEROUS_PATTERNS:
            if re.match(pattern, line, re.IGNORECASE):
                found.append(label)
    return sorted(set(found))


def parse_configuration_lines(raw: str) -> list[str]:
    """Splits stored candidate text into commands, dropping blanks and
    comment lines so they are never sent to a device."""
    out = []
    for line in (raw or "").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("!") or stripped.startswith("#"):
            continue
        out.append(stripped)
    return out


def can_transition(current: str, target: str) -> bool:
    return target in ALLOWED_TRANSITIONS.get(current, set())


def _sanitise_transcript(text: str) -> str:
    """
    Removes anything resembling a credential before the transcript is
    stored. A device echoes what it is sent, so a candidate containing
    a key or password would otherwise land in the database in clear
    text via the transcript -- the one path by which this feature could
    leak a secret it was never given.
    """
    if not text:
        return ""
    patterns = [
        (r"(key\s+\S+)", "key <redacted>"),
        (r"(password\s+\S+)", "password <redacted>"),
        (r"(secret\s+\S+)", "secret <redacted>"),
        (r"(community\s+\S+)", "community <redacted>"),
    ]
    out = text
    for pattern, replacement in patterns:
        out = re.sub(pattern, replacement, out, flags=re.IGNORECASE)
    return out[:100000]


@dataclass
class DeployOutcome:
    ok: bool
    status: str
    deployment_number: int = 0
    verified_changed: bool = False
    message: str = ""
    transcript: str = ""
    blocked_commands: list = field(default_factory=list)


def _next_number(db: Session, model) -> int:
    return (db.query(func.max(model.display_number)).scalar() or 0) + 1


def _backup_now(db: Session, device: NetworkDevice, username: str, password: str,
                source: str, actor: str | None) -> NcmConfiguration | None:
    """Takes a real backup and archives it, returning the snapshot (or
    the existing one if unchanged). None means retrieval failed."""
    driver = ncm_drivers.get_driver(getattr(device, "vendor", None))
    result = driver.get_configuration(
        device.ip_address.split("/")[0].strip(), username, password, "running",
    )
    if not result.ok:
        return None
    archived = ncm_archive.archive_configuration(
        db, device_id=device.id, device_name=device.name,
        configuration_type="running", content=result.content,
        source=source, created_by=actor,
    )
    db.commit()
    return archived.configuration


def deploy_candidate(db: Session, candidate: NcmCandidate, *, actor: str | None) -> DeployOutcome:
    """
    Deploys an APPROVED candidate. See this module's docstring for the
    ordering and why each step exists.
    """
    if candidate.status != STATUS_APPROVED:
        return DeployOutcome(
            ok=False, status=candidate.status,
            message=f"Only an approved candidate can be deployed (this one is '{candidate.status}').",
        )

    commands = parse_configuration_lines(candidate.configuration_lines)
    if not commands:
        return DeployOutcome(ok=False, status=candidate.status, message="The candidate has no commands to send.")

    blocked = check_dangerous_commands(commands)
    if blocked:
        return DeployOutcome(
            ok=False, status=candidate.status, blocked_commands=blocked,
            message="Refused: the candidate contains commands that could sever access or reload the device.",
        )

    device = db.query(NetworkDevice).filter(NetworkDevice.id == candidate.device_id).first()
    if not device:
        return DeployOutcome(ok=False, status=candidate.status, message="Device not found.")

    settings = db.query(AuditScheduleSettings).first()
    if not settings or not settings.ssh_username or not settings.ssh_password_encrypted:
        return DeployOutcome(
            ok=False, status=candidate.status,
            message="No service account is configured, so the device cannot be reached.",
        )
    username = settings.ssh_username
    password = security.decrypt_secret(settings.ssh_password_encrypted)

    deployment = NcmDeployment(
        display_number=_next_number(db, NcmDeployment),
        candidate_id=candidate.id, device_id=device.id, device_name=device.name,
        status="running", started_by=actor,
    )
    db.add(deployment)
    db.commit()
    db.refresh(deployment)

    # STEP 1 -- rollback point. Abort if this fails: changing a device
    # you cannot roll back is the one outcome worth refusing outright.
    pre = _backup_now(db, device, username, password, "pre-deployment", actor)
    if pre is None:
        deployment.status = "failed"
        deployment.error_message = (
            "Aborted before touching the device: the pre-deployment backup failed, "
            "so there would be no rollback point."
        )
        deployment.completed_at = datetime.now(timezone.utc)
        db.commit()
        return DeployOutcome(ok=False, status="failed", deployment_number=deployment.display_number,
                             message=deployment.error_message)
    deployment.pre_configuration_id = pre.id
    db.commit()

    # STEP 2 -- send. Wrapped so `configure terminal`/`end` are always
    # balanced regardless of what the operator wrote, and the change is
    # saved to startup-config.
    wrapped = ["configure terminal", *commands, "end", "write memory"]
    result = ssh_provision.apply_aaa_config(
        device.ip_address.split("/")[0].strip(), username, password, commands=wrapped,
    )
    transcript = _sanitise_transcript("\n".join(result.command_log or []))
    deployment.transcript = transcript

    if not result.success:
        deployment.status = "failed"
        deployment.error_message = (result.message or "Deployment failed.")[:500]
        deployment.completed_at = datetime.now(timezone.utc)
        candidate.status = STATUS_FAILED
        db.commit()
        return DeployOutcome(ok=False, status="failed", deployment_number=deployment.display_number,
                             message=deployment.error_message, transcript=transcript)

    # STEP 3 -- verify from a real backup, never from the commands
    # having been accepted.
    post = _backup_now(db, device, username, password, "post-deployment", actor)
    if post is not None:
        deployment.post_configuration_id = post.id
        deployment.verified_changed = bool(pre and post.sha256 != pre.sha256)
    else:
        deployment.error_message = (
            "Configuration was sent, but the verification backup failed -- "
            "the change could not be confirmed against the device."
        )

    deployment.status = "succeeded"
    deployment.completed_at = datetime.now(timezone.utc)
    candidate.status = STATUS_DEPLOYED
    db.commit()

    return DeployOutcome(
        ok=True, status="succeeded", deployment_number=deployment.display_number,
        verified_changed=deployment.verified_changed, transcript=transcript,
        message=(
            "Deployed and verified: the device configuration changed."
            if deployment.verified_changed
            else "Deployed, but the configuration is unchanged from before -- "
                 "the commands may have had no effect."
        ),
    )


def rollback_deployment(db: Session, deployment: NcmDeployment, *, actor: str | None) -> DeployOutcome:
    """
    Re-applies the pre-deployment configuration.

    Honest limits, stated rather than implied:
      * This REPLAYS the archived pre-deployment configuration as
        commands. On Cisco IOS that reliably restores settings the
        change MODIFIED, but it does NOT remove lines the change ADDED
        -- undoing an addition requires the corresponding `no` form,
        which this platform cannot derive safely (see NcmCandidate).
      * The post-rollback state is therefore verified against the
        pre-deployment snapshot and reported honestly as matching or
        not, rather than being declared successful because the commands
        were accepted.
    """
    if deployment.pre_configuration_id is None:
        return DeployOutcome(ok=False, status=deployment.status,
                             message="This deployment has no pre-deployment snapshot to roll back to.")

    pre = db.query(NcmConfiguration).filter(
        NcmConfiguration.id == deployment.pre_configuration_id
    ).first()
    if pre is None:
        return DeployOutcome(ok=False, status=deployment.status,
                             message="The pre-deployment snapshot is no longer in the archive.")

    device = db.query(NetworkDevice).filter(NetworkDevice.id == deployment.device_id).first()
    if not device:
        return DeployOutcome(ok=False, status=deployment.status, message="Device not found.")

    settings = db.query(AuditScheduleSettings).first()
    if not settings or not settings.ssh_username or not settings.ssh_password_encrypted:
        return DeployOutcome(ok=False, status=deployment.status,
                             message="No service account is configured, so the device cannot be reached.")
    username = settings.ssh_username
    password = security.decrypt_secret(settings.ssh_password_encrypted)

    commands = parse_configuration_lines(pre.configuration_content)
    blocked = check_dangerous_commands(commands)
    if blocked:
        # The archived config legitimately contains lines that look
        # dangerous out of context. Refusing is the safe read: an
        # operator can still restore by hand from the archive.
        return DeployOutcome(
            ok=False, status=deployment.status, blocked_commands=blocked,
            message="Refused: the archived configuration contains commands that cannot be replayed safely.",
        )

    wrapped = ["configure terminal", *commands, "end", "write memory"]
    result = ssh_provision.apply_aaa_config(
        device.ip_address.split("/")[0].strip(), username, password, commands=wrapped,
    )
    transcript = _sanitise_transcript("\n".join(result.command_log or []))

    if not result.success:
        deployment.status = "rollback_failed"
        deployment.error_message = (result.message or "Rollback failed.")[:500]
        db.commit()
        return DeployOutcome(ok=False, status="rollback_failed", transcript=transcript,
                             message=deployment.error_message)

    after = _backup_now(db, device, username, password, "post-rollback", actor)
    matched = bool(after is not None and after.sha256 == pre.sha256)

    deployment.status = "rolled_back"
    deployment.completed_at = datetime.now(timezone.utc)
    db.commit()

    return DeployOutcome(
        ok=True, status="rolled_back", deployment_number=deployment.display_number,
        verified_changed=matched, transcript=transcript,
        message=(
            "Rolled back: the device now matches the pre-deployment configuration."
            if matched
            else "Rollback commands were applied, but the device does NOT byte-match the "
                 "pre-deployment snapshot -- lines the change ADDED are not removed by "
                 "replaying the old configuration. Review the diff."
        ),
    )
