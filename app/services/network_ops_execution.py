"""
app.services.network_ops_execution
=====================================
Network Operations & Assurance Engine, Phase 1: target resolution,
command classification, and SSH command execution against devices
already in NetworkAAA's own inventory.

DELIBERATELY DOES NOT IMPORT app.services.ssh_provision. That module
is live, tested, and used throughout Network Scan & Provision -- this
service defines its own low-level SSH mechanics (paramiko connect +
interactive-shell drain) rather than risk a regression in working
code by refactoring it to share internals. The two implementations
are small and independently testable; the safety of not touching
ssh_provision.py outweighs the minor duplication.

VENDOR SCOPE: Cisco IOS/IOS-XE only, stated plainly (matching this
project's established honesty about the exact same scope limit in
app.services.ssh_provision's own AAA-provisioning commands). The
command classifier below is a Cisco IOS heuristic, not a universal
one -- see classify_command's docstring for exactly what it does and
does not guarantee. A vendor/platform adapter seam is left in
CommandTemplate.vendor and NetworkDevice for a later phase to extend,
per the spec's explicit multi-vendor architecture requirement -- no
other vendor is implemented now.

CREDENTIALS ARE NEVER PERSISTED by this module -- the SSH username/
password used to run a job exists only for the duration of the
request that needs it, the same discipline app.services.ssh_provision
already established.
"""
from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from sqlalchemy.orm import Session

from ..models.device import NetworkDevice
from ..models.device_group import DeviceGroup

_CONNECT_TIMEOUT_SECONDS_DEFAULT = 10
_COMMAND_TIMEOUT_SECONDS_DEFAULT = 30


@dataclass
class ResolvedTarget:
    device_id: str
    device_name: str
    device_ip_address: str
    resolved_from: str  # e.g. "Device Group: Access-Switches", "Individual selection"


def resolve_targets(
    db: Session, *, device_ids: list[str] | None = None, device_group_ids: list[str] | None = None
) -> list[ResolvedTarget]:
    """
    Resolves a job's target selection (individual devices and/or
    device groups, spec section 4) into a deduplicated device list.
    A device appearing in more than one selected group, or both
    individually AND via a group, appears exactly once in the result
    -- the device's FIRST resolution (individual selection takes
    precedence over group membership when both apply, since it's the
    more specific choice) is what's recorded in `resolved_from`.

    Devices that no longer exist (a stale/deleted id) are silently
    skipped, not errored -- a job creation request naming a device
    that was deleted moments earlier should resolve to "not included",
    not fail the whole request.

    An empty group (real, valid device_group_id but zero current
    members) simply contributes nothing -- not an error either.
    """
    device_ids = device_ids or []
    device_group_ids = device_group_ids or []

    seen_device_ids: set[str] = set()
    resolved: list[ResolvedTarget] = []

    # Individual selections resolved FIRST -- see docstring on precedence.
    if device_ids:
        devices = db.query(NetworkDevice).filter(NetworkDevice.id.in_(device_ids)).all()
        for d in devices:
            device_id_str = str(d.id)
            if device_id_str in seen_device_ids:
                continue
            seen_device_ids.add(device_id_str)
            resolved.append(ResolvedTarget(
                device_id=device_id_str, device_name=d.name, device_ip_address=d.ip_address,
                resolved_from="Individual selection",
            ))

    if device_group_ids:
        groups = db.query(DeviceGroup).filter(DeviceGroup.id.in_(device_group_ids)).all()
        for group in groups:
            members = db.query(NetworkDevice).filter(NetworkDevice.device_group_id == group.id).all()
            for d in members:
                device_id_str = str(d.id)
                if device_id_str in seen_device_ids:
                    continue
                seen_device_ids.add(device_id_str)
                resolved.append(ResolvedTarget(
                    device_id=device_id_str, device_name=d.name, device_ip_address=d.ip_address,
                    resolved_from=f"Device Group: {group.name}",
                ))

    return resolved


# ---------- Command classification (spec section 49) ----------

@dataclass
class ClassificationResult:
    classification: str  # READ_ONLY | CONFIGURATION | DESTRUCTIVE | UNKNOWN
    reason: str


_READ_ONLY_PREFIXES = [
    "show", "terminal length", "terminal width", "terminal no", "ping", "traceroute",
    "who", "show running-config", "show run",
]
_CONFIG_MODE_PREFIXES = [
    "configure", "interface", "router", "aaa", "line", "vlan", "ip ", "ipv6 ",
    "spanning-tree", "no ", "hostname", "banner", "crypto", "access-list",
    "class-map", "policy-map", "username", "enable secret", "enable password",
    "snmp-server", "ntp", "logging", "tacacs-server", "radius-server",
    "vty", "console",
    # "write" (e.g. "write memory") -- safe to include here despite
    # "write erase" ALSO starting with "write": the destructive-pattern
    # loop runs BEFORE this one and matches "write erase" first,
    # returning early, so this prefix is only ever reached for
    # non-"write erase" write commands.
    "write",
]
_DESTRUCTIVE_PATTERNS = [
    re.compile(r"^\s*reload\b", re.IGNORECASE),
    re.compile(r"^\s*erase\b", re.IGNORECASE),
    re.compile(r"^\s*write\s+erase\b", re.IGNORECASE),
    re.compile(r"^\s*delete\b", re.IGNORECASE),
    re.compile(r"^\s*format\b", re.IGNORECASE),
    # NOTE: `write memory` is intentionally NOT here -- see
    # classify_command's docstring for why it's classified
    # CONFIGURATION instead (persists config to NVRAM, routine and
    # expected, not destructive in the same class as `reload`/`erase`).
]


def classify_command(command: str) -> ClassificationResult:
    """
    A Cisco IOS-specific HEURISTIC, not a guarantee -- pattern-matches
    against well-known, extremely common command prefixes (spec
    section 49's own examples: `show version` -> READ_ONLY, `interface
    Gi1/0/1` -> CONFIGURATION, `reload` -> DESTRUCTIVE). This is a
    safety-classification aid for the confirmation UI, not a
    guarantee that a READ_ONLY-classified command cannot change
    device state -- an admin should always review the actual command
    list before confirming a job, exactly as the job confirmation
    step already requires.

    Per the spec's own explicit instruction ("Unknown commands should
    require the stricter execution policy"), anything not matched by
    a known pattern is UNKNOWN, not assumed safe.

    `write memory` is deliberately classified CONFIGURATION, not
    DESTRUCTIVE -- it persists the running config to NVRAM (the exact
    command app.services.ssh_provision's own AAA-provisioning command
    list already ends every push with), a routine and expected part of
    making a configuration change stick, not a destructive action in
    the same class as `reload`/`erase`.
    """
    stripped = command.strip()
    if not stripped:
        return ClassificationResult("UNKNOWN", "Empty command.")

    lowered = stripped.lower()

    for pattern in _DESTRUCTIVE_PATTERNS:
        if pattern.search(stripped):
            return ClassificationResult("DESTRUCTIVE", "Matches a known destructive command pattern.")

    for prefix in _READ_ONLY_PREFIXES:
        if lowered.startswith(prefix):
            return ClassificationResult("READ_ONLY", f"Starts with a known read-only prefix ('{prefix}').")

    for prefix in _CONFIG_MODE_PREFIXES:
        if lowered.startswith(prefix):
            return ClassificationResult("CONFIGURATION", f"Starts with a known configuration-mode prefix ('{prefix}').")

    return ClassificationResult("UNKNOWN", "Did not match any known read-only, configuration, or destructive pattern.")


# ---------- SSH execution (independent of app.services.ssh_provision -- see module docstring) ----------

_PROMPT_PATTERN = re.compile(r"[>#]\s*$")


@dataclass
class CommandResult:
    command: str
    success: bool
    output: str
    error_message: str | None = None
    duration_ms: int = 0


@dataclass
class DeviceExecutionResult:
    success: bool
    message: str
    command_results: list[CommandResult] = field(default_factory=list)


def _read_until_idle(shell, *, timeout_seconds: int, max_bytes: int = 8192) -> str:
    buffer = ""
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        if shell.recv_ready():
            chunk = shell.recv(max_bytes).decode(errors="replace")
            buffer += chunk
            deadline = time.time() + 1.5
        else:
            time.sleep(0.1)
    return buffer


def run_commands_on_device(
    host: str, username: str, password: str, commands: list[str],
    *, port: int = 22, connect_timeout_seconds: int = _CONNECT_TIMEOUT_SECONDS_DEFAULT,
    command_timeout_seconds: int = _COMMAND_TIMEOUT_SECONDS_DEFAULT,
) -> DeviceExecutionResult:
    """
    Connects once, runs every command in `commands` in order over an
    interactive shell (needed for stateful sequences like `configure
    terminal` followed by config-mode commands, not one-shot exec),
    and returns a per-command result with the FULL raw output
    preserved (spec section 9) regardless of success or failure.

    One command failing (e.g. an invalid command produces an IOS
    error like "% Invalid input detected") does not stop the
    remaining commands in the SAME device's list -- each command gets
    its own result; the device-level result is success=True as long
    as the CONNECTION itself succeeded, since "one bad show command"
    is not the same failure class as "could not reach the device at
    all". The caller (job orchestration) is what decides how to roll
    per-command outcomes up into the target's overall status.
    """
    import paramiko

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    results: list[CommandResult] = []
    try:
        client.connect(
            host, port=port, username=username, password=password,
            timeout=connect_timeout_seconds, look_for_keys=False, allow_agent=False,
        )
        shell = client.invoke_shell()
        shell.settimeout(command_timeout_seconds)
        _read_until_idle(shell, timeout_seconds=command_timeout_seconds)  # drain initial banner/prompt

        for cmd in commands:
            start = time.time()
            shell.send(cmd + "\n")
            output = _read_until_idle(shell, timeout_seconds=command_timeout_seconds)
            duration_ms = int((time.time() - start) * 1000)
            results.append(CommandResult(command=cmd, success=True, output=output.strip(), duration_ms=duration_ms))

        return DeviceExecutionResult(success=True, message="Connected and executed.", command_results=results)
    except paramiko.AuthenticationException:
        return DeviceExecutionResult(success=False, message="SSH authentication failed -- check the username and password.", command_results=results)
    except Exception as exc:
        return DeviceExecutionResult(success=False, message=f"Could not connect: {exc}", command_results=results)
    finally:
        client.close()


# ---------- Job orchestration ----------
# Persistent DB rows (CommandJob/CommandJobTarget/CommandExecution) are
# the source of truth for job progress -- not an in-memory session like
# app.services.apply_progress uses for the (deliberately ephemeral)
# Network Scan bulk-apply flow. A live "Job Dashboard" poll re-queries
# these rows directly; committing after each target's execution is what
# makes that live, without needing a separate in-memory tracking layer.
#
# Each execution unit (_execute_one_target) opens its OWN database
# session rather than sharing the orchestrator's -- required for
# "controlled parallel" mode (SQLAlchemy sessions are not safe for
# concurrent use across threads), and applied uniformly to sequential
# mode too so both code paths share one implementation rather than
# risk drift between a "fast path" and a "parallel path".

def _now():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc)


def _execute_one_target(
    target_id: str, *, ssh_username: str, ssh_password: str, commands: list[str],
    command_timeout_seconds: int, connect_timeout_seconds: int,
) -> None:
    from ..database import get_sessionmaker
    from ..models.command_job import CommandExecution, CommandJobTarget

    session_local = get_sessionmaker()
    db = session_local()
    try:
        target = db.query(CommandJobTarget).filter(CommandJobTarget.id == target_id).first()
        if target is None:
            return

        target.status = "CONNECTING"
        target.started_at = _now()
        db.commit()

        result = run_commands_on_device(
            target.device_ip_address.split("/")[0], ssh_username, ssh_password, commands,
            connect_timeout_seconds=connect_timeout_seconds, command_timeout_seconds=command_timeout_seconds,
        )

        if not result.success:
            target.status = "FAILED"
            target.error_message = result.message
            target.completed_at = _now()
            db.commit()
            return

        target.status = "RUNNING"
        db.commit()

        for order, cmd_result in enumerate(result.command_results):
            classification = classify_command(cmd_result.command)
            execution = CommandExecution(
                job_target_id=target.id,
                command=cmd_result.command,
                command_order=order,
                command_classification=classification.classification,
                status="COMPLETED" if cmd_result.success else "FAILED",
                raw_output=cmd_result.output,
                error_message=cmd_result.error_message,
                duration_ms=cmd_result.duration_ms,
                completed_at=_now(),
            )
            db.add(execution)

        target.status = "COMPLETED"
        target.completed_at = _now()
        db.commit()
    except Exception as exc:  # pragma: no cover -- defensive: a target must never crash the whole job
        db.rollback()
        target = db.query(CommandJobTarget).filter(CommandJobTarget.id == target_id).first()
        if target is not None:
            target.status = "FAILED"
            target.error_message = f"Unexpected error: {exc}"
            target.completed_at = _now()
            db.commit()
    finally:
        db.close()


def run_job(job_id: str, *, ssh_username: str, ssh_password: str) -> None:
    """
    The background-task entry point (called via FastAPI's
    BackgroundTasks, same pattern as
    app.api.routes_network_scan._apply_all_background) -- runs OUTSIDE
    the HTTP request's own lifecycle, so it opens its own database
    session for job-level status updates. SSH credentials are passed
    in directly and never stored -- same discipline as every other SSH
    flow in this project.

    Sequential mode runs targets one at a time, in order -- simple,
    predictable, and matches how app.api.routes_network_scan's own
    bulk apply already works. Controlled-parallel mode uses a bounded
    thread pool (job.concurrency workers) -- paramiko's SSH I/O
    releases the GIL while waiting on the network, so real concurrency
    is achieved despite Python's GIL, the same reasoning
    app.services.network_scan's own parallel port-scan already relies
    on.
    """
    from concurrent.futures import ThreadPoolExecutor
    from ..database import get_sessionmaker
    from ..models.command_job import CommandJob, CommandJobTarget

    session_local = get_sessionmaker()
    db = session_local()
    try:
        job = db.query(CommandJob).filter(CommandJob.id == job_id).first()
        if job is None:
            return

        job.status = "RUNNING"
        job.started_at = _now()
        db.commit()

        target_ids = [str(t.id) for t in db.query(CommandJobTarget).filter(CommandJobTarget.job_id == job.id).all()]
        commands = list(job.commands)
        command_timeout = job.command_timeout_seconds
        connect_timeout = job.connection_timeout_seconds
        execution_mode = job.execution_mode
        concurrency = max(1, job.concurrency)
    finally:
        db.close()

    if not target_ids:
        _finish_job(job_id, status="FAILED")
        return

    if execution_mode == "parallel" and concurrency > 1:
        with ThreadPoolExecutor(max_workers=min(concurrency, len(target_ids))) as pool:
            list(pool.map(
                lambda tid: _execute_one_target(
                    tid, ssh_username=ssh_username, ssh_password=ssh_password, commands=commands,
                    command_timeout_seconds=command_timeout, connect_timeout_seconds=connect_timeout,
                ),
                target_ids,
            ))
    else:
        for tid in target_ids:
            _execute_one_target(
                tid, ssh_username=ssh_username, ssh_password=ssh_password, commands=commands,
                command_timeout_seconds=command_timeout, connect_timeout_seconds=connect_timeout,
            )

    _finish_job(job_id)


def _finish_job(job_id: str, *, status: str | None = None) -> None:
    """Computes the job's final rolled-up status from its targets'
    individual outcomes (spec section 7): COMPLETED if every target
    succeeded, PARTIAL if some did and some didn't, FAILED if none
    did. `status` can be forced (used for the "no targets resolved at
    all" case, which is FAILED outright rather than computed)."""
    from ..database import get_sessionmaker
    from ..models.command_job import CommandJob, CommandJobTarget

    session_local = get_sessionmaker()
    db = session_local()
    try:
        job = db.query(CommandJob).filter(CommandJob.id == job_id).first()
        if job is None:
            return

        if status:
            job.status = status
        else:
            targets = db.query(CommandJobTarget).filter(CommandJobTarget.job_id == job.id).all()
            statuses = {t.status for t in targets}
            if statuses == {"COMPLETED"}:
                job.status = "COMPLETED"
            elif "COMPLETED" in statuses:
                job.status = "PARTIAL"
            else:
                job.status = "FAILED"

        job.completed_at = _now()
        db.commit()
    finally:
        db.close()
