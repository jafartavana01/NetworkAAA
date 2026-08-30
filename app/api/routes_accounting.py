"""
app.api.routes_accounting
===========================
Read-only accounting browsing/export (spec section 23 and PAM
Expansion Plan §10: search, filter by date range/user/device/device-
group/source-IP/result, export; §9: session correlation). Reads and
parses the log file fresh on every request rather than caching --
accounting volume for a management platform like this is not high
enough to justify the complexity of a background indexer, and "fresh
on every request" means what the GUI shows is always exactly what's
on disk right now.
"""
from __future__ import annotations

import csv
import io
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from ..database import get_db
from ..models.admin import AdminUser
from ..models.device import NetworkDevice
from ..services import accounting_log
from .deps import get_current_admin

router = APIRouter(prefix="/api/tacacs-accounting", tags=["tacacs-accounting"])


def _record_to_dict(r: accounting_log.AccountingRecord) -> dict:
    return {
        "parsed": r.parsed,
        "raw_line": r.raw_line,
        "raw_prefix": r.raw_prefix,
        "timestamp": r.parsed_at.isoformat() if r.parsed_at else None,
        "nas": r.nas,
        "user": r.user,
        "port": r.port,
        "nac": r.nac,
        "accttype": r.accttype,
        "result": r.result,
        "service": r.service,
        "cmd": r.cmd,
    }


def _parse_datetime_param(value: str | None) -> datetime | None:
    """
    `<input type="datetime-local">` sends a naive string (no timezone,
    e.g. "2026-08-20T14:30") representing the browser's local time.
    Our parsed log timestamps are tagged UTC in
    app.services.accounting_log (itself a simplifying assumption, not
    a confirmed fact about what timezone the daemon logs in -- see
    that module's docstring). Comparing a naive and a timezone-aware
    datetime raises TypeError in Python, so naive input here is
    likewise treated as UTC for consistency -- both sides of this
    comparison are already best-effort, and the goal is "filtering
    works and doesn't crash," not minute-perfect timezone accuracy
    that the underlying data doesn't actually support yet.
    """
    if not value:
        return None
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _device_group_member_names(db: Session, device_group_id: str | None) -> list[str] | None:
    """Resolves a device-group id to its member device NAMES, since
    the accounting log only ever records device NAMES (the `nas`
    field), not ids -- None means "no device-group filter applied",
    distinct from an empty list (a real, empty group)."""
    if not device_group_id:
        return None
    try:
        parsed_id = uuid.UUID(device_group_id)
    except ValueError:
        return []
    devices = db.query(NetworkDevice).filter(NetworkDevice.device_group_id == parsed_id).all()
    return [d.name for d in devices]


@router.get("")
def list_accounting_records(
    user: str | None = None,
    device: str | None = None,
    device_group_id: str | None = None,
    source_ip: str | None = None,
    result: str | None = None,
    search: str | None = None,
    since: str | None = None,
    until: str | None = None,
    limit: int = Query(default=200, ge=1, le=2000),
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    records = accounting_log.read_records(limit=max(limit, 2000))
    filtered = accounting_log.filter_records(
        records,
        user=user,
        device=device,
        device_group_device_names=_device_group_member_names(db, device_group_id),
        source_ip=source_ip,
        result=result,
        search=search,
        since=_parse_datetime_param(since),
        until=_parse_datetime_param(until),
    )
    return {
        "total_in_log": len(records),
        "matched": len(filtered),
        "records": [_record_to_dict(r) for r in filtered[:limit]],
    }


@router.get("/export")
def export_accounting_records(
    user: str | None = None,
    device: str | None = None,
    device_group_id: str | None = None,
    source_ip: str | None = None,
    result: str | None = None,
    search: str | None = None,
    since: str | None = None,
    until: str | None = None,
    db: Session = Depends(get_db),
    _admin: AdminUser = Depends(get_current_admin),
):
    records = accounting_log.read_records(limit=10000)
    filtered = accounting_log.filter_records(
        records,
        user=user,
        device=device,
        device_group_device_names=_device_group_member_names(db, device_group_id),
        source_ip=source_ip,
        result=result,
        search=search,
        since=_parse_datetime_param(since),
        until=_parse_datetime_param(until),
    )

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(accounting_log.CSV_HEADER)
    for r in filtered:
        writer.writerow(accounting_log.to_csv_row(r))
    buffer.seek(0)

    return StreamingResponse(
        iter([buffer.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=tacacs-accounting-export.csv"},
    )


@router.get("/sessions")
def list_sessions(
    user: str | None = None,
    device: str | None = None,
    active_only: bool = False,
    limit: int = Query(default=500, ge=1, le=5000),
    _admin: AdminUser = Depends(get_current_admin),
):
    """PAM Expansion Plan §9. Reads the same log the accounting list
    view reads, then groups by (device, port) -- see
    app.services.accounting_log.group_into_sessions for why this is a
    heuristic correlation key, not a true protocol-level session
    identifier (${task_id} was tried and confirmed invalid tac_plus-ng
    syntax by a real deployment failure), and for the is_active
    semantics."""
    records = accounting_log.read_records(limit=limit)
    # group_into_sessions wants oldest-first for chronological command
    # ordering within a session; read_records() returns newest-first.
    sessions = accounting_log.group_into_sessions(records[::-1])

    if user:
        sessions = [s for s in sessions if user.lower() in s.user.lower()]
    if device:
        sessions = [s for s in sessions if device.lower() in s.device.lower()]
    if active_only:
        sessions = [s for s in sessions if s.is_active]

    return {
        "total_sessions": len(sessions),
        "active_count": sum(1 for s in sessions if s.is_active),
        "sessions": [s.to_dict() for s in sessions],
    }


@router.get("/recent-activity")
def recent_activity(
    minutes: int = Query(default=5, ge=1, le=1440),
    limit: int = Query(default=2000, ge=1, le=10000),
    _admin: AdminUser = Depends(get_current_admin),
):
    """Dashboard's "who accessed what, just now" table -- every
    (device, user) pair with at least one accounting event in the
    last `minutes` minutes, most-recently-active pair first. Reads
    the same parsed accounting log every other view here reads;
    "activated" is any accounting event (start, command, or stop) --
    not just a session start, since a device with only mid-session
    command records but no start in the tail (a start that scrolled
    out of the read window) is still real, current activity worth
    surfacing, not something to hide for lack of a start record."""
    records = accounting_log.read_records(limit=limit)
    cutoff = datetime.now(timezone.utc) - timedelta(minutes=minutes)

    latest_by_pair: dict[tuple[str, str], accounting_log.AccountingRecord] = {}
    counts_by_pair: dict[tuple[str, str], int] = {}
    for r in records:
        if not r.parsed or not r.nas or not r.user or not r.parsed_at:
            continue
        if r.parsed_at < cutoff:
            continue
        key = (r.nas, r.user)
        counts_by_pair[key] = counts_by_pair.get(key, 0) + 1
        # records are newest-first, so the FIRST one seen per key is
        # already the most recent -- no comparison needed.
        if key not in latest_by_pair:
            latest_by_pair[key] = r

    rows = [
        {
            "device": device,
            "user": user,
            "last_seen": r.parsed_at.isoformat(),
            "last_service": r.service,
            "last_cmd": r.cmd,
            "last_result": r.result,
            "event_count": counts_by_pair[(device, user)],
        }
        for (device, user), r in latest_by_pair.items()
    ]
    rows.sort(key=lambda row: row["last_seen"], reverse=True)
    return {"minutes": minutes, "rows": rows}


@router.get("/health")
def accounting_health(
    limit: int = Query(default=2000, ge=1, le=10000),
    hours: int = Query(default=24, ge=1, le=168),
    _admin: AdminUser = Depends(get_current_admin),
):
    """PAM Expansion Plan §16-17: AAA Health + Failure Analysis,
    computed server-side over the same parsed accounting records
    every other view here reads -- see
    app.services.accounting_log.compute_health_and_failure_stats for
    exactly what is and isn't included, and why. Also includes an
    hourly activity time series (compute_hourly_activity) for the
    Dashboard's activity chart."""
    records = accounting_log.read_records(limit=limit)
    stats = accounting_log.compute_health_and_failure_stats(records)
    stats["hourly_activity"] = accounting_log.compute_hourly_activity(records, hours=hours)
    return stats
