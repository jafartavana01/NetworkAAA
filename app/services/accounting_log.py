"""
app.services.accounting_log
=============================
Parses /var/log/aaa-platform/tac_plus-ng-accounting.log (spec section
23). Unlike Phase 3's access-log viewer (deliberately left raw/
unparsed because the line format wasn't confirmed), this one CAN
safely parse structured fields -- because app.services.config_compiler
defines the exact accounting format string tac_plus-ng writes with
(`${nas}::${user}::${port}::${nac}::${accttype}::${result}::${service}::${cmd}`),
so both sides of the format are under this project's own control
rather than being reverse-engineered from an undocumented default.

CORRECTION (confirmed against a real deployment): an earlier version
of this format string added `${task_id}` as a ninth field, reasoning
that tac_plus-ng's documentation confirms task_id exists and that the
`${fieldname}` custom-format convention seemed likely to extend to it.
That reasoning was WRONG -- a real install hit
`log variable 'task_id' is not recognized`, a fatal config error that
crash-looped tac_plus-ng. `${task_id}` is not a valid variable in a
custom `accounting format` string; removed. This is exactly the kind
of thing the "reasoned, not confirmed" tag exists to flag honestly,
and exactly why it needs to keep being taken seriously rather than
treated as a formality -- the tag was right to be there, and the
inference under it turned out wrong.

Consequence for PAM Expansion Plan §9 (Session Monitoring): without a
true per-session identifier, `group_into_sessions()` below now
correlates on (device, port) instead -- a heuristic, not a protocol-
level session ID. It assumes at most one open session per device+port
at a time (true for the overwhelming majority of real TACACS+
deployments, where a given tty/line serves one login at a time) and
pairs each `start` record with the next `stop` seen on that same
device+port. This is honestly weaker than true session-id correlation
and is documented as such directly in the Sessions page, not just
here.

What's NOT fully controlled: whether tac_plus-ng prepends anything
(a timestamp, in every real-world example seen during research,
though only independently confirmed for syslog-routed and legacy-
tac_plus file output, not tac_plus-ng's own file output specifically)
before the custom format payload on each line. Rather than guess at
that prefix's exact structure, this parser finds the known-field
payload by its field count and our own delimiter, and keeps whatever
precedes it as an opaque `raw_prefix` string. Spec section 23 also
asks for date-range filtering, which genuinely needs a parsed
timestamp -- so `_try_parse_timestamp()` makes a best-effort attempt
at the one prefix format consistently seen in real tac_plus-family
logs (`MMM DD HH:MM:SS`, syslog convention, no year), and leaves
`parsed_at = None` when it doesn't match rather than guessing further.
Date-range filtering only applies to records where it succeeded; nothing
is dropped or hidden because its timestamp didn't parse, and the GUI
says so explicitly rather than silently filtering unevenly.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from ..config import LOG_DIR
from .config_compiler import ACCOUNTING_FIELD_SEPARATOR

ACCOUNTING_LOG_PATH = LOG_DIR / "tac_plus-ng-accounting.log"

_FIELD_NAMES = ["nas", "user", "port", "nac", "accttype", "result", "service", "cmd"]
_EXPECTED_FIELD_COUNT = len(_FIELD_NAMES)

# e.g. "Jul 12 09:39:50" -- the syslog-style prefix seen consistently
# across real tac_plus-family accounting log examples during research.
# No year (syslog convention omits it), so the current year is assumed
# -- meaning parsing is unreliable right at a year boundary for old
# entries, a known, accepted limitation of a best-effort feature.
_TIMESTAMP_PATTERN = re.compile(r"^([A-Za-z]{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})")


def _try_parse_timestamp(prefix: str) -> datetime | None:
    match = _TIMESTAMP_PATTERN.match(prefix.strip())
    if not match:
        return None
    try:
        current_year = datetime.now(timezone.utc).year
        parsed = datetime.strptime(f"{current_year} {match.group(1)}", "%Y %b %d %H:%M:%S")
        return parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


@dataclass
class AccountingRecord:
    raw_line: str
    parsed: bool
    raw_prefix: str = ""  # whatever preceded the known fields (likely a timestamp)
    parsed_at: datetime | None = None  # best-effort; None if the prefix didn't match a recognized format
    nas: str = ""
    user: str = ""
    port: str = ""
    nac: str = ""
    accttype: str = ""
    result: str = ""
    service: str = ""
    cmd: str = ""

    def matches(self, query: str) -> bool:
        if not query:
            return True
        q = query.lower()
        return q in self.raw_line.lower()


def _parse_line(line: str) -> AccountingRecord:
    line = line.rstrip("\n")
    parts = line.split(ACCOUNTING_FIELD_SEPARATOR)

    if len(parts) < _EXPECTED_FIELD_COUNT:
        return AccountingRecord(raw_line=line, parsed=False)

    # The last _EXPECTED_FIELD_COUNT segments are our known fields
    # (see module docstring for why: whatever precedes them -- an
    # auto-prepended timestamp, most likely -- may itself legitimately
    # contain no delimiter at all, so we anchor from the end, not the
    # start).
    field_values = parts[-_EXPECTED_FIELD_COUNT:]
    raw_prefix = ACCOUNTING_FIELD_SEPARATOR.join(parts[:-_EXPECTED_FIELD_COUNT]).strip()

    values = dict(zip(_FIELD_NAMES, field_values))
    return AccountingRecord(
        raw_line=line,
        parsed=True,
        raw_prefix=raw_prefix,
        parsed_at=_try_parse_timestamp(raw_prefix),
        **values,
    )


def read_records(*, limit: int = 500) -> list[AccountingRecord]:
    """Returns the most recent `limit` records, newest first."""
    if not ACCOUNTING_LOG_PATH.exists():
        return []

    with ACCOUNTING_LOG_PATH.open("r", encoding="utf-8", errors="replace") as fh:
        lines = fh.readlines()

    tail = lines[-limit:]
    records = [_parse_line(line) for line in tail if line.strip()]
    records.reverse()  # newest first
    return records


def filter_records(
    records: list[AccountingRecord],
    *,
    user: str | None = None,
    device: str | None = None,
    device_group_device_names: list[str] | None = None,
    source_ip: str | None = None,
    result: str | None = None,
    search: str | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
) -> list[AccountingRecord]:
    def keep(r: AccountingRecord) -> bool:
        if user and user.lower() not in r.user.lower():
            return False
        if device and device.lower() not in r.nas.lower():
            return False
        # PAM Expansion Plan §10's "Device Group filter" -- resolving a
        # device-group id to its member device NAMES is a DB lookup, so
        # it happens in the caller (app.api.routes_accounting); this
        # function only needs the resolved name list to filter against.
        if device_group_device_names is not None and r.nas not in device_group_device_names:
            return False
        if source_ip and source_ip.lower() not in r.nac.lower():
            return False
        if result and result.lower() != r.result.lower():
            return False
        if search and not r.matches(search):
            return False
        # Date-range filtering only applies where a timestamp was
        # successfully parsed -- a record with parsed_at=None is never
        # excluded by a date filter, since we have no basis to say it
        # falls outside the range (see module docstring).
        if since and r.parsed_at and r.parsed_at < since:
            return False
        if until and r.parsed_at and r.parsed_at > until:
            return False
        return True

    return [r for r in records if keep(r)]


def to_csv_row(r: AccountingRecord) -> list[str]:
    return [r.raw_prefix, r.user, r.nas, r.port, r.nac, r.accttype, r.result, r.service, r.cmd]


CSV_HEADER = ["timestamp_raw", "user", "device", "port", "source_address", "accounting_state", "result", "service", "command"]


@dataclass
class SessionSummary:
    """
    PAM Expansion Plan §9. Correlated on (device, port), NOT a true
    session/task identifier -- see this module's docstring for why:
    `${task_id}` was tried and confirmed NOT to be valid tac_plus-ng
    format-string syntax by a real deployment failure. This heuristic
    assumes at most one open session per device+port at a time (true
    for the overwhelming majority of real deployments) and pairs each
    `start` with the next `stop` observed on that same device+port. A
    session with an observed start and no observed stop yet is shown
    as active -- a genuine, data-backed observation, not an
    assumption -- but the correlation key itself is best-effort, and
    the Sessions page says so directly rather than implying
    protocol-level certainty it doesn't have.
    """
    device: str
    port: str
    user: str
    source_ip: str
    start_at: datetime | None
    stop_at: datetime | None
    is_active: bool
    commands: list[str]
    event_count: int

    def to_dict(self) -> dict:
        return {
            "device": self.device,
            "port": self.port,
            "user": self.user,
            "source_ip": self.source_ip,
            "start_at": self.start_at.isoformat() if self.start_at else None,
            "stop_at": self.stop_at.isoformat() if self.stop_at else None,
            "is_active": self.is_active,
            "commands": self.commands,
            "event_count": self.event_count,
        }


def group_into_sessions(records: list[AccountingRecord]) -> list[SessionSummary]:
    """
    `records` must be given oldest-first (chronological) -- callers
    pass read_records()[::-1], since read_records() itself returns
    newest-first. Walks each (device, port) key's own records in
    order, opening a new session on each `start` and closing it on
    the next `stop` for that same key -- see SessionSummary's
    docstring for the (device, port) heuristic and its limits.
    """
    by_key: dict[tuple[str, str], list[AccountingRecord]] = {}
    for r in records:
        if not r.parsed or not r.nas or not r.port:
            continue
        by_key.setdefault((r.nas, r.port), []).append(r)

    sessions: list[SessionSummary] = []
    for (device, port), group in by_key.items():
        open_session: dict | None = None  # user, source_ip, start_at, commands, event_count

        for r in group:
            accttype = r.accttype.lower()

            if accttype == "start":
                if open_session is not None:
                    # An unclosed prior session on this same device+port --
                    # a new start implicitly ends it (no stop was ever
                    # observed for it in this log tail). Flush it as-is
                    # rather than silently dropping it.
                    sessions.append(SessionSummary(
                        device=device, port=port,
                        user=open_session["user"], source_ip=open_session["source_ip"],
                        start_at=open_session["start_at"], stop_at=None, is_active=False,
                        commands=open_session["commands"], event_count=open_session["event_count"],
                    ))
                open_session = {"user": r.user, "source_ip": r.nac, "start_at": r.parsed_at, "commands": [], "event_count": 1}
                continue

            if open_session is None:
                # A record with no open "start" for this device+port (e.g.
                # a bare `stop` with nothing preceding it in the current
                # log tail) isn't attributable to a session -- skipped,
                # not merged into a fabricated one.
                continue

            open_session["event_count"] += 1
            if r.cmd and accttype != "stop":
                open_session["commands"].append(r.cmd)

            if accttype == "stop":
                sessions.append(SessionSummary(
                    device=device, port=port,
                    user=open_session["user"], source_ip=open_session["source_ip"],
                    start_at=open_session["start_at"], stop_at=r.parsed_at, is_active=False,
                    commands=list(open_session["commands"]), event_count=open_session["event_count"],
                ))
                open_session = None

        if open_session is not None:
            # Still open at the end of the tail -- genuinely active.
            sessions.append(SessionSummary(
                device=device, port=port,
                user=open_session["user"], source_ip=open_session["source_ip"],
                start_at=open_session["start_at"], stop_at=None, is_active=True,
                commands=list(open_session["commands"]), event_count=open_session["event_count"],
            ))

    sessions.sort(key=lambda s: s.start_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True)
    return sessions


def compute_hourly_activity(records: list[AccountingRecord], *, hours: int = 24) -> list[dict]:
    """
    A real time-series for the Dashboard's activity chart: total
    parsed-record count per hourly bucket over the last `hours` hours,
    oldest first. Only counts records with a successfully parsed
    timestamp (see module docstring on `_try_parse_timestamp` -- best
    effort, not guaranteed for every line) -- a record whose timestamp
    didn't parse is simply absent from every bucket rather than
    guessed into one, so the chart never implies more precision than
    the underlying data supports. Buckets with zero events are still
    included (as 0), so the chart's x-axis stays a continuous,
    genuine hourly timeline rather than skipping silently over quiet
    periods.
    """
    now = datetime.now(timezone.utc)
    bucket_starts = [
        now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=h)
        for h in range(hours - 1, -1, -1)
    ]
    counts = {b: 0 for b in bucket_starts}

    for r in records:
        if not r.parsed or not r.parsed_at:
            continue
        bucket = r.parsed_at.replace(minute=0, second=0, microsecond=0)
        if bucket in counts:
            counts[bucket] += 1

    return [{"hour": b.isoformat(), "count": counts[b]} for b in bucket_starts]


def compute_health_and_failure_stats(records: list[AccountingRecord]) -> dict:
    """
    PAM Expansion Plan §16-17. Only aggregates what's genuinely
    observable from parsed accounting records -- no authentication
    success/failure breakdown here, since the access log (spec
    section 52's confirmed-real event source) is deliberately left
    raw/unparsed (its line format was never independently confirmed
    the way the accounting format is, because this project defines
    that one itself -- see app/api/routes_tacacs_logs.py). Section
    16's suggested "Authentication Requests/Success/Failure" and
    "RADIUS" cards are omitted rather than faked; only cards backed by
    real, parsed data are included, per §16's own "do not create fake
    statistics" instruction.

    `result` values are treated data-driven: this module doesn't
    assume a fixed vocabulary (e.g. only "permit"/"deny" ever appear).
    A record's result counts as "non-permit" for the failure-analysis
    breakdown whenever it's parsed, non-empty, and not exactly
    "permit" (case-insensitive) -- confirmed meaningful for
    command/config-type accounting records specifically (a real
    deployed tac_plus-ng example was found using `result=permit` on a
    "config" accttype record during config_compiler's own accounting
    format work), not assumed to carry authorization-decision meaning
    for every accttype (a bare "start" record's result is typically
    empty, and empty results are excluded from this breakdown
    entirely -- they're not a signal either way, not a silent "success").
    """
    total = len(records)
    parsed_records = [r for r in records if r.parsed]

    by_accttype: dict[str, int] = {}
    result_counts: dict[str, int] = {}
    non_permit_by_device: dict[str, int] = {}
    non_permit_by_user: dict[str, int] = {}
    permit_count = 0
    non_permit_count = 0

    for r in parsed_records:
        if r.accttype:
            by_accttype[r.accttype] = by_accttype.get(r.accttype, 0) + 1

        result_value = r.result.strip()
        if not result_value:
            continue  # no result recorded on this record (e.g. a bare "start") -- not a signal either way

        result_counts[result_value] = result_counts.get(result_value, 0) + 1
        if result_value.lower() == "permit":
            permit_count += 1
        else:
            non_permit_count += 1
            if r.nas:
                non_permit_by_device[r.nas] = non_permit_by_device.get(r.nas, 0) + 1
            if r.user:
                non_permit_by_user[r.user] = non_permit_by_user.get(r.user, 0) + 1

    def top_n(counts: dict[str, int], n: int = 10) -> list[dict]:
        ranked = sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n]
        return [{"name": name, "count": count} for name, count in ranked]

    distinct_devices = len({r.nas for r in parsed_records if r.nas})
    distinct_users = len({r.user for r in parsed_records if r.user})

    now = datetime.now(timezone.utc)
    last_hour_count = sum(
        1 for r in parsed_records if r.parsed_at and (now - r.parsed_at).total_seconds() <= 3600
    )

    return {
        "total_records_in_tail": total,
        "parsed_records": len(parsed_records),
        "unparsed_records": total - len(parsed_records),
        "distinct_devices": distinct_devices,
        "distinct_users": distinct_users,
        "events_last_hour": last_hour_count,
        "by_accttype": by_accttype,
        "result_counts": result_counts,
        "permit_count": permit_count,
        "non_permit_count": non_permit_count,
        "top_non_permit_devices": top_n(non_permit_by_device),
        "top_non_permit_users": top_n(non_permit_by_user),
    }
