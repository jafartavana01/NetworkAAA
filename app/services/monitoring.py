"""
app.services.monitoring
=========================
Detection side of "monitoring mode" (see app.models.monitoring_settings
for the compiler side -- the catch-all host block that makes an
unrecognized device's connection attempt observable at all).

Deliberately a WEAKER claim than a structured log parse: this scans
the access log's raw text for anything IP-shaped, rather than
extracting a specific confirmed field position -- app.api.routes_tacacs_logs's
own docstring already establishes that this log's exact line format
was never independently confirmed (only syslog-style output was seen
during research, which has a different prefix added by syslog itself).
A generic "does this look like an IP" scan doesn't need to know which
field holds the source address, only that one appears somewhere on a
line -- which can produce false positives (any IP-shaped token on a
line, not necessarily the actual connecting device), and the GUI says
so plainly rather than presenting this as a guaranteed-accurate parse.

The shared secret itself is NEVER shown, and never could be: TACACS+
does not transmit the key over the wire at all (it's a pre-shared
secret used only to derive the obfuscation pad -- see RFC8907). What
IS shown is the source IP and the raw log line it was seen in, so the
admin has real context to work from without this module overclaiming
what's actually knowable from the protocol.
"""
from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import LOG_DIR
from ..models.device import NetworkDevice

ACCESS_LOG_PATH = LOG_DIR / "tac_plus-ng-access.log"

_IPV4_PATTERN = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")

_EXCLUDED_IPS = {"0.0.0.0", "127.0.0.1", "255.255.255.255"}


def _configured_ips(db: Session) -> set[str]:
    """The bare IP (CIDR suffix stripped) of every currently-configured
    device -- NetworkDevice.ip_address is stored as CIDR (e.g.
    "10.10.10.10/32"), see app.models.device."""
    devices = db.query(NetworkDevice).all()
    return {d.ip_address.split("/")[0].strip() for d in devices}


def find_unrecognized_connections(db: Session, *, tail_lines: int = 500) -> list[dict]:
    """
    Scans the last `tail_lines` of the access log for IP-shaped
    substrings that don't match any currently-configured device,
    deduplicated by IP. Sorted by how many times each IP was seen in
    the scanned window, descending -- a reasonable proxy for "still
    actively attempting to connect," which is the more actionable
    signal for an admin deciding what to add. Returns [] if the log
    doesn't exist yet (nothing has connected at all) rather than an
    error -- an empty result here is a normal, expected state.
    """
    if not ACCESS_LOG_PATH.exists():
        return []

    with ACCESS_LOG_PATH.open("r", encoding="utf-8", errors="replace") as fh:
        all_lines = fh.readlines()
    tail = all_lines[-tail_lines:]

    known_ips = _configured_ips(db) | _EXCLUDED_IPS

    seen: dict[str, dict] = {}
    for line in tail:
        for ip in set(_IPV4_PATTERN.findall(line)):
            if ip in known_ips:
                continue
            if ip not in seen:
                seen[ip] = {"ip_address": ip, "sample_line": line.strip(), "occurrences": 0}
            seen[ip]["occurrences"] += 1
            seen[ip]["sample_line"] = line.strip()  # keep the most recent occurrence as the sample shown

    return sorted(seen.values(), key=lambda r: r["occurrences"], reverse=True)
