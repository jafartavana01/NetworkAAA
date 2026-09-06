"""
app.services.ncm_archive
===========================
Configuration archiving (Phase 1) and diffing (Phase 2).

Archiving is deliberately split from the backup engine
(app.services.ncm_backup): "given this configuration text, store it if
it is new" is a pure database concern with no SSH in it, which makes
it directly testable and reusable by any future source of
configuration text (candidate configs, uploaded configs, drift
snapshots) without dragging device connectivity along.
"""
from __future__ import annotations

import difflib
import hashlib
from dataclasses import dataclass

from sqlalchemy import func
from sqlalchemy.orm import Session

from ..models.ncm import NcmConfiguration


def sha256_of(content: str) -> str:
    """SHA-256 over the UTF-8 bytes of the configuration text."""
    return hashlib.sha256(content.encode("utf-8")).hexdigest()


@dataclass
class ArchiveResult:
    changed: bool
    configuration: NcmConfiguration | None
    previous_sha256: str | None = None


def latest_configuration(db: Session, device_id, configuration_type: str) -> NcmConfiguration | None:
    return (
        db.query(NcmConfiguration)
        .filter(
            NcmConfiguration.device_id == device_id,
            NcmConfiguration.configuration_type == configuration_type,
        )
        .order_by(NcmConfiguration.version_number.desc())
        .first()
    )


def _next_version_number(db: Session, device_id, configuration_type: str) -> int:
    """
    Version numbers are per device AND per configuration type, so a
    device's running-config and startup-config each have their own #1,
    #2, #3 sequence. Sharing one counter across both would make
    "version #184" ambiguous about what it is a version OF.
    """
    current_max = (
        db.query(func.max(NcmConfiguration.version_number))
        .filter(
            NcmConfiguration.device_id == device_id,
            NcmConfiguration.configuration_type == configuration_type,
        )
        .scalar()
    )
    return (current_max or 0) + 1


def archive_configuration(
    db: Session, *, device_id, device_name: str, configuration_type: str, content: str,
    source: str, created_by: str | None = None, job_id=None,
) -> ArchiveResult:
    """
    Stores `content` as a new immutable snapshot -- UNLESS it is
    byte-identical (by SHA-256) to this device's most recent snapshot
    of the same configuration_type, in which case nothing is written
    and `changed=False` is returned.

    The caller still records that a backup ran (on
    NcmBackupJobTarget), which is what keeps "backup executed but
    configuration unchanged" distinct from "configuration changed"
    without accumulating an identical row every night.

    Comparison is against the LATEST snapshot only, not any historical
    one: a configuration that changes and then reverts is genuinely a
    new event worth recording, and de-duplicating against all history
    would silently hide that.
    """
    digest = sha256_of(content)
    previous = latest_configuration(db, device_id, configuration_type)

    if previous is not None and previous.sha256 == digest:
        return ArchiveResult(changed=False, configuration=previous, previous_sha256=previous.sha256)

    snapshot = NcmConfiguration(
        device_id=device_id,
        device_name=device_name,
        version_number=_next_version_number(db, device_id, configuration_type),
        configuration_type=configuration_type,
        configuration_content=content,
        sha256=digest,
        size_bytes=len(content.encode("utf-8")),
        source=source,
        created_by=created_by,
        job_id=job_id,
    )
    db.add(snapshot)
    db.flush()  # assign the PK without committing -- the caller owns the transaction
    return ArchiveResult(
        changed=True, configuration=snapshot,
        previous_sha256=previous.sha256 if previous else None,
    )


@dataclass
class DiffResult:
    added: int
    removed: int
    unchanged: int
    lines: list  # [{"type": "add"|"remove"|"context"|"meta", "text": str}]
    identical: bool


def diff_configurations(from_content: str, to_content: str, *, from_label: str = "A", to_label: str = "B") -> DiffResult:
    """
    Standard unified text diff. Deliberately text-based, not
    semantic: this implementation cannot prove what a configuration
    line MEANS to a device, and presenting a guess as network
    semantics would be worse than presenting an honest text diff. A
    future vendor-aware differ can replace this function without any
    caller changing, since the DiffResult shape carries no
    text-diff-specific assumptions.

    "Changed" lines are not reported as a separate count: in a
    line-based diff a modification is genuinely a removal plus an
    addition, and inventing a third number by pairing them up would
    be a heuristic presented as fact. The GUI shows added/removed and
    the diff itself, which is what is actually true.
    """
    from_lines = from_content.splitlines()
    to_lines = to_content.splitlines()

    if from_content == to_content:
        return DiffResult(added=0, removed=0, unchanged=len(from_lines), lines=[], identical=True)

    added = removed = unchanged = 0
    out: list[dict] = []
    for raw in difflib.unified_diff(from_lines, to_lines, fromfile=from_label, tofile=to_label, lineterm="", n=3):
        if raw.startswith("+++") or raw.startswith("---") or raw.startswith("@@"):
            out.append({"type": "meta", "text": raw})
        elif raw.startswith("+"):
            added += 1
            out.append({"type": "add", "text": raw[1:]})
        elif raw.startswith("-"):
            removed += 1
            out.append({"type": "remove", "text": raw[1:]})
        else:
            unchanged += 1
            out.append({"type": "context", "text": raw[1:] if raw.startswith(" ") else raw})

    return DiffResult(added=added, removed=removed, unchanged=unchanged, lines=out, identical=False)
