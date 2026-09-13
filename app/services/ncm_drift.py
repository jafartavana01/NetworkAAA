"""
app.services.ncm_drift
=========================
Configuration drift detection -- NCM Phase 4.

Drift is defined as: the device's LATEST archived snapshot differs from
the snapshot designated as its baseline. Both sides are real, immutable,
SHA-256-hashed archive entries, so a drift result is a comparison
between two artifacts the platform actually holds -- never between a
device and a hand-maintained document that could itself be wrong.

Nothing here contacts a device. Drift describes what has been archived;
if a device has not been backed up since it changed, that shows as
"no newer snapshot", which is honest, rather than as "in sync", which
would be a false all-clear.

Status vocabulary, deliberately five values rather than a boolean:

  in_sync       latest snapshot is byte-identical to the baseline
  drifted       latest snapshot differs from the baseline
  no_baseline   device has snapshots but none designated golden
  no_snapshot   device has never been backed up
  baseline_gone the designated snapshot was deleted from the archive

The last three are not failures of the device -- they are gaps in
coverage, and collapsing them into "drifted" would raise false alarms
while collapsing them into "in_sync" would hide real blind spots.
"""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from ..models.device import NetworkDevice
from ..models.ncm import NcmBaseline, NcmConfiguration
from . import ncm_archive

STATUS_IN_SYNC = "in_sync"
STATUS_DRIFTED = "drifted"
STATUS_NO_BASELINE = "no_baseline"
STATUS_NO_SNAPSHOT = "no_snapshot"
STATUS_BASELINE_GONE = "baseline_gone"

#: Statuses that represent a gap in coverage rather than a device that
#: has changed. Kept as one list so every caller agrees on the split.
COVERAGE_GAP_STATUSES = (STATUS_NO_BASELINE, STATUS_NO_SNAPSHOT, STATUS_BASELINE_GONE)


@dataclass
class DeviceDrift:
    device_id: str
    device_name: str
    configuration_type: str
    status: str
    baseline_version: int | None = None
    latest_version: int | None = None
    baseline_configuration_id: str | None = None
    latest_configuration_id: str | None = None
    lines_added: int = 0
    lines_removed: int = 0
    last_backup_at: object | None = None
    baseline_set_at: object | None = None


def evaluate_device_drift(
    device_id, device_name: str, configuration_type: str,
    baseline: NcmBaseline | None, latest: NcmConfiguration | None,
    baseline_config: NcmConfiguration | None,
    *, compute_diff: bool = True,
) -> DeviceDrift:
    """
    Pure function -- no database access -- so the status rules are
    testable directly and cannot drift from what the API reports.

    Comparison is by SHA-256 first. The line counts are only computed
    when the hashes differ, because diffing two identical multi-thousand
    line configurations to prove they are identical is wasted work on
    every in-sync device in the fleet.
    """
    result = DeviceDrift(
        device_id=str(device_id), device_name=device_name,
        configuration_type=configuration_type, status=STATUS_NO_SNAPSHOT,
    )

    if latest is not None:
        result.latest_version = latest.version_number
        result.latest_configuration_id = str(latest.id)
        result.last_backup_at = latest.created_at

    if baseline is not None:
        result.baseline_version = baseline.version_number
        result.baseline_set_at = baseline.set_at
        if baseline.configuration_id is not None:
            result.baseline_configuration_id = str(baseline.configuration_id)

    if latest is None:
        result.status = STATUS_NO_SNAPSHOT
        return result
    if baseline is None:
        result.status = STATUS_NO_BASELINE
        return result
    if baseline_config is None:
        # The baseline row survives but the snapshot it pointed at is
        # gone. Reporting in_sync here would be a false all-clear
        # against a config that no longer exists.
        result.status = STATUS_BASELINE_GONE
        return result

    if baseline_config.sha256 == latest.sha256:
        result.status = STATUS_IN_SYNC
        return result

    result.status = STATUS_DRIFTED
    if compute_diff:
        diff = ncm_archive.diff_configurations(
            baseline_config.configuration_content, latest.configuration_content,
            from_label=f"baseline v{baseline_config.version_number}",
            to_label=f"current v{latest.version_number}",
        )
        result.lines_added = diff.added
        result.lines_removed = diff.removed
    return result


def compute_fleet_drift(db: Session, configuration_type: str = "running") -> list[DeviceDrift]:
    """
    Drift for every enabled device, using three queries total rather
    than three per device -- a fleet-wide drift page must not become
    N+1 against a large inventory.
    """
    devices = (
        db.query(NetworkDevice)
        .filter(NetworkDevice.enabled.is_(True))
        .order_by(NetworkDevice.name.asc())
        .all()
    )
    if not devices:
        return []

    device_ids = [d.id for d in devices]

    baselines = {
        b.device_id: b
        for b in db.query(NcmBaseline).filter(
            NcmBaseline.device_id.in_(device_ids),
            NcmBaseline.configuration_type == configuration_type,
        ).all()
    }

    # Latest snapshot per device, newest-first so the first row wins.
    latest_by_device: dict = {}
    by_config_id: dict = {}
    for c in (
        db.query(NcmConfiguration)
        .filter(
            NcmConfiguration.device_id.in_(device_ids),
            NcmConfiguration.configuration_type == configuration_type,
        )
        .order_by(NcmConfiguration.created_at.desc())
        .all()
    ):
        latest_by_device.setdefault(c.device_id, c)
        by_config_id[c.id] = c

    out = []
    for d in devices:
        baseline = baselines.get(d.id)
        baseline_config = (
            by_config_id.get(baseline.configuration_id)
            if baseline and baseline.configuration_id else None
        )
        out.append(evaluate_device_drift(
            d.id, d.name, configuration_type, baseline,
            latest_by_device.get(d.id), baseline_config,
        ))
    return out


def summarize(drifts: list[DeviceDrift]) -> dict:
    """Counts by status. Coverage gaps are reported separately from
    drift so a fleet with no baselines set does not read as healthy."""
    counts = {s: 0 for s in (
        STATUS_IN_SYNC, STATUS_DRIFTED, STATUS_NO_BASELINE, STATUS_NO_SNAPSHOT, STATUS_BASELINE_GONE,
    )}
    for d in drifts:
        if d.status in counts:
            counts[d.status] += 1
    counts["total"] = len(drifts)
    counts["coverage_gaps"] = sum(counts[s] for s in COVERAGE_GAP_STATUSES)
    return counts
