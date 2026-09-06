"""
app.services.ncm_compare
===========================
Multi-device configuration comparison: the category matrix, per-device
consistency, and outlier detection behind NCM → Configuration Compare.

Everything here is computed from the ACTUAL stored configuration text
of each device's latest snapshot. Nothing is sampled, estimated, or
filled in. A device with no snapshot is reported as having no snapshot
rather than being silently dropped or counted as matching.

Design note on the category matrix
----------------------------------
A "category" is a named set of configuration-line patterns (AAA, SSH,
NTP, ...). For each device the matching lines are extracted, normalised
and hashed; devices whose hash for a category is identical are
genuinely running byte-equivalent configuration for that category.

That is a claim this code can actually prove. What it deliberately
does NOT claim is semantic equivalence -- two different configurations
that happen to behave the same way will be reported as different,
because proving otherwise would require modelling device behaviour.
The UI says "identical", not "equivalent", for the same reason.
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field

#: Ordered category definitions. Each pattern is matched against a
#: whole configuration line (case-insensitive, leading whitespace
#: preserved so sub-mode lines under an interface still belong to the
#: interface category).
#:
#: These patterns describe REAL Cisco IOS configuration syntax. A
#: category with no matching lines on any device is dropped from the
#: matrix entirely rather than shown as a row of "no data" -- an
#: empty row invites the reader to think something was checked and
#: found absent, when in fact nothing was checked at all.
CATEGORY_PATTERNS: list[tuple[str, list[str]]] = [
    ("AAA", [r"^aaa\b", r"^username\b", r"^enable\s+(secret|password)\b", r"^tacacs", r"^radius"]),
    ("SSH", [r"^ip\s+ssh\b", r"^line\s+vty\b", r"^\s+transport\s+input\b", r"^crypto\s+key\b"]),
    ("SNMP", [r"^snmp-server\b"]),
    ("Logging", [r"^logging\b"]),
    ("NTP", [r"^ntp\b", r"^clock\s+timezone\b"]),
    ("HTTP", [r"^ip\s+http\b"]),
    ("Interfaces", [r"^interface\b", r"^\s+(ip\s+address|switchport|description|shutdown|no\s+shutdown)\b"]),
    ("Routing", [r"^router\b", r"^ip\s+route\b", r"^\s+(network|redistribute|passive-interface)\b"]),
    ("ACL", [r"^access-list\b", r"^ip\s+access-list\b", r"^\s+(permit|deny)\b"]),
    ("Services", [r"^service\b", r"^no\s+service\b", r"^ip\s+domain", r"^banner\b"]),
]

_COMPILED = [
    (name, [re.compile(p, re.IGNORECASE) for p in patterns])
    for name, patterns in CATEGORY_PATTERNS
]


def _normalise(line: str) -> str:
    """Collapses trailing whitespace only. Leading whitespace is
    significant in IOS (it marks sub-mode), so it is preserved."""
    return line.rstrip()


def extract_category_lines(content: str) -> dict[str, list[str]]:
    """Returns category -> the configuration lines belonging to it.

    A line may match more than one category (an interface's `ip access-
    group` is arguably both), and is counted in each -- categories are
    views over the configuration, not a partition of it, and forcing
    exclusivity would mean silently hiding a line from a category an
    operator would expect to find it in.
    """
    out: dict[str, list[str]] = {name: [] for name, _ in _COMPILED}
    for raw in (content or "").splitlines():
        line = _normalise(raw)
        if not line.strip() or line.strip() == "!":
            continue
        for name, patterns in _COMPILED:
            if any(p.match(line) for p in patterns):
                out[name].append(line)
    return out


def _hash_lines(lines: list[str]) -> str:
    return hashlib.sha256("\n".join(lines).encode("utf-8")).hexdigest()


@dataclass
class DeviceConfigInput:
    device_id: str
    device_name: str
    ip_address: str | None
    configuration_id: str | None
    version_number: int | None
    created_at: object | None
    content: str | None  # None = no snapshot exists for this device


@dataclass
class CategoryCell:
    device_id: str
    present: bool          # does this device have ANY line in this category
    matches_majority: bool
    line_count: int


@dataclass
class CategoryRow:
    category: str
    cells: list[CategoryCell]
    matching_devices: int
    total_devices: int

    @property
    def match_percent(self) -> float:
        return round((self.matching_devices / self.total_devices) * 100, 1) if self.total_devices else 0.0


@dataclass
class CompareResult:
    devices: list[dict] = field(default_factory=list)
    categories: list[CategoryRow] = field(default_factory=list)
    comparable_devices: int = 0
    devices_without_snapshot: list[str] = field(default_factory=list)
    identical_devices: int = 0
    differing_devices: int = 0
    consistency_percent: float = 0.0
    outlier_device_id: str | None = None
    outlier_difference_count: int = 0
    baseline_device_id: str | None = None


def compare_devices(inputs: list[DeviceConfigInput]) -> CompareResult:
    """
    Compares each device against the MAJORITY configuration per
    category.

    Majority rather than a fixed first device, because "which of these
    is the odd one out" is the question an operator is actually asking;
    anchoring to whichever device happened to be selected first would
    make the answer depend on click order. When no majority exists (a
    2-device comparison that differs, or an all-different set), the
    devices are reported as differing without one being labelled the
    outlier -- calling an arbitrary side "correct" would be a guess
    presented as a finding.
    """
    result = CompareResult()

    comparable = [d for d in inputs if d.content]
    result.devices_without_snapshot = [d.device_id for d in inputs if not d.content]
    result.comparable_devices = len(comparable)

    result.devices = [
        {
            "device_id": d.device_id, "device_name": d.device_name, "ip_address": d.ip_address,
            "configuration_id": d.configuration_id, "version_number": d.version_number,
            "created_at": d.created_at, "has_snapshot": bool(d.content),
        }
        for d in inputs
    ]

    if len(comparable) < 2:
        # One device (or none) cannot be compared with anything. Report
        # that plainly rather than returning a 100%-consistent result,
        # which would read as "everything matches" when nothing was
        # actually checked.
        return result

    per_device_categories = {d.device_id: extract_category_lines(d.content or "") for d in comparable}

    difference_counts: dict[str, int] = {d.device_id: 0 for d in comparable}

    for name, _ in _COMPILED:
        hashes: dict[str, str] = {}
        counts: dict[str, int] = {}
        for d in comparable:
            lines = per_device_categories[d.device_id][name]
            hashes[d.device_id] = _hash_lines(lines)
            counts[d.device_id] = len(lines)

        # Drop a category no device uses at all -- see CATEGORY_PATTERNS.
        if all(c == 0 for c in counts.values()):
            continue

        tally: dict[str, int] = {}
        for h in hashes.values():
            tally[h] = tally.get(h, 0) + 1
        majority_hash, majority_size = max(tally.items(), key=lambda kv: kv[1])
        # A "majority" of one in a set where every device differs is not
        # a majority; treat it as no consensus.
        has_consensus = majority_size > 1 or len(comparable) == 1

        cells = []
        matching = 0
        for d in comparable:
            is_match = has_consensus and hashes[d.device_id] == majority_hash
            if is_match:
                matching += 1
            else:
                difference_counts[d.device_id] += 1
            cells.append(CategoryCell(
                device_id=d.device_id, present=counts[d.device_id] > 0,
                matches_majority=is_match, line_count=counts[d.device_id],
            ))

        result.categories.append(CategoryRow(
            category=name, cells=cells, matching_devices=matching, total_devices=len(comparable),
        ))

    result.identical_devices = sum(1 for v in difference_counts.values() if v == 0)
    result.differing_devices = len(comparable) - result.identical_devices

    total_cells = sum(r.total_devices for r in result.categories)
    matching_cells = sum(r.matching_devices for r in result.categories)
    result.consistency_percent = round((matching_cells / total_cells) * 100, 1) if total_cells else 0.0

    # The outlier is the single device differing in the most categories,
    # and only when it is UNIQUELY worst -- if two devices tie, there is
    # no single odd one out, and naming one would be arbitrary.
    if difference_counts:
        ranked = sorted(difference_counts.items(), key=lambda kv: kv[1], reverse=True)
        worst_id, worst_count = ranked[0]
        uniquely_worst = worst_count > 0 and (len(ranked) == 1 or ranked[1][1] < worst_count)
        if uniquely_worst:
            result.outlier_device_id = worst_id
            result.outlier_difference_count = worst_count

    # Baseline for the raw-diff pane: a device that matches the
    # majority everywhere, so "diff against baseline" compares an
    # outlier against something representative rather than against
    # another outlier.
    for d in comparable:
        if difference_counts[d.device_id] == 0:
            result.baseline_device_id = d.device_id
            break

    return result
