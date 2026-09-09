"""
app.services.ncm_diff_detail
===============================
Turns a raw text diff into the structures the Configuration Diff page
needs: aligned side-by-side rows, a table of individual changes with
their location, and per-category counts.

The raw text diff remains authoritative. Everything here is a VIEW over
`difflib`'s opcodes -- nothing is re-derived from a second algorithm,
and no line is shown as changed that difflib did not report as changed.

Two derivations are honest inference and are labelled as such:

  * **Location.** A configuration line's context is the nearest
    preceding line at column 0 (`interface GigabitEthernet0/1`), and
    its attribute is the line's first token (`description`). That is
    real IOS structure -- indentation IS the hierarchy -- not a guess.

  * **Modified.** difflib reports a `replace` opcode when a block of
    lines was substituted. Within one such block, a removed line and an
    added line are paired as a MODIFICATION when they share the same
    parent context and the same first token; anything left unpaired
    stays a plain add or remove. Pairing is a presentation choice, and
    the underlying add/remove counts are never altered by it -- the
    summary reports both so the two can always be reconciled.
"""
from __future__ import annotations

import difflib
import re
from dataclasses import dataclass, field

from .ncm_compare import CATEGORY_PATTERNS

_COMPILED_CATEGORIES = [
    (name, [re.compile(p, re.IGNORECASE) for p in patterns])
    for name, patterns in CATEGORY_PATTERNS
]


def categorize_line(line: str) -> str:
    """First matching category, or 'Other'. Uses the SAME patterns as
    the multi-device comparison page, so a line categorised as Routing
    there is Routing here too."""
    for name, patterns in _COMPILED_CATEGORIES:
        if any(p.match(line) for p in patterns):
            return name
    return "Other"


def _context_of(lines: list[str], index: int) -> str:
    """
    Nearest preceding line at column 0. In IOS the indentation IS the
    hierarchy, so this is structure, not a heuristic. Returns '' for a
    top-level line, which the caller renders as 'global'.
    """
    # A top-level line has no parent -- it IS the context for the lines
    # under it. Returning the line itself would both mislabel its
    # location ("version 17.9 - version") and stop it pairing with its
    # replacement, since two different top-level lines never share a
    # context. Start the search ABOVE the line for that reason.
    if index < len(lines) and lines[index][:1] and not lines[index][:1].isspace():
        return ""
    for i in range(index - 1, -1, -1):
        line = lines[i]
        if line.strip() and not line[:1].isspace() and line.strip() != "!":
            return line.strip()
    return ""


def _first_token(line: str) -> str:
    parts = line.strip().split()
    return parts[0] if parts else ""


@dataclass
class DiffRow:
    """One aligned row. `left`/`right` are None where a side has no
    corresponding line, which is what keeps the two panels aligned."""
    left_no: int | None
    left: str | None
    right_no: int | None
    right: str | None
    kind: str  # equal | add | remove | modify


@dataclass
class ChangeEntry:
    type: str            # added | removed | modified
    location: str        # "interface GigabitEthernet0/1 - description"
    previous_value: str
    new_value: str
    category: str
    left_no: int | None = None
    right_no: int | None = None


@dataclass
class DetailedDiff:
    rows: list = field(default_factory=list)
    changes: list = field(default_factory=list)
    added: int = 0
    removed: int = 0
    modified: int = 0
    unchanged: int = 0
    identical: bool = False
    categories: dict = field(default_factory=dict)


def _location(context: str, line: str) -> str:
    token = _first_token(line)
    if context and token:
        return f"{context} - {token}"
    if context:
        return context
    return token or "global"


def build_detailed_diff(from_text: str, to_text: str) -> DetailedDiff:
    left = (from_text or "").splitlines()
    right = (to_text or "").splitlines()

    result = DetailedDiff()
    if from_text == to_text:
        result.identical = True
        result.unchanged = len(left)
        result.rows = [
            DiffRow(i + 1, l, i + 1, l, "equal") for i, l in enumerate(left)
        ]
        return result

    matcher = difflib.SequenceMatcher(None, left, right, autojunk=False)

    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            for offset in range(i2 - i1):
                result.rows.append(DiffRow(
                    i1 + offset + 1, left[i1 + offset],
                    j1 + offset + 1, right[j1 + offset], "equal",
                ))
                result.unchanged += 1
            continue

        removed_block = [(i1 + k, left[i1 + k]) for k in range(i2 - i1)]
        added_block = [(j1 + k, right[j1 + k]) for k in range(j2 - j1)]

        # Pair removals with additions that share parent context AND
        # first token -- those are the same setting with a new value.
        paired: list = []
        used_adds: set = set()
        for li, ltext in removed_block:
            lctx, ltok = _context_of(left, li), _first_token(ltext)
            if not ltok:
                continue
            for ri, rtext in added_block:
                if ri in used_adds:
                    continue
                if _context_of(right, ri) == lctx and _first_token(rtext) == ltok:
                    paired.append(((li, ltext), (ri, rtext)))
                    used_adds.add(ri)
                    break

        paired_left = {li for (li, _), _ in paired}

        for (li, ltext), (ri, rtext) in paired:
            result.rows.append(DiffRow(li + 1, ltext, ri + 1, rtext, "modify"))
            result.modified += 1
            ctx = _context_of(left, li)
            result.changes.append(ChangeEntry(
                type="modified", location=_location(ctx, ltext),
                previous_value=ltext.strip(), new_value=rtext.strip(),
                category=categorize_line(ltext), left_no=li + 1, right_no=ri + 1,
            ))

        for li, ltext in removed_block:
            if li in paired_left:
                continue
            result.rows.append(DiffRow(li + 1, ltext, None, None, "remove"))
            result.removed += 1
            ctx = _context_of(left, li)
            result.changes.append(ChangeEntry(
                type="removed", location=_location(ctx, ltext),
                previous_value=ltext.strip(), new_value="",
                category=categorize_line(ltext), left_no=li + 1,
            ))

        for ri, rtext in added_block:
            if ri in used_adds:
                continue
            result.rows.append(DiffRow(None, None, ri + 1, rtext, "add"))
            result.added += 1
            ctx = _context_of(right, ri)
            result.changes.append(ChangeEntry(
                type="added", location=_location(ctx, rtext),
                previous_value="", new_value=rtext.strip(),
                category=categorize_line(rtext), right_no=ri + 1,
            ))

    # Rows are emitted per opcode block; sort so modifications appear
    # beside the lines they replace rather than after the whole block.
    result.rows.sort(key=lambda r: (
        r.left_no if r.left_no is not None else (r.right_no or 0) + 0.5
    ))

    counts: dict = {}
    for change in result.changes:
        bucket = counts.setdefault(change.category, {"added": 0, "removed": 0, "modified": 0})
        bucket[change.type] += 1
    result.categories = counts

    return result
