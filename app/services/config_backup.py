"""
app.services.config_backup
============================
Structured, version-aware backup export/import for the Configuration
page's restore-from-file feature. Distinct from the plain-text
"Download" button on a version's own history entry (routes_config.py's
`get_version_content` -- unchanged, still just the raw config text,
still exactly what it's always been): that download predates this
feature and carries no metadata at all, which is precisely the honesty
problem this module has to handle rather than hide.

CONFIG_BACKUP_FORMAT_VERSION versions the shape of the file THIS
module writes and reads -- not an overall "platform release version"
(no such concept exists yet), and not the database schema (this
project is clean-install-only by deliberate decision -- see
app/database.py's docstring; that decision is about NOT building
in-place database migrations, and doesn't conflict with versioning
this much narrower, separate file format). Bump it whenever the shape
of what gets exported changes.

Two file shapes are accepted on import:
  1. This module's own JSON format, carrying a real
     `format_version` -- a genuine compatibility check is possible.
  2. Plain text (the ONLY shape the existing "Download" button has
     ever produced, and so the only shape any file "already
     downloaded" from this platform can actually be in). No version
     information exists in that shape to check -- there was never
     anywhere to put it. Importing one is accepted, but flagged
     plainly as unversioned rather than silently claiming a
     compatibility check that isn't possible.

Only ONE format_version has ever existed so far, so there is nothing
to convert FROM yet -- `convert_backup()` exists as the extension
point for when a second version is introduced, not as something with
real conversion logic today. A version mismatch today always means
"show it plainly," per this feature's own explicit fallback
instruction, not a silent best-effort guess.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone

CONFIG_BACKUP_FORMAT_VERSION = 1


@dataclass
class ImportResult:
    config_text: str | None
    compatible: bool
    is_legacy_plaintext: bool
    message: str


def build_backup_payload(*, config_text: str, source_version_number: int | None) -> dict:
    return {
        "format_version": CONFIG_BACKUP_FORMAT_VERSION,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source_version_number": source_version_number,
        "config_text": config_text,
    }


def convert_backup(payload: dict, from_version: int) -> dict | None:
    """
    Extension point for when a second format_version exists. Returns
    the payload upgraded to CONFIG_BACKUP_FORMAT_VERSION, or None if
    no conversion path is known. Today there is only ever one version
    that has existed, so this always returns None -- not a stub
    pretending to work, just genuinely nothing to convert from yet.
    """
    return None


def parse_uploaded_backup(raw_text: str) -> ImportResult:
    raw_text = raw_text.strip()
    if not raw_text:
        return ImportResult(None, False, False, "The uploaded file is empty.")

    try:
        payload = json.loads(raw_text)
    except (json.JSONDecodeError, ValueError):
        # Not JSON at all -- the plain-text shape the existing
        # Download button has always produced. No version information
        # ever existed in this shape, so none can be checked here --
        # accepted, but flagged honestly rather than silently treated
        # as verified-compatible.
        return ImportResult(
            config_text=raw_text,
            compatible=True,
            is_legacy_plaintext=True,
            message=(
                "This file has no embedded version information -- it's in the older, "
                "unversioned plain-text format every 'Download' button on this platform "
                "has always produced. It's accepted, but review the diff below carefully "
                "before applying; no compatibility check was possible."
            ),
        )

    if not isinstance(payload, dict) or "format_version" not in payload:
        return ImportResult(
            None, False, False,
            "This JSON file doesn't look like a configuration backup from this platform "
            "(no 'format_version' field found).",
        )

    file_version = payload.get("format_version")
    if file_version == CONFIG_BACKUP_FORMAT_VERSION:
        config_text = payload.get("config_text")
        if not isinstance(config_text, str) or not config_text.strip():
            return ImportResult(None, False, False, "This backup file has no configuration content in it.")
        return ImportResult(
            config_text=config_text,
            compatible=True,
            is_legacy_plaintext=False,
            message=f"Version match (format_version {file_version}). Exported at {payload.get('exported_at', 'an unknown time')}.",
        )

    converted = convert_backup(payload, file_version)
    if converted is not None:
        return ImportResult(
            config_text=converted.get("config_text"),
            compatible=True,
            is_legacy_plaintext=False,
            message=f"Converted from backup format version {file_version} to {CONFIG_BACKUP_FORMAT_VERSION}.",
        )

    return ImportResult(
        None, False, False,
        f"Version mismatch: this backup is format_version {file_version}, but this "
        f"platform writes and expects format_version {CONFIG_BACKUP_FORMAT_VERSION}. "
        "No automatic conversion is available between these versions -- restoring "
        "this file is not supported here.",
    )
