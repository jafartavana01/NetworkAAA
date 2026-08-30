"""
app.services.apply_progress
==============================
In-memory, per-process progress tracking for a bulk "Apply AAA to
all" run -- backs the live "Applying..." display, which needs to see
updates WHILE a multi-device SSH push is still in progress, not only
after the whole batch finishes. A single blocking HTTP request/
response can't do that; this lets the apply run as a background task
that updates shared state as it goes, while the frontend polls a
separate read-only endpoint for the current state.

Deliberately in-memory, not a database table: this is transient,
single-session progress for something already fully recorded
elsewhere once it completes (every device this creates, and its
audit trail, lives in the real Device/ConfigVersion tables as usual)
-- a process restart losing an in-flight progress record is a
non-issue, not a data-loss concern, and avoids adding schema for
something with no reason to outlive the browser tab watching it.

NOT thread-safe against true concurrent writers to the SAME session
id, which is fine here: exactly one background task ever owns a given
session id, appending to it; readers (the progress endpoint) only
ever read. A dict's own atomicity for single-key get/set is
sufficient for that access pattern.
"""
from __future__ import annotations

import time
import uuid

_SESSIONS: dict[str, dict] = {}
_MAX_AGE_SECONDS = 3600  # stale sessions are dropped on next write, not eagerly swept


def start_session() -> str:
    session_id = str(uuid.uuid4())
    _SESSIONS[session_id] = {"status": "running", "log": [], "results": None, "started_at": time.time()}
    _prune_stale()
    return session_id


def append_log(session_id: str, line: str) -> None:
    session = _SESSIONS.get(session_id)
    if session is not None:
        session["log"].append(line)


def finish_session(session_id: str, results: list[dict]) -> None:
    session = _SESSIONS.get(session_id)
    if session is not None:
        session["status"] = "done"
        session["results"] = results


def get_session(session_id: str) -> dict | None:
    return _SESSIONS.get(session_id)


def _prune_stale() -> None:
    cutoff = time.time() - _MAX_AGE_SECONDS
    stale = [sid for sid, s in _SESSIONS.items() if s.get("started_at", 0) < cutoff]
    for sid in stale:
        _SESSIONS.pop(sid, None)
