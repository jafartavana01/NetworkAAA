"""
app.api.routes_tacacs_logs
============================
Spec section 52 (Phase 3): "GUI must display the authentication
event." tac_plus-ng writes AUTHEN successes/failures to the access
log, and AUTHOR permit/deny decisions to the authorization log --
both configured in app.services.config_compiler's STATIC_PREAMBLE.

Both are returned as RAW text rather than parsed into structured
fields (timestamp/user/result columns) -- the exact line format
tac_plus-ng writes to a file-based log target was not independently
confirmed (only syslog-style output was seen during research, which
has a different prefix added by syslog itself, not by tac_plus-ng).
Displaying raw text is honest about that; inventing a parser for an
unconfirmed format risks silently mis-displaying or dropping real
events, which would be worse than not parsing at all. Contrast with
app/services/accounting_log.py (Phase 6), which CAN safely parse,
because that log's format is one this project defines itself.

`search` is a plain substring filter the admin supplies themselves --
this project isn't claiming to know what a "failure" looks like in an
unconfirmed format, but the admin typing their own term (e.g. "fail",
"denied") to narrow the tail is still genuinely useful, and honest
about who's doing the interpreting.
"""
from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends

from ..config import LOG_DIR
from ..models.admin import AdminUser
from .deps import get_current_admin

router = APIRouter(prefix="/api/tacacs-logs", tags=["tacacs-logs"])

ACCESS_LOG_PATH = LOG_DIR / "tac_plus-ng-access.log"
AUTHORIZATION_LOG_PATH = LOG_DIR / "tac_plus-ng-authorization.log"


def _tail_log(path: Path, *, lines: int, search: str | None) -> dict:
    lines = max(1, min(lines, 1000))

    if not path.exists():
        return {
            "path": str(path),
            "content": "",
            "note": "No log file yet -- it's created by tac_plus-ng on its first "
                     "logged event, so this is expected before any request of this kind.",
        }

    with path.open("r", encoding="utf-8", errors="replace") as fh:
        all_lines = fh.readlines()

    if search:
        needle = search.lower()
        all_lines = [line for line in all_lines if needle in line.lower()]

    tail = all_lines[-lines:]
    note = None
    if search and not tail:
        note = f"No lines matched '{search}'."
    return {"path": str(path), "content": "".join(tail), "note": note}


@router.get("/access")
def tail_access_log(
    lines: int = 100,
    search: str | None = None,
    _admin: AdminUser = Depends(get_current_admin),
):
    return _tail_log(ACCESS_LOG_PATH, lines=lines, search=search)


@router.get("/authorization")
def tail_authorization_log(
    lines: int = 100,
    search: str | None = None,
    _admin: AdminUser = Depends(get_current_admin),
):
    return _tail_log(AUTHORIZATION_LOG_PATH, lines=lines, search=search)
