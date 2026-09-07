"""
app.web.auth_helpers
======================
Shared by every web.routes_* module: resolves the current admin from
the signed session cookie for server-rendered pages (as opposed to
app.api.deps.get_current_admin, which is the JSON-API version that
raises 401 instead of returning None). Kept in one place so page
routes across modules can't quietly diverge on how they check login
state.
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from .. import security
from ..database import get_sessionmaker
from ..models.admin import AdminUser


def redirect_to_login(session_token: str | None = None):
    """
    Bounce to the login page, CLEARING a session cookie that exists but
    no longer validates.

    Without this, a cookie signed with a previous session secret (an
    upgrade, a restored install, a rebuilt server) leaves the browser
    in a silent loop: it keeps sending a token the server keeps
    rejecting, so correct credentials appear to "do nothing" while
    wrong ones correctly show an error -- which points the user at
    their password rather than at the stale cookie. Deleting the bad
    cookie on the way out breaks the loop on the first bounce.
    """
    from fastapi.responses import RedirectResponse

    response = RedirectResponse(url="/login", status_code=302)
    if session_token:
        response.delete_cookie(security.SESSION_COOKIE_NAME)
        response.delete_cookie(security.CSRF_COOKIE_NAME)
    return response


def current_admin_or_none(session_token: str | None) -> AdminUser | None:
    if not session_token:
        return None
    username = security.read_session_token(session_token)
    if not username:
        return None
    session_local = get_sessionmaker()
    db: Session = session_local()
    try:
        return db.query(AdminUser).filter(AdminUser.username == username).first()
    finally:
        db.close()
