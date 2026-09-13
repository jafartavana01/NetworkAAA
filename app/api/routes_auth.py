"""
app.api.routes_auth
=====================
Login/logout for the platform admin GUI + REST API (spec section 25:
"Secure GUI authentication", section 35: session security/CSRF).
Deliberately rate-limits failed attempts per username in-process, and
never reveals whether a failure was due to an unknown username, a
wrong password, or a login attempt from outside that account's
trusted-host allowlist (AdminUser.allowed_source_ips) -- all three
return the exact same generic error.
"""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from sqlalchemy.orm import Session

from .. import security
from ..database import get_db
from ..models.admin import AdminUser
from ..schemas.auth import AdminUserOut, LoginRequest
from .deps import get_current_admin, verify_csrf

router = APIRouter(prefix="/api/auth", tags=["auth"])

# Simple in-process throttle: 5 failed attempts -> 60s lockout per username.
# A future HA-aware version would move this into PostgreSQL/shared state;
# noted here rather than silently pretending this survives multi-node.
_FAILED_ATTEMPTS: dict[str, list[float]] = {}
_MAX_ATTEMPTS = 5
_LOCKOUT_SECONDS = 60


def _is_locked_out(username: str) -> bool:
    attempts = _FAILED_ATTEMPTS.get(username, [])
    recent = [t for t in attempts if time.time() - t < _LOCKOUT_SECONDS]
    _FAILED_ATTEMPTS[username] = recent
    return len(recent) >= _MAX_ATTEMPTS


def _record_failure(username: str) -> None:
    _FAILED_ATTEMPTS.setdefault(username, []).append(time.time())


def _clear_failures(username: str) -> None:
    _FAILED_ATTEMPTS.pop(username, None)


@router.post("/login")
def login(payload: LoginRequest, request: Request, response: Response, db: Session = Depends(get_db)):
    if _is_locked_out(payload.username):
        raise HTTPException(
            status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many failed attempts. Try again in a minute.",
        )

    admin = db.query(AdminUser).filter(AdminUser.username == payload.username).first()

    # request.client.host is the real TCP peer address for a direct
    # uvicorn bind (the only supported deployment so far) -- NOT
    # spoofable by the client, unlike an X-Forwarded-For header would
    # be. If a reverse proxy is ever put in front of this app, this
    # check needs to switch to trusting X-Forwarded-For ONLY when the
    # immediate peer is that known proxy, or trusted-host restriction
    # becomes trivially bypassable by anyone setting their own header.
    source_ip = request.client.host if request.client else None
    host_allowed = (
        admin is not None
        and source_ip is not None
        and security.is_source_ip_allowed(admin.allowed_source_ips, source_ip)
    )

    valid = (
        admin is not None
        and admin.is_active
        and host_allowed
        and security.verify_password(payload.password, admin.password_hash)
    )

    if not valid:
        _record_failure(payload.username)
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid username or password")

    _clear_failures(payload.username)

    from datetime import datetime, timezone
    admin.last_login_at = datetime.now(timezone.utc)
    db.commit()

    token = security.create_session_token(admin.username)
    csrf_token = security.new_csrf_token()

    # `secure` reflects how THIS request actually arrived, rather than
    # being hardcoded True. Hardcoding it would silently break login
    # the moment this is reached over plain HTTP from anywhere other
    # than 127.0.0.1/localhost (which browsers treat as an implicit
    # secure context, masking the problem in the common dev-tunnel
    # case) -- the browser accepts a Secure cookie on login but then
    # refuses to send it back on subsequent non-HTTPS requests, which
    # looks like login silently not "taking" rather than a clear
    # error. This adapts automatically if TLS is added in front later.
    is_secure_request = request.url.scheme == "https"

    response.set_cookie(
        security.SESSION_COOKIE_NAME,
        token,
        max_age=security.SESSION_MAX_AGE_SECONDS,
        httponly=True,
        secure=is_secure_request,
        samesite="lax",
    )
    response.set_cookie(
        security.CSRF_COOKIE_NAME,
        csrf_token,
        max_age=security.SESSION_MAX_AGE_SECONDS,
        httponly=False,  # must be readable by JS to echo back as X-CSRF-Token
        secure=is_secure_request,
        samesite="lax",
    )
    return {"status": "ok", "username": admin.username}


@router.post("/logout", dependencies=[Depends(verify_csrf)])
def logout(response: Response):
    response.delete_cookie(security.SESSION_COOKIE_NAME)
    response.delete_cookie(security.CSRF_COOKIE_NAME)
    return {"status": "ok"}


@router.get("/me", response_model=AdminUserOut)
def me(admin: AdminUser = Depends(get_current_admin)):
    return admin
