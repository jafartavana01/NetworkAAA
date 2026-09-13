"""
app.security
=============
Password hashing (bcrypt, called directly), signed session cookies
(itsdangerous), and reversible encryption for device shared secrets
(Fernet, via cryptography). No plaintext admin passwords are ever
stored (spec section 17); device shared secrets ARE recoverable by
design, because tac_plus-ng's own configuration file needs the real
value -- but only via encrypt/decrypt through this module, and only
ever decrypted in memory at config-compile time, never logged or
returned by the API in plaintext (spec section 36).

Password hashing calls the `bcrypt` package directly rather than going
through passlib's CryptContext. passlib (last released 2020, no
functional updates since) probes bcrypt's internals to detect its
version, using an attribute (`bcrypt.__about__.__version__`) that
bcrypt 4.x removed -- passlib catches its own failure and keeps
working ("(trapped) error reading bcrypt version"), but it's a
permanent, unfixable-upstream warning on every single hash/verify call
for as long as passlib stays unmaintained. bcrypt's own direct API
(`hashpw`/`checkpw`) is stable, small, and sufficient for what this
module needs, so it's used directly instead.
"""
from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .config import get_settings

SESSION_COOKIE_NAME = "aaa_platform_session"
SESSION_MAX_AGE_SECONDS = 8 * 60 * 60  # 8 hours
CSRF_COOKIE_NAME = "aaa_platform_csrf"

# bcrypt's own algorithm silently ignores password bytes beyond this
# length (a limitation of bcrypt itself, not this implementation).
# Truncating explicitly here, rather than letting bcrypt do it
# implicitly, keeps hash_password/verify_password behaving identically
# for any password length instead of raising on unusually long input.
_BCRYPT_MAX_BYTES = 72


def _bcrypt_bytes(password: str) -> bytes:
    return password.encode("utf-8")[:_BCRYPT_MAX_BYTES]


def hash_password(password: str) -> str:
    return bcrypt.hashpw(_bcrypt_bytes(password), bcrypt.gensalt()).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(_bcrypt_bytes(password), password_hash.encode("utf-8"))
    except (ValueError, TypeError):
        return False


def _fernet() -> Fernet:
    return Fernet(get_settings().secret_encryption_key.encode("utf-8"))


def encrypt_secret(plaintext: str) -> str:
    """Returns a Fernet token (str) safe to store in the database."""
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("utf-8")


def decrypt_secret(token: str) -> str:
    """Raises ValueError if the token is invalid/tampered/wrong key."""
    try:
        return _fernet().decrypt(token.encode("utf-8")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Stored secret could not be decrypted (wrong key or corrupted data).") from exc


def _serializer() -> URLSafeTimedSerializer:
    return URLSafeTimedSerializer(get_settings().session_secret, salt="aaa-platform-session")


def create_session_token(username: str) -> str:
    return _serializer().dumps({"username": username})


def read_session_token(token: str) -> str | None:
    try:
        data = _serializer().loads(token, max_age=SESSION_MAX_AGE_SECONDS)
        return data.get("username")
    except (BadSignature, SignatureExpired):
        return None


def new_csrf_token() -> str:
    return secrets.token_urlsafe(32)


def parse_allowed_source_ips(raw: str | None) -> list:
    """
    Parses AdminUser.allowed_source_ips (comma-separated IPs/CIDRs,
    e.g. "10.0.0.5, 192.168.1.0/24") into a list of ipaddress network
    objects. Raises ValueError on the first unparseable entry -- used
    both for validating admin input (app.schemas.admin) and for the
    actual login-time check below, so the two can never silently
    disagree about what a given string means.
    """
    if not raw or not raw.strip():
        return []
    import ipaddress

    networks = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            if "/" in part:
                networks.append(ipaddress.ip_network(part, strict=False))
            else:
                addr = ipaddress.ip_address(part)
                max_prefix = 32 if addr.version == 4 else 128
                networks.append(ipaddress.ip_network(f"{addr}/{max_prefix}"))
        except ValueError as exc:
            raise ValueError(f"'{part}' is not a valid IP address or CIDR network.") from exc
    return networks


def is_source_ip_allowed(allowed_source_ips: str | None, source_ip: str) -> bool:
    """
    None/empty allowed list means unrestricted -- login from anywhere,
    the default and only possible state for a brand-new account. An
    unparseable `source_ip` (shouldn't happen -- it comes from
    Request.client.host, not user input) fails closed (denied) rather
    than silently bypassing the restriction.
    """
    import ipaddress

    networks = parse_allowed_source_ips(allowed_source_ips)
    if not networks:
        return True
    try:
        addr = ipaddress.ip_address(source_ip)
    except ValueError:
        return False
    return any(addr in network for network in networks)
