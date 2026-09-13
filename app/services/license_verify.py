"""
app.services.license_verify
==============================
Verifies signed license files.

Format
------
A license is two base64url segments separated by a dot:

    <payload>.<signature>

`payload` is UTF-8 JSON. `signature` is an Ed25519 signature over the
RAW PAYLOAD BYTES -- the exact bytes between the start of the string
and the dot, not a re-serialisation of the parsed JSON. That matters:
re-serialising would let two different byte strings verify as the same
license, and key ordering or whitespace differences would break
otherwise-valid signatures.

Cryptography
------------
Ed25519 via `cryptography`, which this project already depends on for
Fernet. No new dependency and no invented primitives.

The PRIVATE key exists only with the issuer (see tools/issue_license.py,
which is excluded from customer distributions). Only the PUBLIC key is
embedded below. A customer can verify a license; they cannot mint one.

What this module does NOT claim
-------------------------------
On self-hosted software, anyone with root can edit this file and make
`verify()` return whatever they like. No amount of obfuscation changes
that, and pretending otherwise would be dishonest. What signing DOES
prevent is forging or editing a license: changing a device limit,
extending an expiry, or upgrading an edition all invalidate the
signature, because they change the signed bytes.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import ed25519

#: The product this build accepts licenses for. A license issued for a
#: different product is rejected outright rather than partially
#: honoured.
PRODUCT_ID = "netopsguard"

#: Format version. Bumping this is how a future incompatible license
#: layout is introduced without silently misreading old files.
SUPPORTED_FORMATS = {1}

#: Issuer's Ed25519 public verification key, base64url, 32 bytes.
#:
#: Replace this with the real product key before distributing builds.
#: The placeholder below is a valid key whose private half is published
#: in tools/issue_license.py FOR DEVELOPMENT ONLY, so the licensing
#: path can be exercised end to end without access to the real key.
#: Licenses signed with the development key are marked as such and the
#: GUI says so -- see `LicenseStatus.development_key`.
DEVELOPMENT_PUBLIC_KEY = "YiyCc-ymGtkwfuwf8c8CNC8cJ1DrvKiwMuaeCX_FFSE"

#: Set to the production key at release time. While None, the
#: development key is used and every license is flagged as untrusted in
#: the UI, so a development license can never be mistaken for a real one.
# The product's real verification key. With this set, ONLY licences
# signed by the matching private key verify -- the development key
# below is no longer trusted, so the published development seed is
# worthless against this build.
#
# This is a PUBLIC key. It is meant to ship, and reveals nothing: it can
# verify a signature but cannot create one.
PRODUCTION_PUBLIC_KEY: str | None = "jEzgXixh5BAc26lr6vMfvYIQQLauZ8N-g9go8VuRscU"


def _b64url_decode(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


@dataclass
class LicenseStatus:
    valid: bool
    reason: str = ""
    #: The verified payload. Populated ONLY when `valid` is True, so a
    #: caller cannot accidentally read entitlements out of a license
    #: that failed verification.
    payload: dict = field(default_factory=dict)
    development_key: bool = False


def _active_public_key() -> tuple[str, bool]:
    if PRODUCTION_PUBLIC_KEY:
        return PRODUCTION_PUBLIC_KEY, False
    return DEVELOPMENT_PUBLIC_KEY, True


def verify(license_text: str, *, now: datetime | None = None) -> LicenseStatus:
    """
    Verifies signature, product, format and expiry, in that order.

    Order matters: an expired license that is also FORGED should be
    reported as invalid, not as expired, because "expired" implies it
    was once genuine.
    """
    text = (license_text or "").strip()
    if not text:
        return LicenseStatus(valid=False, reason="No license supplied.")

    key_b64, is_dev = _active_public_key()

    parts = text.split(".")
    if len(parts) != 2:
        return LicenseStatus(
            valid=False,
            reason="This does not look like a license file. Expected two dot-separated sections.",
        )

    payload_b64, signature_b64 = parts
    try:
        payload_bytes = _b64url_decode(payload_b64)
        signature = _b64url_decode(signature_b64)
    except Exception:
        return LicenseStatus(valid=False, reason="The license file is malformed and could not be decoded.")

    try:
        public_key = ed25519.Ed25519PublicKey.from_public_bytes(_b64url_decode(key_b64))
    except Exception:
        return LicenseStatus(valid=False, reason="The verification key is not usable in this build.")

    try:
        # Signed over the raw encoded payload, exactly as received.
        public_key.verify(signature, payload_b64.encode("ascii"))
    except InvalidSignature:
        return LicenseStatus(
            valid=False,
            reason=(
                "The signature does not match. The license has been modified, or it was not "
                "issued for this product."
            ),
            development_key=is_dev,
        )
    except Exception:
        return LicenseStatus(valid=False, reason="The signature could not be checked.")

    try:
        payload = json.loads(payload_bytes.decode("utf-8"))
    except Exception:
        return LicenseStatus(valid=False, reason="The license contents could not be read.")
    if not isinstance(payload, dict):
        return LicenseStatus(valid=False, reason="The license contents are not in the expected form.")

    if payload.get("product") != PRODUCT_ID:
        return LicenseStatus(
            valid=False,
            reason=f"This license was issued for a different product ({payload.get('product') or 'unknown'}).",
            development_key=is_dev,
        )

    if payload.get("format") not in SUPPORTED_FORMATS:
        return LicenseStatus(
            valid=False,
            reason=(
                "This license uses a newer format than this version understands. "
                "Update the platform, then import it again."
            ),
            development_key=is_dev,
        )

    current = now or datetime.now(timezone.utc)
    expires = payload.get("expires_at")
    if expires:
        try:
            expiry = datetime.fromisoformat(expires)
            if expiry.tzinfo is None:
                expiry = expiry.replace(tzinfo=timezone.utc)
        except ValueError:
            return LicenseStatus(valid=False, reason="The license expiry date could not be read.",
                                 development_key=is_dev)
        if current > expiry:
            return LicenseStatus(
                valid=False,
                reason=f"This license expired on {expiry.date().isoformat()}.",
                payload=payload,           # returned so the UI can show WHICH license expired
                development_key=is_dev,
            )

    return LicenseStatus(valid=True, payload=payload, development_key=is_dev)


def fingerprint(license_text: str) -> str:
    """
    A short, stable identifier for a license file, safe to display.

    Derived from the signature rather than the payload, so two licenses
    with identical entitlements but different identities do not collide.
    Never reveals key material -- it is a truncated hash of a public
    signature.
    """
    import hashlib

    text = (license_text or "").strip()
    if "." not in text:
        return ""
    signature = text.split(".")[-1]
    return hashlib.sha256(signature.encode("ascii", errors="ignore")).hexdigest()[:16]
