"""
app.services.tls_certs
========================
Self-signed certificate generation (default) and custom certificate
upload, for the management GUI's own HTTPS listener. Uses the
`cryptography` library directly -- already a project dependency since
Phase 2 (Fernet encryption of device shared secrets) -- rather than
shelling out to `openssl`. No new system package is required: this is
the same library, a different part of its API (`cryptography.x509`
instead of `cryptography.fernet`).

Files live under /etc/aaa-platform/tls/, owned by the aaa-platform
service account (same ownership pattern as every other runtime secret
-- see installer/app_install.py's provision_secret_files() from
Phase 1/2), mode 0600 for the key, 0644 for the certificate (a TLS
certificate is not secret -- it's what the server hands to every
client that connects -- only the private key needs restricting).
"""
from __future__ import annotations

import datetime
import ipaddress
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

TLS_DIR = Path("/etc/aaa-platform/tls")
CERT_PATH = TLS_DIR / "server.crt"
KEY_PATH = TLS_DIR / "server.key"

DEFAULT_VALIDITY_DAYS = 825  # under the 825-day CA/Browser Forum ceiling; irrelevant for
                              # a self-signed cert with no CA, kept anyway as a sane default
DEFAULT_KEY_SIZE = 2048


class CertificateError(ValueError):
    pass


def generate_self_signed(
    *,
    common_name: str,
    organization: str | None = None,
    organizational_unit: str | None = None,
    validity_days: int = DEFAULT_VALIDITY_DAYS,
    key_size: int = DEFAULT_KEY_SIZE,
    subject_alt_names: list[str] | None = None,
) -> tuple[bytes, bytes]:
    """
    Returns (cert_pem, key_pem). Does not write to disk -- callers
    decide where and how (see write_active_certificate below), keeping
    this function pure and independently testable.
    """
    if key_size not in (2048, 3072, 4096):
        raise CertificateError("Key size must be 2048, 3072, or 4096 bits.")
    if not (1 <= validity_days <= 3650):
        raise CertificateError("Validity must be between 1 and 3650 days.")
    if not common_name.strip():
        raise CertificateError("Common Name (CN) is required -- typically the hostname or IP admins use to reach this GUI.")

    key = rsa.generate_private_key(public_exponent=65537, key_size=key_size)

    name_attributes = [x509.NameAttribute(NameOID.COMMON_NAME, common_name.strip())]
    if organization:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization.strip()))
    if organizational_unit:
        name_attributes.append(x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, organizational_unit.strip()))
    subject = issuer = x509.Name(name_attributes)

    san_entries: list[x509.GeneralName] = []
    for entry in (subject_alt_names or [common_name.strip()]):
        entry = entry.strip()
        if not entry:
            continue
        try:
            san_entries.append(x509.IPAddress(ipaddress.ip_address(entry)))
        except ValueError:
            san_entries.append(x509.DNSName(entry))

    now = datetime.datetime.now(datetime.timezone.utc)
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))  # small clock-skew tolerance
        .not_valid_after(now + datetime.timedelta(days=validity_days))
        # ca=False: this is a self-signed END-ENTITY (server) certificate,
        # not a Certificate Authority. Getting this backwards is a real
        # correctness bug, not a style choice -- some strict TLS clients
        # reject or warn on server certificates flagged as CA:TRUE.
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        )
    )
    if san_entries:
        builder = builder.add_extension(x509.SubjectAlternativeName(san_entries), critical=False)

    certificate = builder.sign(key, hashes.SHA256())

    cert_pem = certificate.public_bytes(serialization.Encoding.PEM)
    key_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return cert_pem, key_pem


def validate_certificate_pair(cert_pem: bytes, key_pem: bytes) -> x509.Certificate:
    """
    Used for both self-signed (defensive self-check after generating)
    and custom, admin-uploaded certificates (a real correctness check,
    not just a formality -- a malformed or mismatched pair uploaded
    here would otherwise only surface as a cryptic TLS handshake
    failure at the next service restart, with no diagnostic in the GUI
    at all).
    """
    try:
        certificate = x509.load_pem_x509_certificate(cert_pem)
    except ValueError as exc:
        raise CertificateError(f"Could not parse certificate: {exc}") from exc

    try:
        private_key = serialization.load_pem_private_key(key_pem, password=None)
    except ValueError as exc:
        raise CertificateError(f"Could not parse private key: {exc}") from exc

    cert_public_numbers = certificate.public_key().public_numbers()
    key_public_numbers = private_key.public_key().public_numbers()
    if cert_public_numbers != key_public_numbers:
        raise CertificateError("This certificate and private key do not match each other.")

    now = datetime.datetime.now(datetime.timezone.utc)
    if certificate.not_valid_after_utc < now:
        raise CertificateError(f"This certificate expired on {certificate.not_valid_after_utc.date()}.")

    return certificate


def write_active_certificate(cert_pem: bytes, key_pem: bytes, *, uid: int, gid: int) -> None:
    """Validates, then writes as the currently active cert/key, with
    correct ownership so the (unprivileged) running service can read
    the key. Takes effect on the next restart of aaa-platform.service,
    not instantly -- same restart-required note as platform_settings.py."""
    validate_certificate_pair(cert_pem, key_pem)

    import os
    TLS_DIR.mkdir(parents=True, exist_ok=True)

    CERT_PATH.write_bytes(cert_pem)
    KEY_PATH.write_bytes(key_pem)
    os.chown(CERT_PATH, uid, gid)
    os.chown(KEY_PATH, uid, gid)
    CERT_PATH.chmod(0o644)
    KEY_PATH.chmod(0o600)


def describe_active_certificate() -> dict | None:
    """For the Settings GUI: what's currently installed, without
    exposing the private key material at all."""
    if not CERT_PATH.exists():
        return None
    try:
        certificate = x509.load_pem_x509_certificate(CERT_PATH.read_bytes())
    except ValueError:
        return {"error": "The active certificate file could not be parsed."}

    def _name_or_none(oid):
        attrs = certificate.subject.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None

    return {
        "common_name": _name_or_none(NameOID.COMMON_NAME),
        "organization": _name_or_none(NameOID.ORGANIZATION_NAME),
        "not_valid_before": certificate.not_valid_before_utc.isoformat(),
        "not_valid_after": certificate.not_valid_after_utc.isoformat(),
        "serial_number": format(certificate.serial_number, "x"),
        "is_expired": certificate.not_valid_after_utc < datetime.datetime.now(datetime.timezone.utc),
    }
