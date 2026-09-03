"""
app.models.ad_settings
========================
Active Directory / LDAP connection settings, for two DISTINCT things
this project keeps carefully separate (see app.services.ad_directory
for the full reasoning):

1. Direct LDAP connectivity FROM the management plane itself (this
   platform binding to AD to test connectivity, run a health check, or
   let an admin browse real AD group names) -- a genuine, standard
   LDAP client operation this project fully controls, using the
   `ldap3` library.

2. Configuring tac_plus-ng's OWN separate MAVIS-based AD backend
   (`mavis_tacplus_ads.pl`, confirmed real via the upstream project's
   own integration guide -- see app.services.config_compiler's AD
   section) so the DAEMON itself can authenticate TACACS+ users
   against AD.

Both consume the SAME stored settings -- one set of AD connection
details, used two ways -- but a successful connectivity test (#1)
does not by itself guarantee tac_plus-ng's own separate Perl-based
integration (#2) is configured identically; they're related but
distinct claims, and the GUI says so.

Singleton by convention, not by a database constraint: the API only
ever reads/writes the first (and normally only) row -- see
app.api.routes_ad_settings. `bind_password_encrypted` follows the
EXACT same Fernet-encryption pattern as
NetworkDevice.shared_secret_encrypted (app.security.encrypt_secret /
decrypt_secret) -- an AD service account's password is exactly as
sensitive as a device's TACACS+ shared secret, so it gets the same
treatment, never stored or logged in plaintext.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AdSettings(Base):
    __tablename__ = "ad_settings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    host: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=389)
    # Two genuinely distinct, mutually exclusive mechanisms -- confirmed
    # by the ldap3 library's own documentation, which explicitly
    # describes them as the two separate ways LDAP secures a
    # connection. use_tls: dedicated SSL from the moment the socket
    # opens (LDAPS, conventionally port 636). use_starttls: connect
    # in the clear (conventionally port 389), then explicitly upgrade
    # the SAME connection to TLS via the StartTLS extended operation
    # before any bind is attempted -- see app.services.ad_directory
    # for why the upgrade must complete before the bind, not after.
    # Both depend on the domain controller actually having a working
    # TLS/certificate setup; StartTLS is not an independent fallback
    # for a DC with no TLS configured at all, per real-world reports
    # from AD-specific StartTLS usage.
    use_tls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    use_starttls: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # Confirmed real from the upstream project's own AD integration
    # guide: a bind (service) account DN/UPN and password, an LDAP
    # search base, and a sAMAccountName-based user filter template are
    # exactly the settings mavis_tacplus_ads.pl itself needs (its
    # LDAP_USER / LDAP_PASSWD / LDAP_BASE / LDAP_FILTER setenv
    # directives) -- this model mirrors that vocabulary directly
    # rather than inventing different field names for the same thing.
    bind_dn: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    bind_password_encrypted: Mapped[str | None] = mapped_column(Text, nullable=True)
    search_base: Mapped[str] = mapped_column(String(255), nullable=False, default="")
    user_filter_template: Mapped[str] = mapped_column(
        String(255), nullable=False, default="(&(objectClass=user)(sAMAccountName=%s))"
    )

    # AD_GROUP_PREFIX / FLAG_USE_MEMBEROF in the confirmed real
    # example -- how AD group membership maps into the SAME `member ==`
    # mechanism this project's policy engine already uses for local
    # groups. group_prefix stripped from an AD group's CN before it's
    # treated as a tac_plus-ng group name; NULL/empty means no prefix
    # filtering (every AD group the user is a member of is offered).
    group_prefix: Mapped[str | None] = mapped_column(String(64), nullable=True)
    use_memberof: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
