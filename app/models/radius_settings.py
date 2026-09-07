"""
app.models.radius_settings
=============================
Platform-level RADIUS listener settings.

Every default and directive here is taken from the upstream sample
`tac_plus-ng/sample/tac_plus-ng-radius.cfg`, read from the real
checkout on the installed server -- not inferred. See
`docs/RADIUS_FINDINGS.md` for the verbatim source lines.

Confirmed structure this backs:

    id = spawnd {
        listen { port = 1812 protocol = UDP }                    # auth
        listen { port = 1813 protocol = UDP flag = accounting }   # acct
    }
    id = tac_plus-ng {
        log rad-accesslog { destination = ... }
        log rad-acctlog   { destination = ... }
        radius.access log = rad-accesslog
        radius.accounting log = rad-acctlog
        include = "$CONFDIR/radius-dict.cfg"
    }

Singleton by convention, matching AdSettings and
AuditScheduleSettings: the API only ever reads/writes the first row.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Integer, String
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class RadiusSettings(Base):
    __tablename__ = "radius_settings"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    # Disabled by default. Enabling adds listeners to the daemon that
    # the operator did not previously have, so it must be an explicit
    # choice rather than something a software update switches on.
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # 1812/1813 are the IANA-registered RADIUS ports and exactly what
    # the upstream sample uses.
    auth_port: Mapped[int] = mapped_column(Integer, default=1812, nullable=False)
    acct_port: Mapped[int] = mapped_column(Integer, default=1813, nullable=False)

    # The sample's listen lines use `protocol = UDP`. TCP/DTLS/TLS are
    # documented by upstream as supported, but their listen syntax was
    # NOT in the sample that was read, so only UDP is offered here --
    # the same rule applied to IPv6 host addresses elsewhere in this
    # project.
    protocol: Mapped[str] = mapped_column(String(16), default="UDP", nullable=False)

    # Vendor dictionaries ship with the distribution and are pulled in
    # by reference, not copied: `include = "$CONFDIR/radius-dict.cfg"`.
    include_dictionaries: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    updated_by: Mapped[str | None] = mapped_column(String(64), nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow)
