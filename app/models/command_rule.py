"""
app.models.command_rule
=========================
Ordered, per-command permit/deny rules. Belongs to a reusable
CommandSet (command_set_id), not directly to a Policy -- a Policy
grants access by referencing one or more CommandSets (see
PolicyCommandSet) rather than duplicating its own rule list, per PAM
Expansion Plan §5.

IMPORTANT HONESTY NOTE (carried forward unchanged): the surrounding
profile/ruleset/permit/deny mechanics (app/models/policy.py) are
confirmed against four independent real tac_plus-ng configs. Matching
a SPECIFIC command name via `cmd =~ /pattern/` is NOT directly
confirmed the same way -- every real example found only showed the
exact-match `cmd == ""` case (an empty command, meaning "just logging
in, nothing typed yet"). What IS confirmed is that `cmd` is a real
script variable comparable with `==`, and that `=~` is a real
regex-match operator used elsewhere in this exact script language
against other string variables (`nas-name`, `user`, `$PASSWORD`).
Extending that operator to `cmd` is a reasoned inference from
consistent language mechanics, not a fabrication from nothing -- but
it's one level less certain than everything else this project has
shipped, and should be the first thing verified against a real
command-authorization request from an actual NAS.

`command_pattern` is a PCRE regular expression (the daemon's own
version string reports PCRE2 support), evaluated against the `cmd`
variable in generation order. Rules within a single CommandSet are
evaluated as a first-match-wins chain (ACL-style precedent confirmed
elsewhere in tac_plus-ng's own docs: "the first regex that matches
ends the evaluation"), which is why `order` matters and is a required,
explicit field rather than left to insertion order. Deny-overrides
ACROSS command sets (a Policy's referenced sets are compiled
deny-rules-first) is handled in app/services/policy_engine.py, not
here.
"""
import uuid
from datetime import datetime, timezone

from sqlalchemy import DateTime, ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from ..database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class CommandRule(Base):
    __tablename__ = "command_rules"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    command_set_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("command_sets.id", ondelete="CASCADE"), nullable=False, index=True
    )
    category_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True), ForeignKey("command_categories.id", ondelete="SET NULL"), nullable=True
    )

    order: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    action: Mapped[str] = mapped_column(String(8), nullable=False)  # "permit" | "deny"
    command_pattern: Mapped[str] = mapped_column(String(256), nullable=False)  # PCRE regex tested against `cmd`
    description: Mapped[str | None] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
