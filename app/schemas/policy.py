"""
app.schemas.policy
====================
`name` becomes a bare identifier inside a generated tac_plus-ng
`profile {}` block -- same identifier-safety reasoning as every other
named entity in this project.

PAM Expansion Plan §4/Increment 1: replaces the old inline
`command_rules` list with `condition_*` fields (a Policy is now
self-contained -- it declares both "when do I match" and "what do I
grant") and `command_set_ids` (an ordered list of CommandSet ids the
policy references, replacing duplicated rule lists per policy -- see
app.schemas.command_set for where rules actually live now).

Like CommandSet, a policy's referenced-set list is edited as a whole
on every save (the full ordered id list sent every time, replaced
wholesale server-side) rather than through separate association CRUD
endpoints -- same reasoning as before: this is how the GUI actually
edits it.
"""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")
_VALID_ACTIONS = {"permit", "deny"}


class PolicyBase(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=2000)
    enabled: bool = True
    priority: int = Field(default=0, ge=0, le=100000)

    # Conditions -- None means "matches anything" for that dimension.
    # See app/models/policy.py's docstring for which are implemented
    # vs. deferred (source-IP/time conditions aren't wired in yet).
    condition_group_id: str | None = None
    condition_device_id: str | None = None
    condition_device_group_id: str | None = None

    default_priv_lvl: int = Field(default=1, ge=0, le=15)
    default_action: str = Field(default="deny")

    # Manual approval mode -- see app/models/policy.py's own docstring
    # on requires_manual_approval for the full design reasoning
    # (a separate axis from default_action, not a third value of it).
    requires_manual_approval: bool = False
    manual_default_command_set_id: str | None = None

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not _NAME_PATTERN.match(v):
            raise ValueError(
                "Policy name must start with a letter or digit and contain only "
                "letters, digits, hyphens, and underscores (max 64 chars) -- it is "
                "used as a raw identifier in the generated tac_plus-ng configuration."
            )
        return v

    @field_validator("default_action")
    @classmethod
    def validate_default_action(cls, v: str) -> str:
        if v not in _VALID_ACTIONS:
            raise ValueError("default_action must be 'permit' or 'deny'.")
        return v

    @model_validator(mode="after")
    def validate_manual_mode(self):
        # Deliberately NOT requiring manual_default_command_set_id
        # whenever requires_manual_approval is true -- a manual-mode
        # policy is still valid to save mid-draft, before every field
        # is filled in (matching app/models/policy.py's own reasoning
        # for why the column itself is nullable). What's actually
        # enforced: a command set can only be attached as the manual
        # default when manual mode is actually on -- carrying one over
        # from an earlier edit after switching back to Permit/Deny
        # would silently misrepresent what the policy does.
        if not self.requires_manual_approval and self.manual_default_command_set_id:
            raise ValueError(
                "manual_default_command_set_id can only be set when requires_manual_approval is true."
            )
        return self


class PolicyCreate(PolicyBase):
    command_set_ids: list[str] = Field(default_factory=list)
    change_description: str | None = Field(default=None, max_length=500)


class PolicyUpdate(PolicyBase):
    command_set_ids: list[str] = Field(default_factory=list)
    change_description: str | None = Field(default=None, max_length=500)


class ReferencedCommandSet(BaseModel):
    id: str
    name: str
    enabled: bool


class PolicyOut(PolicyBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    condition_group_name: str | None = None
    condition_device_name: str | None = None
    condition_device_group_name: str | None = None
    manual_default_command_set_name: str | None = None
    has_condition_tree: bool = False
    command_sets: list[ReferencedCommandSet] = Field(default_factory=list)
