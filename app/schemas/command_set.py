"""
app.schemas.command_set
=========================
PAM Expansion Plan §5. Mirrors app.schemas.policy's command-rule
sub-editing pattern closely on purpose: a CommandSet's rules are
edited as a whole (the full ordered list sent on every save, replaced
wholesale server-side) rather than through separate rule-level CRUD
endpoints, same reasoning as Policy's command_rules list had in
Phase 5 -- this is how the GUI actually edits it (one form, one
ordered list, one save).
"""
from __future__ import annotations

import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")
_VALID_ACTIONS = {"permit", "deny"}


class CommandRuleInput(BaseModel):
    order: int = Field(ge=0, le=9999)
    action: str
    command_pattern: str = Field(min_length=1, max_length=256)
    description: str | None = Field(default=None, max_length=500)
    category_id: str | None = None

    @field_validator("action")
    @classmethod
    def validate_action(cls, v: str) -> str:
        if v not in _VALID_ACTIONS:
            raise ValueError("action must be 'permit' or 'deny'.")
        return v

    @field_validator("command_pattern")
    @classmethod
    def validate_pattern(cls, v: str) -> str:
        try:
            re.compile(v)
        except re.error as exc:
            raise ValueError(f"'{v}' is not a valid regular expression: {exc}")
        return v


class CommandRuleOut(CommandRuleInput):
    model_config = ConfigDict(from_attributes=True)

    id: str
    category_name: str | None = None


class CommandSetBase(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    description: str | None = Field(default=None, max_length=2000)
    vendor: str = Field(default="cisco_ios", max_length=32)
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not _NAME_PATTERN.match(v):
            raise ValueError(
                "Command set name must start with a letter or digit and contain only "
                "letters, digits, hyphens, and underscores (max 64 chars)."
            )
        return v


class CommandSetCreate(CommandSetBase):
    rules: list[CommandRuleInput] = Field(default_factory=list)


class CommandSetUpdate(CommandSetBase):
    rules: list[CommandRuleInput] = Field(default_factory=list)


class CommandSetOut(CommandSetBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    rules: list[CommandRuleOut] = Field(default_factory=list)
    policy_count: int = 0  # how many policies currently reference this set
