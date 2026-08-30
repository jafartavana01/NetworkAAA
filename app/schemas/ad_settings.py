"""
app.schemas.ad_settings
=========================
`bind_password` is write-only, matching every other secret field in
this project (NetworkDevice's shared secret, admin passwords): the
GET response never includes it, even encrypted, and PUT leaves the
stored password unchanged when the field is omitted -- the same
"blank means keep existing" convention already used for
TacacsUserUpdate.password.
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class AdSettingsUpdate(BaseModel):
    enabled: bool = False
    host: str = Field(default="", max_length=255)
    port: int = Field(default=389, ge=1, le=65535)
    use_tls: bool = False
    bind_dn: str = Field(default="", max_length=255)
    bind_password: str | None = Field(default=None, max_length=512)
    search_base: str = Field(default="", max_length=255)
    user_filter_template: str = Field(default="(&(objectClass=user)(sAMAccountName=%s))", max_length=255)
    group_prefix: str | None = Field(default=None, max_length=64)
    use_memberof: bool = True


class AdSettingsOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    enabled: bool
    host: str
    port: int
    use_tls: bool
    bind_dn: str
    has_password: bool = False
    search_base: str
    user_filter_template: str
    group_prefix: str | None
    use_memberof: bool
    updated_at: str | None = None


class AdTestRequest(BaseModel):
    """Lets an admin test connectivity with a password they just
    typed but haven't saved yet -- host/bind_dn/etc. are taken from
    this payload too (not the stored settings), so "Test" always
    checks exactly what's currently in the form, not what was last
    saved."""
    host: str = Field(default="", max_length=255)
    port: int = Field(default=389, ge=1, le=65535)
    use_tls: bool = False
    bind_dn: str = Field(default="", max_length=255)
    bind_password: str | None = Field(default=None, max_length=512)
    search_base: str = Field(default="", max_length=255)
