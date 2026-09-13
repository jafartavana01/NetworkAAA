from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")


class MonitoringSettingsUpdate(BaseModel):
    enabled: bool = False


class MonitoringSettingsOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    enabled: bool


class UnrecognizedConnectionOut(BaseModel):
    ip_address: str
    sample_line: str
    occurrences: int


class QuickAddDeviceRequest(BaseModel):
    ip_address: str
    name: str = Field(min_length=1, max_length=64)
    shared_secret: str = Field(min_length=1, max_length=256)

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        # Same identifier-safety restriction as app.schemas.device --
        # this name becomes a raw `host NAME {}` block identifier too.
        if not _NAME_PATTERN.match(v):
            raise ValueError(
                "Device name must start with a letter or digit and contain only "
                "letters, digits, hyphens, and underscores (max 64 chars)."
            )
        return v

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, v: str) -> str:
        # Mirrors app.schemas.device's own bare-IP-to-/32 normalization
        # (not imported directly -- that function is private-by-
        # convention to its own module) so a device created this way
        # ends up in exactly the same stored format as one created
        # through the normal Devices page.
        try:
            addr = ipaddress.ip_address(v.strip())
        except ValueError as exc:
            raise ValueError(f"'{v}' is not a valid IP address.") from exc
        prefix = 32 if addr.version == 4 else 128
        return str(ipaddress.ip_network(f"{addr}/{prefix}", strict=False))
