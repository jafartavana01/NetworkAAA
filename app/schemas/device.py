"""
app.schemas.device
====================
Validation here is a security boundary, not just a UX nicety: `name`
becomes a bare identifier inside a generated tac_plus-ng `host {}`
block (app.services.config_compiler), so it's restricted to a
conservative safe charset rather than escaped -- there's no confirmed
quoting mechanism for that grammar position, so restriction is the
only safe option (spec section 35: never construct config from
unsanitized input). IP addresses are parsed with Python's `ipaddress`
module, which rejects anything that isn't a real, unambiguous address.
"""
from __future__ import annotations

import ipaddress
import re

from pydantic import BaseModel, ConfigDict, Field, field_validator

_NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_\-]{0,63}$")


def _normalize_cidr(value: str, *, version: int) -> str:
    value = value.strip()
    try:
        if "/" in value:
            network = ipaddress.ip_network(value, strict=False)
        else:
            addr = ipaddress.ip_address(value)
            max_prefix = 32 if addr.version == 4 else 128
            network = ipaddress.ip_network(f"{addr}/{max_prefix}", strict=False)
    except ValueError as exc:
        raise ValueError(f"'{value}' is not a valid IP address or CIDR network.") from exc

    if network.version != version:
        raise ValueError(f"Expected an IPv{version} address, got IPv{network.version}.")
    return str(network)


class DeviceBase(BaseModel):
    name: str = Field(min_length=1, max_length=64)
    ip_address: str
    ipv6_address: str | None = None
    vendor: str | None = Field(default=None, max_length=64)
    platform: str | None = Field(default=None, max_length=64)
    description: str | None = Field(default=None, max_length=2000)
    device_group_id: str | None = None
    enabled: bool = True

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        if not _NAME_PATTERN.match(v):
            raise ValueError(
                "Device name must start with a letter or digit and contain only "
                "letters, digits, hyphens, and underscores (max 64 chars) -- it is "
                "used as a raw identifier in the generated tac_plus-ng configuration."
            )
        return v

    @field_validator("ip_address")
    @classmethod
    def validate_ip_address(cls, v: str) -> str:
        return _normalize_cidr(v, version=4)

    @field_validator("ipv6_address")
    @classmethod
    def validate_ipv6_address(cls, v: str | None) -> str | None:
        if v is None or v.strip() == "":
            return None
        return _normalize_cidr(v, version=6)


class DeviceCreate(DeviceBase):
    shared_secret: str = Field(min_length=1, max_length=256)


class DeviceUpdate(DeviceBase):
    # Leave shared_secret unset (None) to keep the existing secret --
    # the GUI never round-trips the real value back to the client.
    shared_secret: str | None = Field(default=None, min_length=1, max_length=256)


class DeviceOut(DeviceBase):
    model_config = ConfigDict(from_attributes=True)

    id: str
    has_secret: bool
    device_group_name: str | None = None
