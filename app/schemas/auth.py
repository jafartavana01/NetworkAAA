from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)


class AdminUserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    username: str
    is_superadmin: bool
