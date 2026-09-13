"""
app.config
===========
Central application settings. Reads database credentials and generated
secrets from the root-only files the installer wrote under
/etc/aaa-platform -- nothing sensitive lives in source control or in
environment variables that might leak into process listings.
"""
from __future__ import annotations

import json
import secrets
from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ETC_DIR = Path("/etc/aaa-platform")
CONFIG_DIR = ETC_DIR / "config"
DB_CREDENTIALS_PATH = ETC_DIR / "db_credentials.json"
BUILD_INFO_PATH = ETC_DIR / "build_info.json"
SESSION_SECRET_PATH = ETC_DIR / "session_secret.key"
SECRET_ENCRYPTION_KEY_PATH = ETC_DIR / "secret_encryption.key"
LOG_DIR = Path("/var/log/aaa-platform")
GENERATED_DIR = Path("/opt/aaa-platform/generated")
BACKUPS_DIR = Path("/opt/aaa-platform/backups")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="AAA_PLATFORM_")

    app_name: str = "AAA Management Platform"
    database_url: str
    session_secret: str
    secret_encryption_key: str
    debug: bool = False


def _load_database_url() -> str:
    if not DB_CREDENTIALS_PATH.exists():
        raise RuntimeError(
            f"{DB_CREDENTIALS_PATH} not found -- has the installer been run?"
        )
    creds = json.loads(DB_CREDENTIALS_PATH.read_text(encoding="utf-8"))
    return (
        f"postgresql+psycopg://{creds['username']}:{creds['password']}"
        f"@{creds['host']}:{creds['port']}/{creds['database']}"
    )


def _load_or_create_session_secret() -> str:
    if SESSION_SECRET_PATH.exists():
        return SESSION_SECRET_PATH.read_text(encoding="utf-8").strip()
    secret = secrets.token_urlsafe(64)
    SESSION_SECRET_PATH.parent.mkdir(parents=True, exist_ok=True)
    SESSION_SECRET_PATH.write_text(secret, encoding="utf-8")
    SESSION_SECRET_PATH.chmod(0o600)
    return secret


def _load_or_create_secret_encryption_key() -> str:
    """
    Fernet key protecting device shared secrets at rest (spec section
    36). Distinct from the session secret and from admin password
    hashing: shared secrets must be *decryptable* (tac_plus-ng needs
    the real value to put in its config), unlike admin passwords,
    which only ever need to be verified (bcrypt, one-way). Generated
    once on first use and never logged or displayed.
    """
    if SECRET_ENCRYPTION_KEY_PATH.exists():
        return SECRET_ENCRYPTION_KEY_PATH.read_text(encoding="utf-8").strip()
    from cryptography.fernet import Fernet
    key = Fernet.generate_key().decode("utf-8")
    SECRET_ENCRYPTION_KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    SECRET_ENCRYPTION_KEY_PATH.write_text(key, encoding="utf-8")
    SECRET_ENCRYPTION_KEY_PATH.chmod(0o600)
    return key


@lru_cache
def get_settings() -> Settings:
    return Settings(
        database_url=_load_database_url(),
        session_secret=_load_or_create_session_secret(),
        secret_encryption_key=_load_or_create_secret_encryption_key(),
    )


def load_build_info() -> dict:
    if not BUILD_INFO_PATH.exists():
        return {}
    return json.loads(BUILD_INFO_PATH.read_text(encoding="utf-8"))
