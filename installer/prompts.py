"""
installer.prompts
===================
Interactive administrator prompts (spec sections 8-10, 38): build
profile selection, optional feature confirmation, and initial admin
account creation. Kept separate from the orchestration logic in
setup.py so the prompting flow can be unit-tested / driven
non-interactively later if needed.
"""
from __future__ import annotations

import getpass
import re

from . import utils
from .upstream_build import BuildProfile, ConfigureOption


def choose_build_profile(profiles: list[BuildProfile]) -> BuildProfile:
    utils.section("tac_plus-ng Installation Profile")
    for idx, profile in enumerate(profiles, start=1):
        print(f"  [{idx}] {profile.name}")
        print(f"      {profile.description}")
    default_idx = 1
    while True:
        choice = utils.ask("Choose profile", default=str(default_idx))
        if choice.isdigit() and 1 <= int(choice) <= len(profiles):
            return profiles[int(choice) - 1]
        utils.warn(f"Enter a number between 1 and {len(profiles)}.")


def choose_custom_flags(options: list[ConfigureOption]) -> list[str]:
    if not options:
        utils.warn(
            "Could not parse any flags from './configure --help' output for this "
            "checkout. Falling back to the default (Recommended) build."
        )
        return ["tac_plus-ng"]

    utils.section("Custom Build -- discovered ./configure options")
    utils.info("These are parsed live from this checkout's `./configure --help`, not a fixed list.")
    for idx, opt in enumerate(options, start=1):
        print(f"  [{idx:>2}] {opt.flag:<28} {opt.description}")

    utils.info("Enter comma-separated numbers to enable those flags, or leave blank for none extra.")
    raw = utils.ask("Flags to enable", default="")
    selected: list[str] = []
    if raw.strip():
        for token in raw.split(","):
            token = token.strip()
            if token.isdigit() and 1 <= int(token) <= len(options):
                selected.append(options[int(token) - 1].flag)
    selected.append("tac_plus-ng")
    return selected


def confirm_installation_summary(*, profile: BuildProfile, configure_args: list[str]) -> bool:
    utils.section("Continue Installation?")
    utils.info(f"Build profile      : {profile.name}")
    utils.info(f"Configure arguments: {' '.join(configure_args)}")
    return utils.confirm("Continue installation?", default_yes=True)


_PASSWORD_MIN_LENGTH = 8


def _password_strong_enough(password: str) -> bool:
    if len(password) < _PASSWORD_MIN_LENGTH:
        return False
    classes = [
        re.search(r"[a-z]", password),
        re.search(r"[A-Z]", password),
        re.search(r"[0-9]", password),
        re.search(r"[^a-zA-Z0-9]", password),
    ]
    return sum(bool(c) for c in classes) >= 3


def create_initial_admin() -> tuple[str, str]:
    """
    Prompts for the first platform administrator account. The password
    is never echoed, never logged, and never written to disk in plain
    text -- only its bcrypt hash is stored, by app.security.hash_password
    at the call site in setup.py.
    """
    utils.section("Initial Administrator Account")
    utils.info(
        f"Choose a strong password ({_PASSWORD_MIN_LENGTH}+ characters, mixing case, "
        "digits, and symbols). It will not be displayed or logged."
    )

    username = utils.ask("Administrator username", default="admin")

    while True:
        password = getpass.getpass("  Administrator password: ")
        if not _password_strong_enough(password):
            utils.warn(
                f"Password must be at least {_PASSWORD_MIN_LENGTH} characters and include "
                "at least 3 of: lowercase, uppercase, digits, symbols."
            )
            continue
        confirm_pw = getpass.getpass("  Confirm password: ")
        if password != confirm_pw:
            utils.warn("Passwords did not match -- try again.")
            continue
        return username, password
