"""
installer.utils
================
Shared low-level helpers for the installer: safe subprocess execution,
colored console output, and a persistent install log.

Security note (spec section 35/37): every external command is invoked as
an argv list -- never through shell=True, and never built by string-
concatenating untrusted input. Anything that must vary (paths, package
names, feature flags) is validated against an allow-list or a known type
before being placed in argv.
"""
from __future__ import annotations

import subprocess
import sys
import shlex
import datetime
from pathlib import Path
from dataclasses import dataclass, field


class InstallError(RuntimeError):
    """Raised for any unrecoverable installer failure."""


LOG_PATH = Path("/tmp/aaa-platform-install.log")


def _log(line: str) -> None:
    timestamp = datetime.datetime.now().isoformat(timespec="seconds")
    try:
        with LOG_PATH.open("a", encoding="utf-8") as fh:
            fh.write(f"[{timestamp}] {line}\n")
    except OSError:
        # Logging must never crash the installer.
        pass


class Color:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    CYAN = "\033[36m"


def _supports_color() -> bool:
    return sys.stdout.isatty()


def _c(text: str, color: str) -> str:
    if not _supports_color():
        return text
    return f"{color}{text}{Color.RESET}"


def header(title: str) -> None:
    line = "=" * 60
    print(f"\n{_c(line, Color.CYAN)}")
    print(_c(f" {title}", Color.BOLD + Color.CYAN))
    print(f"{_c(line, Color.CYAN)}")
    _log(f"==== {title} ====")


def section(title: str) -> None:
    print(f"\n{_c('-' * 44, Color.DIM)}")
    print(_c(f" {title}", Color.BOLD))
    print(f"{_c('-' * 44, Color.DIM)}")
    _log(f"---- {title} ----")


def info(msg: str) -> None:
    print(f"  {msg}")
    _log(f"INFO: {msg}")


def ok(msg: str) -> None:
    print(f"  {_c('[OK]', Color.GREEN)} {msg}")
    _log(f"OK: {msg}")


def warn(msg: str) -> None:
    print(f"  {_c('[WARN]', Color.YELLOW)} {msg}")
    _log(f"WARN: {msg}")


def error(msg: str) -> None:
    print(f"  {_c('[ERROR]', Color.RED)} {msg}", file=sys.stderr)
    _log(f"ERROR: {msg}")


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default is not None else ""
    try:
        raw = input(f"  {prompt}{suffix}: ").strip()
    except EOFError:
        raw = ""
    return raw if raw else (default or "")


def confirm(prompt: str, default_yes: bool = True) -> bool:
    hint = "Y/n" if default_yes else "y/N"
    try:
        raw = input(f"  {prompt} [{hint}]: ").strip().lower()
    except EOFError:
        raw = ""
    if not raw:
        return default_yes
    return raw in ("y", "yes")


@dataclass
class CommandResult:
    argv: list[str]
    returncode: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.returncode == 0


def run(
    argv: list[str],
    *,
    cwd: str | Path | None = None,
    env: dict | None = None,
    check: bool = True,
    capture: bool = True,
    input_text: str | None = None,
    timeout: int | None = None,
) -> CommandResult:
    """
    Run a command safely. `argv` must always be a list -- never a shell
    string. Raises InstallError on failure when check=True.
    """
    if isinstance(argv, str):  # defensive: never allow shell strings
        raise InstallError(
            f"Refusing to run a string command (shell injection risk): {argv!r}"
        )

    printable = " ".join(shlex.quote(a) for a in argv)
    _log(f"RUN: {printable} (cwd={cwd})")

    try:
        proc = subprocess.run(
            argv,
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=capture,
            text=True,
            input=input_text,
            timeout=timeout,
        )
    except FileNotFoundError as exc:
        raise InstallError(f"Command not found: {argv[0]} ({exc})") from exc
    except subprocess.TimeoutExpired as exc:
        raise InstallError(f"Command timed out after {timeout}s: {printable}") from exc

    result = CommandResult(
        argv=argv,
        returncode=proc.returncode,
        stdout=proc.stdout or "",
        stderr=proc.stderr or "",
    )
    _log(f"  -> exit={proc.returncode}")
    if result.stdout.strip():
        _log(f"  stdout: {result.stdout.strip()[:2000]}")
    if result.stderr.strip():
        _log(f"  stderr: {result.stderr.strip()[:2000]}")

    if check and not result.ok:
        raise InstallError(
            f"Command failed ({result.returncode}): {printable}\n{result.stderr.strip()}"
        )
    return result


def which(binary: str) -> str | None:
    result = run(["/usr/bin/env", "which", binary], check=False)
    path = result.stdout.strip()
    return path or None
