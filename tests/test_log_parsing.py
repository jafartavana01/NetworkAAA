"""
tests/test_log_parsing.py
============================
Regression tests for the three tac_plus-ng log formats.

Every case here comes from a line captured on a REAL deployment. Each
one also corresponds to a bug that actually shipped:

  * The access-log parser required six fields where the format has five
    (four identity fields plus a free-text message), so every
    authentication record failed to parse and the page showed an empty
    table rather than an error.
  * The authorization-log parser assumed a fixed eight fields, so
    SESSION records -- which have seven and no command -- never parsed.
  * `_try_parse_timestamp` was given a captured prefix while the
    pattern it used demanded trailing whitespace that the capture
    excluded, so `parsed_at` was silently None and the Time column
    rendered an em dash.

The last one is the reason `parsed_at` is asserted explicitly for every
format below: it is the field most easily overlooked, because an empty
timestamp looks like "no data" rather than a failure.

Run:  python3 tests/test_log_parsing.py
"""
from __future__ import annotations

import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_module():
    """Loads accounting_log with its package imports stubbed, so the
    parsers can be tested without SQLAlchemy or a real config."""
    pkg = types.ModuleType("app"); pkg.__path__ = []
    svc = types.ModuleType("app.services"); svc.__path__ = []
    cfg = types.ModuleType("app.config"); cfg.LOG_DIR = Path("/tmp")
    cc = types.ModuleType("app.services.config_compiler")
    cc.ACCOUNTING_FIELD_SEPARATOR = "::"
    sys.modules.update({
        "app": pkg, "app.services": svc,
        "app.config": cfg, "app.services.config_compiler": cc,
    })
    src = (REPO_ROOT / "app" / "services" / "accounting_log.py").read_text()
    src = src.replace("from ..config import LOG_DIR", "from app.config import LOG_DIR")
    src = src.replace(
        "from .config_compiler import ACCOUNTING_FIELD_SEPARATOR",
        "from app.services.config_compiler import ACCOUNTING_FIELD_SEPARATOR",
    )
    mod = types.ModuleType("accounting_log")
    sys.modules["accounting_log"] = mod
    exec(compile(src, "accounting_log", "exec"), mod.__dict__)
    return mod


# Real lines, tabs restored.
ACCESS_LINES = [
    "2026-09-12 21:57:31 +0000 192.168.44.10\tu1\ttty0\tasync\tshell login succeeded",
    "2026-09-13 05:12:20 +0000 192.168.44.10\tjafar\ttty0\tasync\tshell login failed",
    "2026-09-13 05:12:53 +0000 192.168.44.10\tsakjdkasd\ttty0\tasync\tshell login failed",
]

AUTHORIZATION_LINES = [
    # Seven fields: a session authorization, no command.
    "2026-09-12 21:57:32 +0000 192.168.44.10\tu1\ttty0\tasync\tnnnn\tpermit\tshell",
    "2026-09-12 21:57:35 +0000 192.168.44.10\tu1\ttty0\tasync\tnnnn\tpermit\tshell\tconfigure terminal <cr>",
    "2026-09-12 21:57:40 +0000 192.168.44.10\tu1\ttty0\tasync\tnnnn\tdeny\tshell\tinterface FastEthernet 0/1 <cr>",
    # Cleartext credential -- must never reach a response unmasked.
    "2026-09-12 21:58:33 +0000 192.168.44.10\tu1\ttty0\tasync\tnnnn\tpermit\tshell\tusername 11 password 22 <cr>",
]

ACCOUNTING_LINES = [
    "2026-09-12 21:57:32 +0000 192.168.44.10::u1::tty0::async::start::::shell::",
    "2026-09-12 21:58:33 +0000 192.168.44.10::u1::tty0::async::stop::::shell::username 11 password *****",
]


def main() -> int:
    m = _load_module()
    failures: list[str] = []

    def check(desc, actual, expected):
        ok = actual == expected
        print(f"  {'PASS' if ok else 'FAIL'}  {desc:56} -> {actual!r}")
        if not ok:
            failures.append(f"{desc}: expected {expected!r}, got {actual!r}")

    print("1. Access log (authentication):")
    for line in ACCESS_LINES:
        r = m._access_parse_line(line)
        check(f"parses: {r.user or '?'}", r.parsed, True)
        # The Time column bug: parsed_at must never be None here.
        check(f"has a timestamp: {r.user or '?'}", r.parsed_at is not None, True)
    outcomes = [m._access_parse_line(l).outcome for l in ACCESS_LINES]
    check("outcomes in order", outcomes, ["success", "failure", "failure"])

    print("\n2. Access log outcome is conservative:")
    for message, expected in [
        ("shell login succeeded", "success"),
        ("shell login failed", "failure"),
        ("login denied", "failure"),
        ("", "unknown"),
        ("a message from a future release", "unknown"),
    ]:
        check(f"{message!r}", m.AccessRecord(raw_line="x", parsed=True, message=message).outcome, expected)

    print("\n3. Authorization log (7 and 8 field forms):")
    for line in AUTHORIZATION_LINES:
        r = m._auth_parse_line(line)
        check(f"parses: {(r.cmd or '(session)')[:28]}", r.parsed, True)
        check(f"has a timestamp: {(r.cmd or '(session)')[:20]}", r.parsed_at is not None, True)
    session = m._auth_parse_line(AUTHORIZATION_LINES[0])
    check("session record has no command", session.cmd, "")
    check("session record recognised as a login", m.is_login_record(session), True)
    check("deny maps to failure", m.login_outcome(m._auth_parse_line(AUTHORIZATION_LINES[2])), "failure")

    print("\n4. Credential masking:")
    credential_line = m._auth_parse_line(AUTHORIZATION_LINES[3])
    check("raw log really does contain the secret", "password 22" in credential_line.cmd, True)
    check("masked output hides it", "22" in m.mask_credentials(credential_line.cmd).split("password")[1], False)
    for keep in ["service password-encryption", "show version", "aaa authentication login www group tacacs+"]:
        check(f"not mangled: {keep[:34]}", m.mask_credentials(keep), keep)

    print("\n5. Accounting log still parses (no regression):")
    for line in ACCOUNTING_LINES:
        r = m._parse_line(line)
        check(f"parses: {(r.cmd or '(start)')[:28]}", r.parsed, True)
        check(f"has a timestamp: {(r.cmd or '(start)')[:20]}", r.parsed_at is not None, True)
    check("accounting result field is empty (why we read authorization)",
          m._parse_line(ACCOUNTING_LINES[0]).result, "")

    print("\n6. Timestamp helper accepts both a bare prefix and a full line:")
    check("bare prefix", m._try_parse_timestamp("2026-09-13 05:12:20 +0000") is not None, True)
    check("full line", m._try_parse_timestamp("2026-09-13 05:12:20 +0000 rest") is not None, True)
    check("not a timestamp", m._try_parse_timestamp("garbage"), None)

    print("\n" + "=" * 66)
    if failures:
        print(f"{len(failures)} FAILURE(S):")
        for f in failures:
            print("  - " + f)
        return 1
    print("ALL LOG PARSING TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
