"""
tests/test_policy_block_authorization.py
===========================================
Regression tests for `config_compiler._policy_block`.

Covers the bug where the initial EXEC (shell login) authorization was
denied: the generated profile set `priv-lvl` for an empty `cmd` but
never issued `permit`, so the empty command fell through every
`cmd =~` rule to the policy's default_action and a deny-by-default
policy refused login outright ("% Authorization failed.").

Run with:  python3 tests/test_policy_block_authorization.py

Written as a plain runnable script rather than pytest because this
project has no test dependency installed and no existing suite -- a
test that cannot be run is worth nothing.

`evaluate_profile` below is a deliberately small interpreter of the
subset of tac_plus-ng script semantics this compiler emits: ordered
`if (cmd =~ /re/) { action }` statements, an `if (cmd == "")` block,
and a trailing unconditional action, where the FIRST permit/deny wins.
It is not a general tac_plus-ng emulator and does not claim to be --
it exists so these tests assert on generated behaviour rather than on
string matching, which would pass just as happily on a config that
denies every login.
"""
from __future__ import annotations

import ast
import re
import sys
import types
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent


def _load_policy_block():
    """Loads `_policy_block` in isolation.

    The compiler module imports SQLAlchemy models at import time, which
    are not needed here and may not be installed, so the single
    function under test is extracted and executed against stub types.
    """
    src = (REPO_ROOT / "app" / "services" / "config_compiler.py").read_text()
    fn = next(
        ast.get_source_segment(src, n)
        for n in ast.parse(src).body
        if isinstance(n, ast.FunctionDef) and n.name == "_policy_block"
    )
    mod = types.ModuleType("_pb")
    sys.modules["_pb"] = mod
    exec(compile("from __future__ import annotations\nclass Policy: pass\n" + fn, "_pb", "exec"), mod.__dict__)
    return mod._policy_block


class FakePolicy:
    def __init__(self, name="only_show", priv=15, default_action="deny"):
        self.name = name
        self.default_priv_lvl = priv
        self.default_action = default_action


class FakeRule:
    def __init__(self, pattern, action):
        self.command_pattern = pattern
        self.action = action


def evaluate_profile(profile_text: str, *, service: str, cmd: str):
    """
    Returns (decision, priv_lvl) for a service/cmd against a generated
    profile. First matching permit/deny wins, mirroring how tac_plus-ng
    evaluates the emitted script top-down.

    Brace depth is tracked so a `permit` INSIDE the `if (cmd == "")`
    block is not mistaken for the trailing unconditional default_action
    -- they are textually identical lines and only their nesting tells
    them apart.
    """
    if f"if (service == {service})" not in profile_text:
        return ("deny", None)

    priv = None
    empty_block_depth = None
    depth = 0

    for raw in profile_text.splitlines():
        stripped = raw.strip()
        if not stripped:
            continue

        # Entering the empty-cmd block: remember the depth it opened at.
        if re.match(r'if \(cmd == ""\) \{$', stripped):
            depth += 1
            empty_block_depth = depth
            continue

        if stripped == "}":
            if empty_block_depth is not None and depth == empty_block_depth:
                empty_block_depth = None
            depth -= 1
            continue

        if stripped.endswith("{"):
            depth += 1
            continue

        inside_empty_block = empty_block_depth is not None

        if stripped.startswith("set priv-lvl ="):
            if inside_empty_block and cmd == "":
                priv = int(stripped.split("=")[1].strip())
            continue

        # A single-line rule: if (cmd =~ /re/) { action }
        m_rule = re.match(r"if \(cmd =~ /(.*)/\) \{ (permit|deny) \}$", stripped)
        if m_rule:
            if inside_empty_block:
                continue
            pattern, action = m_rule.group(1), m_rule.group(2)
            if cmd and re.search(pattern, cmd):
                return (action, priv)
            continue

        if stripped in ("permit", "deny"):
            if inside_empty_block:
                # Only applies to the empty command.
                if cmd == "":
                    return (stripped, priv)
                continue
            return (stripped, priv)

    return ("deny", priv)


def main() -> int:
    _policy_block = _load_policy_block()
    failures: list[str] = []

    def check(desc, actual, expected):
        ok = actual == expected
        print(f"  {'PASS' if ok else 'FAIL'}  {desc:52} -> {actual}")
        if not ok:
            failures.append(f"{desc}: expected {expected}, got {actual}")

    rules = [
        FakeRule(r"^show(\s|$)", "permit"),
        FakeRule(r"^exit(\s|$)", "permit"),
        FakeRule(r"^ssh(\s|$)", "permit"),
    ]
    profile = _policy_block(FakePolicy(), rules)

    print("Generated only_show profile:\n")
    print(profile)

    print("1. Initial login (service=shell, cmd=''):")
    check("initial EXEC authorization", evaluate_profile(profile, service="shell", cmd=""), ("permit", 15))

    print("\n2. Allowed commands:")
    for cmd in [
        "show version", "show ip interface brief", "show running-config",
        "show users", "exit", "ssh -l user 192.168.1.1",
    ]:
        check(cmd, evaluate_profile(profile, service="shell", cmd=cmd)[0], "permit")

    print("\n3. Forbidden commands:")
    for cmd in [
        "configure terminal", "conf t", "interface GigabitEthernet0/1",
        "router ospf 1", "username test privilege 15",
        "ip route 10.0.0.0 255.255.255.0 192.168.1.1", "reload", "write memory",
    ]:
        check(cmd, evaluate_profile(profile, service="shell", cmd=cmd)[0], "deny")

    print("\n4. Prefix-confusion guard (the reason for the \\s|$ anchor):")
    for cmd in ["showevil", "exitnow", "sshd_config"]:
        check(cmd, evaluate_profile(profile, service="shell", cmd=cmd)[0], "deny")

    print("\n5. The regression itself -- permit must be INSIDE the empty-cmd block:")
    m = re.search(r'if \(cmd == ""\) \{(.*?)\n\s*\}', profile, re.S)
    inner = m.group(1) if m else ""
    check("empty-cmd block contains permit", "permit" in inner, True)
    check("empty-cmd block sets priv-lvl", "set priv-lvl" in inner, True)

    print("\n6. A permit-by-default policy still authorizes login:")
    permissive = _policy_block(FakePolicy(name="full_access", priv=15, default_action="permit"), [])
    check("permissive policy initial login", evaluate_profile(permissive, service="shell", cmd=""), ("permit", 15))

    print("\n7. Non-shell service is not silently permitted:")
    check("service=ppp", evaluate_profile(profile, service="ppp", cmd="")[0], "deny")

    print("\n" + "=" * 62)
    if failures:
        print(f"{len(failures)} FAILURE(S):")
        for f in failures:
            print("  - " + f)
        return 1
    print("ALL TESTS PASSED")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
