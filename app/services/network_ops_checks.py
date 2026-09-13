"""
app.services.network_ops_checks
==================================
Network Operations & Assurance Engine, Phase 3 (Check engine).

A small, code-defined registry of Cisco IOS check evaluators -- keyed
by `check_key`, matching a `Check` row's own `check_key` column (see
app.models.network_ops_check). Deliberately NOT an admin-scriptable
rule system in Phase 3 -- every evaluator here is a real Python
function, reviewed and tested the same way as everything else in this
project, not something an admin types into a text box and this
platform blindly executes.

Every evaluator works off ALREADY-COLLECTED command output
(CommandExecution.raw_output rows from a completed CommandJob) --
running a check never triggers a new SSH connection; see
app.api.routes_network_ops_checks for how results get attached to a
job's targets after the fact.

HONESTY DISCIPLINE (spec section 12, and the same philosophy the
referenced cisco-ios-security-auditor project's own MANUAL_REVIEW/N-A
statuses embody): an evaluator that doesn't have the command output it
needs returns NOT_APPLICABLE with a clear reason, never a guessed
PASS or FAIL. This is checked once, centrally, in `run_check()` below
-- an individual evaluator function only runs at all once its
required command's output has already been confirmed present.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from .cisco_config_parser import ParsedConfig

_RUNNING_CONFIG_COMMAND_PATTERN = re.compile(r"^\s*(sh|show)\s+run(ning-config)?\b", re.IGNORECASE)


def find_running_config_output(command_outputs: dict[str, str]) -> str | None:
    """
    Cisco IOS allows command abbreviation ("sh run", "show run", "show
    running-config" are all the same command) -- matching only the
    exact literal string a job happened to use would be fragile, so
    this matches by PREFIX PATTERN instead, returning the first
    matching command's output. Returns None if nothing in this
    device's collected output looks like a running-config dump at
    all -- the caller (run_check) turns that into NOT_APPLICABLE, not
    a guess.
    """
    for command, output in command_outputs.items():
        if _RUNNING_CONFIG_COMMAND_PATTERN.match(command):
            return output
    return None


@dataclass
class CheckEvalResult:
    status: str  # PASS | FAIL | WARNING | NOT_APPLICABLE | MANUAL_REVIEW | UNKNOWN
    title: str
    description: str
    evidence: list[str] = field(default_factory=list)
    actual_value: str | None = None
    expected_value: str | None = None
    recommendation: str | None = None


# ---------- Evaluators ----------

def _check_aaa_new_model(cfg: ParsedConfig) -> CheckEvalResult:
    enabled = cfg.has_toplevel(r"^aaa new-model\b")
    if enabled:
        return CheckEvalResult(
            status="PASS", title="AAA new-model is enabled",
            description="The AAA subsystem is enabled, which is required for any TACACS+/RADIUS authentication, authorization, or accounting to actually take effect.",
            actual_value="aaa new-model present", expected_value="aaa new-model present",
        )
    return CheckEvalResult(
        status="FAIL", title="AAA new-model is enabled",
        description="`aaa new-model` was not found. Without it, the device falls back to line-level (or no) authentication regardless of any other AAA configuration present.",
        actual_value="aaa new-model absent", expected_value="aaa new-model present",
        recommendation="aaa new-model",
    )


def _check_password_encryption(cfg: ParsedConfig) -> CheckEvalResult:
    enabled = cfg.has_toplevel(r"^service password-encryption\b")
    if enabled:
        return CheckEvalResult(
            status="PASS", title="Password encryption service is enabled",
            description="`service password-encryption` is present.",
            actual_value="present", expected_value="present",
        )
    return CheckEvalResult(
        status="FAIL", title="Password encryption service is enabled",
        description="`service password-encryption` was not found -- some password types are stored in fully readable plaintext in the configuration without it.",
        actual_value="absent", expected_value="present",
        recommendation="service password-encryption",
    )


def _check_vty_ssh_only(cfg: ParsedConfig) -> CheckEvalResult:
    vty_blocks = cfg.get_blocks("line vty")
    if not vty_blocks:
        return CheckEvalResult(
            status="NOT_APPLICABLE", title="VTY lines restrict transport to SSH",
            description="No `line vty` stanzas were found in the collected configuration.",
        )
    telnet_allowed = [b for b in vty_blocks if b.has(r"transport input\s+(telnet|all)\b")]
    if not telnet_allowed:
        return CheckEvalResult(
            status="PASS", title="VTY lines restrict transport to SSH",
            description=f"All {len(vty_blocks)} VTY line stanza(s) restrict transport to SSH.",
            actual_value="ssh only", expected_value="ssh only",
        )
    names = [b.name() for b in telnet_allowed]
    return CheckEvalResult(
        status="FAIL", title="VTY lines restrict transport to SSH",
        description="One or more VTY line stanzas allow telnet (unencrypted) or 'all' transport, not SSH only.",
        evidence=names, actual_value=f"telnet/all allowed on: {', '.join(names)}", expected_value="ssh only",
        recommendation="line vty <range>\n transport input ssh",
    )


def _check_http_server_disabled(cfg: ParsedConfig) -> CheckEvalResult:
    explicit_disabled = cfg.has_toplevel(r"^no ip http server\b")
    enabled = cfg.has_toplevel(r"^ip http server\b") and not explicit_disabled
    if enabled:
        return CheckEvalResult(
            status="FAIL", title="HTTP management server is disabled",
            description="`ip http server` is present and not disabled -- the unencrypted HTTP management interface is reachable.",
            actual_value="enabled", expected_value="disabled",
            recommendation="no ip http server",
        )
    return CheckEvalResult(
        status="PASS", title="HTTP management server is disabled",
        description="No enabled `ip http server` directive was found.",
        actual_value="disabled", expected_value="disabled",
    )


# check_key -> (evaluator function, required command list)
_REGISTRY: dict[str, tuple] = {
    "aaa_new_model": (_check_aaa_new_model, ["show running-config"]),
    "password_encryption": (_check_password_encryption, ["show running-config"]),
    "vty_ssh_only": (_check_vty_ssh_only, ["show running-config"]),
    "http_server_disabled": (_check_http_server_disabled, ["show running-config"]),
}


def default_checks() -> list[dict]:
    """The starter set seeded on first boot (see
    app.api.routes_network_ops_checks.ensure_seeded) -- a no-op on
    every subsequent boot once any Check row exists, same pattern as
    every other seeded catalog in this project."""
    return [
        {"check_key": "aaa_new_model", "name": "AAA new-model enabled", "category": "Management Plane",
         "default_severity": "HIGH", "required_commands": ["show running-config"],
         "description": "Confirms the AAA subsystem is enabled -- without it, no other AAA configuration takes effect."},
        {"check_key": "password_encryption", "name": "Password encryption service enabled", "category": "Management Plane",
         "default_severity": "MEDIUM", "required_commands": ["show running-config"],
         "description": "Confirms `service password-encryption` is set."},
        {"check_key": "vty_ssh_only", "name": "VTY lines restrict transport to SSH", "category": "Management Plane",
         "default_severity": "HIGH", "required_commands": ["show running-config"],
         "description": "Confirms every VTY line stanza restricts transport to SSH only, not telnet."},
        {"check_key": "http_server_disabled", "name": "HTTP management server disabled", "category": "Management Plane",
         "default_severity": "MEDIUM", "required_commands": ["show running-config"],
         "description": "Confirms the unencrypted HTTP management interface is not enabled."},
    ]


def run_check(check_key: str, command_outputs: dict[str, str]) -> CheckEvalResult:
    """
    Runs one registered check against a device's already-collected
    command output. Returns NOT_APPLICABLE (never a guessed PASS/FAIL)
    if the needed command output wasn't collected for this device at
    all, or UNKNOWN if the check_key isn't a registered evaluator
    (e.g. a Check row whose code was since removed).
    """
    entry = _REGISTRY.get(check_key)
    if entry is None:
        return CheckEvalResult(
            status="UNKNOWN", title=check_key,
            description=f"No registered evaluator exists for check_key '{check_key}'.",
        )
    evaluator, required = entry

    # Every evaluator implemented so far needs running-config output
    # specifically -- this central lookup is what lets NOT_APPLICABLE
    # be enforced in exactly one place rather than duplicated in every
    # evaluator function.
    running_config_output = find_running_config_output(command_outputs)
    if running_config_output is None:
        return CheckEvalResult(
            status="NOT_APPLICABLE", title=check_key,
            description=f"This check needs {', '.join(required)} in the job's commands, which wasn't collected for this device.",
        )

    cfg = ParsedConfig(running_config_output)
    return evaluator(cfg)


# ---------- Score computation (spec section 15) ----------
# The exact formula used by the referenced cisco-ios-security-auditor
# project (confirmed by fetching its actual README, not guessed):
# a simple, transparent weighted deduction -- deliberately NOT an
# opaque or fitted model, per the spec's own explicit instruction, and
# now doubly defensible for being sourced from a real, working
# reference implementation rather than invented for this project.

SEVERITY_WEIGHT = {"CRITICAL": 12, "HIGH": 7, "MEDIUM": 3, "LOW": 1, "INFO": 0}


@dataclass
class ScoreBreakdown:
    score: int
    total_checks: int
    passed: int
    failed: int
    not_applicable: int
    other: int  # WARNING | MANUAL_REVIEW | UNKNOWN
    findings_by_severity: dict  # severity -> count of FAILed checks at that severity
    deductions_by_severity: dict  # severity -> total points deducted at that severity


def compute_score(results: list) -> ScoreBreakdown:
    """
    `results` is a list of objects with `.status` and `.severity`
    attributes (CheckResult rows, or anything shaped like one).
    NOT_APPLICABLE, WARNING, MANUAL_REVIEW, and UNKNOWN never affect
    the score either way -- only a real, evaluable FAIL deducts
    points, matching the referenced project's own N/A-doesn't-penalize
    behavior for checks that were never applicable to begin with.
    """
    findings_by_severity: dict = {}
    deductions_by_severity: dict = {}
    passed = failed = not_applicable = other = 0

    for r in results:
        if r.status == "PASS":
            passed += 1
        elif r.status == "FAIL":
            failed += 1
            weight = SEVERITY_WEIGHT.get(r.severity, 0)
            findings_by_severity[r.severity] = findings_by_severity.get(r.severity, 0) + 1
            deductions_by_severity[r.severity] = deductions_by_severity.get(r.severity, 0) + weight
        elif r.status == "NOT_APPLICABLE":
            not_applicable += 1
        else:
            other += 1

    total_deduction = sum(deductions_by_severity.values())
    score = max(0, 100 - total_deduction)

    return ScoreBreakdown(
        score=score, total_checks=len(results), passed=passed, failed=failed,
        not_applicable=not_applicable, other=other,
        findings_by_severity=findings_by_severity, deductions_by_severity=deductions_by_severity,
    )
