"""
app.security_center.engine.orchestrator
==========================================
Single entry point tying the whole migrated engine together: parse ->
run all 9 device-level domains -> run the correlation engine -> run
compliance mapping -> score everything (overall, per-domain, and
device-vs-interface). This is new code (no equivalent in either
legacy project, which each only ever drove their own single-purpose
CLI/server) -- it's the actual bridge this migration was for, and the
only thing app.api routes for Security Center should ever call
directly rather than reaching into individual check modules
themselves.

Interface-level auditing is intentionally NOT invoked from here yet --
see run_device_audit()'s own docstring for why that's a deliberate,
separate decision rather than an oversight.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..checks.policy import DEFAULT_POLICY
from ..checks.registry import DOMAIN_REGISTRY, run_all_device_checks
from ..compliance.loader import control_status, load_compliance_mappings, map_findings_to_compliance
from ..parser.cisco_config import CiscoConfig
from .context import Context
from .correlation import run_correlation_engine
from .finding import Finding
from .scoring import ScoreBreakdown, risk_level, score_by_domain, score_findings

_COMPLIANCE_FRAMEWORKS_CACHE = None  # loaded once per process; the 4 JSON files never change at runtime


def _frameworks() -> list[dict]:
    global _COMPLIANCE_FRAMEWORKS_CACHE
    if _COMPLIANCE_FRAMEWORKS_CACHE is None:
        _COMPLIANCE_FRAMEWORKS_CACHE = load_compliance_mappings()
    return _COMPLIANCE_FRAMEWORKS_CACHE


@dataclass
class DeviceAuditResult:
    hostname: str
    findings: list[Finding]
    correlation_findings: list[Finding]
    overall: ScoreBreakdown
    overall_risk_level: str
    domain_scores: dict[str, ScoreBreakdown]
    compliance: dict[str, dict[str, list[dict]]] = field(default_factory=dict)  # framework_key -> control -> entries
    compliance_status: dict[str, dict[str, str]] = field(default_factory=dict)  # framework_key -> control -> status


def run_device_audit(raw_config_text: str, policy: dict | None = None) -> DeviceAuditResult:
    """
    Runs the complete device-level pipeline against one running-config
    text: all 9 domains, correlation, compliance, and overall/per-
    domain scoring.

    Deliberately does NOT also run the interface-level engine here --
    the two engines use different parsers over the same raw text (see
    app.security_center.parser's own module docstring on why that's a
    deliberate design choice, not an oversight) and produce Finding
    lists in two genuinely different shapes-of-origin (device checks
    via F(), interface checks via to_unified_findings()). Combining
    both into one call now, before either has a real caller (the API
    layer isn't built yet), would be premature -- a caller that wants
    both today can run app.security_center.checks.interfaces'
    to_unified_findings() per-interface alongside this, and combine the
    two finding lists itself; whether device- and interface-level
    audits should always run together, or be independently triggerable
    (spec section 9's "audit a single device" vs likely wanting
    interface results as part of that same run) is a real product
    decision for the API layer design, not something to silently
    decide here.
    """
    policy = policy or DEFAULT_POLICY
    cfg = CiscoConfig(raw_config_text)
    ctx = Context()

    device_findings = run_all_device_checks(cfg, policy, ctx)
    correlation_findings = run_correlation_engine(cfg, policy, ctx)

    # Correlation findings are scored alongside the individual findings
    # that fed them -- they're real, additional findings (their own
    # CORR-* check_id, own severity), not just annotations on existing
    # ones, so they belong in the denominator too.
    all_findings = device_findings + correlation_findings

    overall = score_findings(all_findings)
    domain_scores = score_by_domain(all_findings)

    compliance: dict[str, dict[str, list[dict]]] = {}
    compliance_status: dict[str, dict[str, str]] = {}
    for framework in _frameworks():
        key = framework["_framework_key"]
        by_control = map_findings_to_compliance(all_findings, framework)
        compliance[key] = by_control
        compliance_status[key] = {control: control_status(entries) for control, entries in by_control.items()}

    return DeviceAuditResult(
        hostname=cfg.get_hostname(),
        findings=device_findings,
        correlation_findings=correlation_findings,
        overall=overall,
        overall_risk_level=risk_level(overall.score),
        domain_scores=domain_scores,
        compliance=compliance,
        compliance_status=compliance_status,
    )
