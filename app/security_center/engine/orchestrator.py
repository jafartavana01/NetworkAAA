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

import logging
from dataclasses import dataclass, field

from ..checks.interfaces import assess_features, to_unified_findings
from ..checks.policy import DEFAULT_POLICY
from ..checks.registry import DOMAIN_REGISTRY, run_all_device_checks
from ..compliance.loader import control_status, load_compliance_mappings, map_findings_to_compliance
from ..parser.cisco_config import CiscoConfig
from ..parser.interface_config import parse_interface_config
from .context import Context
from .correlation import run_correlation_engine
from .finding import Finding
from .scoring import ScoreBreakdown, risk_level, score_by_domain, score_findings

logger = logging.getLogger(__name__)

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


def run_interface_checks(raw_config_text: str) -> list:
    """
    Runs the interface-level engine over every interface in the config
    and returns its findings already converted to unified Finding
    objects.

    Wrapped in a broad try/except on purpose: this is an addition to an
    already-working device-level audit, and a config this parser
    chokes on (an unusual platform, a truncated capture) must degrade
    to "no interface findings" rather than failing the whole audit and
    losing the device-level results the user actually asked for. The
    failure is logged, not swallowed silently.
    """
    try:
        device = parse_interface_config(raw_config_text)
    except Exception:
        logger.exception("Interface parsing failed; continuing with device-level findings only.")
        return []

    findings: list = []
    global_features = device.get("global", {})
    for iface in device.get("interfaces", []):
        name = iface.get("name")
        if not name:
            continue
        try:
            assessment = assess_features(iface, global_features)
            findings.extend(to_unified_findings(name, assessment))
        except Exception:
            # One bad interface must not drop every other interface's
            # results -- same reasoning as the per-device isolation in
            # app.services.scheduled_audit.
            logger.exception("Interface assessment failed for %s; skipping that interface.", name)
    return findings


def run_device_audit(raw_config_text: str, policy: dict | None = None) -> DeviceAuditResult:
    """
    Runs the complete audit pipeline against one running-config text:
    all 9 device-level domains, the interface-level engine over every
    interface in that same config, correlation, compliance, and
    overall/per-domain scoring.

    Interface-level results are part of THIS run by explicit product
    decision (previously deferred here pending exactly that decision):
    auditing a device means auditing its interfaces too, so both
    engines run over the same raw text and their findings are merged
    into one list. The two engines deliberately keep their own parsers
    (see app.security_center.parser's own module docstring on why that
    is a design choice, not an oversight) and their findings arrive in
    two shapes-of-origin -- device checks via F(), interface checks via
    to_unified_findings() -- but both produce the same unified Finding
    type, so downstream scoring, correlation, compliance mapping and
    persistence need no special-casing.

    Interface findings carry their own `Interface Security / *` domain
    prefix and a non-null `interface_name`, which is what lets the GUI
    separate per-interface results from device-wide ones without a
    second query or a parallel storage path.

    A malformed or interface-less config must not fail the whole audit:
    the interface pass is wrapped so a device-level audit still returns
    its full result if interface parsing raises.
    """
    policy = policy or DEFAULT_POLICY
    cfg = CiscoConfig(raw_config_text)
    ctx = Context()

    device_findings = run_all_device_checks(cfg, policy, ctx)
    correlation_findings = run_correlation_engine(cfg, policy, ctx)
    interface_findings = run_interface_checks(raw_config_text)

    # Correlation findings are scored alongside the individual findings
    # that fed them -- they're real, additional findings (their own
    # CORR-* check_id, own severity), not just annotations on existing
    # ones, so they belong in the denominator too. Interface findings
    # likewise: they are real pass/fail checks against this device.
    all_findings = device_findings + interface_findings + correlation_findings

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
        findings=device_findings + interface_findings,
        correlation_findings=correlation_findings,
        overall=overall,
        overall_risk_level=risk_level(overall.score),
        domain_scores=domain_scores,
        compliance=compliance,
        compliance_status=compliance_status,
    )
