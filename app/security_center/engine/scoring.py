"""
app.security_center.engine.scoring
=====================================
Unified scoring, applied consistently at both device and interface
granularity -- resolving the scoring-model tension identified during
this migration's capability matrix: cisco-ios-security-auditor's own
scoring is a flat `100 - sum(severity_weight for FAILs)` with no
concept of "applicable checks," so a device with 200 applicable
checks and one with 20 sit on the same subtractive scale, unfairly.
cisco-interface-security-audit's own scoring
(`earned_weight / applicable_weight * 100`) self-normalizes correctly
per interface, so THAT model is what's used here for both -- not a
straight port of either original scoring function.

Device-level findings have no authored per-check `weight` the way
interface rules do (compare: interfaces.py's `add_rule(..., weight=...)`
vs. app.security_center.checks.management's plain `F(...)` calls) --
SEVERITY_WEIGHT (migrated from cisco_audit.py: CRITICAL=12, HIGH=7,
MEDIUM=3, LOW=1, INFO=0) is used as each device-level finding's weight
for this purpose, since severity is the only ordinal signal a
device-level check actually carries.

Credit-per-status, applied uniformly to both granularities:
  PASS   -> full weight
  WARN   -> half weight (interface-engine-only status; see
            app.security_center.engine.finding.Status's own comment
            on why this isn't folded into MANUAL)
  MANUAL -> ZERO weight, but the check's weight still counts toward
            the applicable-weight denominator -- a deliberate,
            conservative choice: an unconfirmed control should not
            inflate the score the way excluding it entirely would (an
            un-auditable control isn't the same as a genuinely
            inapplicable one), and it must not silently earn credit
            for something never actually confirmed secure either.
  FAIL   -> zero weight, counts toward the denominator (obviously).
  NA     -> excluded entirely, from both earned and applicable --
            genuinely not applicable to this device (e.g. no VPN
            configured), so it shouldn't affect the score at all.

The interface engine's own "maturity" score (a 65/35 blend of the base
score and an "advanced categories" sub-score) is deliberately NOT
carried over -- see this project's migration architecture notes: an
unexplained blend constant doesn't meet the "scoring must be
explainable" bar. If a maturity score is wanted later, it needs its
own stated definition, not an inherited magic number.
"""
from __future__ import annotations

from dataclasses import dataclass

from .finding import SEVERITY_WEIGHT, Finding, Status

_CREDIT_FRACTION = {
    Status.PASS: 1.0,
    Status.WARN: 0.5,
    Status.MANUAL: 0.0,
    Status.FAIL: 0.0,
}
# Status.NA is deliberately absent -- handled by outright exclusion
# below, not a 0.0 entry here (a 0.0 entry would still count toward
# the applicable-weight denominator, which NA must NOT do).


@dataclass
class ScoreBreakdown:
    score: float                 # 0-100, this granularity's own normalized score
    fail_count: int
    manual_count: int
    pass_count: int
    warn_count: int
    na_count: int
    applicable_weight: float     # denominator actually used (0 if nothing applicable)


def score_findings(findings: list[Finding]) -> ScoreBreakdown:
    """Scores one flat list of findings -- callers decide what that list
    represents (one device's findings, one interface's, one domain's
    slice of either); this function has no opinion on grouping."""
    earned = 0.0
    applicable = 0.0
    counts = {Status.PASS: 0, Status.WARN: 0, Status.MANUAL: 0, Status.FAIL: 0, Status.NA: 0}

    for f in findings:
        counts[f.status] += 1
        if f.status == Status.NA:
            continue
        weight = SEVERITY_WEIGHT[f.true_severity] if f.true_severity in SEVERITY_WEIGHT else 0.0
        if weight == 0.0:
            # A genuinely INFO-severity check (by its TRUE severity, not
            # F()'s display-only PASS/NA-downgrade -- see
            # Finding.true_severity's own docstring for why those are
            # different fields) contributes nothing to either side of
            # the ratio -- correct, since it was never a real security
            # gap to weigh in the first place.
            continue
        applicable += weight
        earned += weight * _CREDIT_FRACTION[f.status]

    score = round((earned / applicable) * 100.0, 1) if applicable > 0 else 100.0
    return ScoreBreakdown(
        score=score,
        fail_count=counts[Status.FAIL],
        manual_count=counts[Status.MANUAL],
        pass_count=counts[Status.PASS],
        warn_count=counts[Status.WARN],
        na_count=counts[Status.NA],
        applicable_weight=applicable,
    )


def score_by_domain(findings: list[Finding]) -> dict[str, ScoreBreakdown]:
    """Groups findings by their `domain` field and scores each group
    independently -- backs the per-domain score breakdown (spec
    section 6's "Management Plane 82 / Layer 2 Security 61 / ...").
    """
    by_domain: dict[str, list[Finding]] = {}
    for f in findings:
        by_domain.setdefault(f.domain, []).append(f)
    return {domain: score_findings(flist) for domain, flist in by_domain.items()}


def risk_level(score: float) -> str:
    """Bucketing thresholds migrated verbatim from cisco-interface-
    security-audit's own risk_level() -- reused for both device- and
    interface-level scores now that both use the same normalized
    scale, rather than defining a second, potentially-inconsistent
    bucketing scheme for device-level scores."""
    if score >= 95:
        return "Minimal"
    if score >= 85:
        return "Low"
    if score >= 70:
        return "Medium"
    if score >= 50:
        return "High"
    if score >= 25:
        return "Severe"
    return "Critical"
