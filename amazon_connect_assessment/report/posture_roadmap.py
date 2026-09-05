"""
Posture Improvement Roadmap generator (Phase 7 / Task 15 / Requirement 37).

Computes per-pillar posture scores, maturity levels, and a prioritized
list of prescriptive improvement actions from the aggregate findings.
This module is independent of the main report generator so it can evolve
separately and be tested in isolation.
"""

from dataclasses import dataclass, field
from typing import Dict, List

from ..models import CheckStatus, Finding, Pillar, Severity


@dataclass
class PostureScore:
    """Posture assessment for a single pillar."""

    pillar: Pillar
    total_checks: int
    passed_checks: int
    pass_rate: float  # 0.0 - 100.0
    maturity_level: str  # "Basic" | "Intermediate" | "Advanced"
    improvement_actions: List[Dict] = field(default_factory=list)


# Maturity thresholds.
_BASIC_THRESHOLD = 50.0
_INTERMEDIATE_THRESHOLD = 80.0


def _maturity(pass_rate: float) -> str:
    if pass_rate >= _INTERMEDIATE_THRESHOLD:
        return "Advanced"
    if pass_rate >= _BASIC_THRESHOLD:
        return "Intermediate"
    return "Basic"


_SEVERITY_ORDER = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
}

_EFFORT_MAP_HIGH = {
    # ACGR audit findings all carry architectural weight — remediating
    # them typically involves identity migration or multi-region
    # replication work, not a self-service toggle.
    "res-acgr-identity-001",
    "res-acgr-tdg-status-001",
    "res-acgr-traffic-dist-001",
    "res-acgr-failover-test-001",
    "res-acgr-numbers-001",
    "sec-ai-cascade-001",
    "sec-excessive-agency-001",
}
_EFFORT_MAP_LOW = {
    "ops-logging-001",
    "sec-origins-001",
    "sec-federation-001",
    "ops-early-media-001",
}


def _estimate_effort(check_id: str) -> str:
    if check_id in _EFFORT_MAP_HIGH:
        return "High"
    if check_id in _EFFORT_MAP_LOW:
        return "Low"
    return "Medium"


def generate_posture_roadmap(findings: List[Finding]) -> Dict[str, PostureScore]:
    """
    Generate per-pillar posture scores and improvement roadmap.

    Returns a dict keyed by pillar value string.
    """
    roadmap: Dict[str, PostureScore] = {}

    for pillar in Pillar:
        pillar_findings = [f for f in findings if f.pillar == pillar]
        if not pillar_findings:
            continue

        # Exclude NOT_APPLICABLE and SKIPPED from the maturity denominator:
        # a check that didn't apply or couldn't run shouldn't drag the score
        # down or falsely inflate it. Total is preserved for display only.
        total = len(pillar_findings)
        evaluated_findings = [
            f
            for f in pillar_findings
            if f.status not in (CheckStatus.NOT_APPLICABLE, CheckStatus.SKIPPED)
        ]
        evaluated_total = len(evaluated_findings)
        passed = sum(1 for f in evaluated_findings if f.status == CheckStatus.PASS)
        pass_rate = (passed / evaluated_total * 100) if evaluated_total > 0 else 0.0
        maturity = _maturity(pass_rate)

        # Prioritize improvement actions from failed findings.
        failed = [f for f in pillar_findings if f.status == CheckStatus.FAIL]
        failed.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 4))
        actions = []
        for f in failed[:10]:
            actions.append(
                {
                    "check_id": f.check_id,
                    "title": f.check_name,
                    "severity": f.severity.value,
                    "guidance": (
                        f.structured_remediation.summary
                        if f.structured_remediation
                        else f.remediation[:200]
                    ),
                    "effort": _estimate_effort(f.check_id),
                    "impact": (
                        "High" if f.severity in (Severity.CRITICAL, Severity.HIGH) else "Medium"
                    ),
                }
            )

        roadmap[pillar.value] = PostureScore(
            pillar=pillar,
            total_checks=total,
            passed_checks=passed,
            pass_rate=round(pass_rate, 1),
            maturity_level=maturity,
            improvement_actions=actions,
        )

    return roadmap
