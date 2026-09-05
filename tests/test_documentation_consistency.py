"""Deterministic drift checks for checked-in assessment documentation."""

import re
from collections import Counter
from pathlib import Path

from amazon_connect_assessment.checks.base import BaseCheck
from amazon_connect_assessment.checks.registration import register_all_checks
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import Pillar

REPO_ROOT = Path(__file__).resolve().parents[1]
README_PATH = REPO_ROOT / "README.md"
CATALOG_PATH = REPO_ROOT / "docs" / "check-catalog.md"
CATALOG_CHECK_ROW = re.compile(r"^\| `([a-z][a-z0-9-]*-\d{3})` \|", re.MULTILINE)
JOURNEY_FINDING_IDS = {
    "journey-sec-001",
    "journey-cost-001",
    "journey-res-001",
    "journey-scope-001",
}
PILLAR_HEADINGS = {
    Pillar.SECURITY: "Security",
    Pillar.RESILIENCE: "Resilience",
    Pillar.COST_OPTIMIZATION: "Cost Optimization",
    Pillar.OPERATIONAL_EXCELLENCE: "Operational Excellence",
    Pillar.PERFORMANCE_EFFICIENCY: "Performance Efficiency",
}


def _registered_checks() -> list[BaseCheck]:
    registry = CheckRegistry()
    register_all_checks(registry)
    return registry.get_all_checks()


def test_documentation_catalog_registry_ids_match():
    # Arrange
    registered_ids = [check.check_id for check in _registered_checks()]

    # Act
    catalog = CATALOG_PATH.read_text(encoding="utf-8")
    catalog_rows = CATALOG_CHECK_ROW.findall(catalog)
    catalog_registered_ids = [
        check_id for check_id in catalog_rows if check_id not in JOURNEY_FINDING_IDS
    ]
    catalog_journey_ids = [check_id for check_id in catalog_rows if check_id in JOURNEY_FINDING_IDS]

    # Assert
    assert Counter(catalog_registered_ids) == Counter(registered_ids)
    assert Counter(catalog_journey_ids) == Counter(JOURNEY_FINDING_IDS)


def test_documentation_runtime_count_matches_readme_and_catalog():
    # Arrange
    checks = _registered_checks()
    check_count = len(checks)
    pillar_counts = Counter(check.pillar for check in checks)

    # Act
    readme = README_PATH.read_text(encoding="utf-8")
    catalog = CATALOG_PATH.read_text(encoding="utf-8")

    # Assert
    assert f"**{check_count} assessment checks**" in readme
    assert f"{check_count} registered checks across 5 AWS Well-Architected pillars" in catalog
    for pillar, heading in PILLAR_HEADINGS.items():
        count = pillar_counts[pillar]
        assert f"| {heading} | {count} |" in readme
        assert f"## {heading} — {count} checks" in catalog


def test_documentation_iam_guidance_uses_canonical_artifacts():
    # Arrange
    expected_json = "docs/iam-policy-template.json"
    expected_cloudformation = "cloudformation/AmazonConnectSelfAssessmentPolicy.yaml"

    # Act
    documentation = "\n".join(
        [
            README_PATH.read_text(encoding="utf-8"),
            CATALOG_PATH.read_text(encoding="utf-8"),
        ]
    )

    # Assert
    assert expected_json in documentation
    assert expected_cloudformation in documentation
    assert "qconnect:" not in documentation
