"""
MVP Check Registration for Amazon Connect Assessment Tool.

This module provides functionality to register all MVP (Minimum Viable Product)
checks with the check registry. MVP checks focus on Critical and High severity
issues across all three AWS Well-Architected Framework pillars.

The MVP implementation prioritizes the most impactful checks that can be
easily detected and provide immediate value to users.
"""

import logging
from typing import List

from ..models import Severity
from .base import BaseCheck
from .cost_optimization_checks import (
    InefficientResourceAllocationCheck,
    OversizedConfigurationCheck,
    UnusedResourcesCheck,
)
from .registry import CheckRegistry

# The original resilience_checks.py module is gone. All three of its checks
# (MultiAZ, DR, FailoverMechanism) fired on trivially-true conditions —
# 'only one routing profile', 'no more than one queue', 'contact flows
# should be regularly exported'. None of them detected a real problem. Real
# resilience signal lives in resilience_advanced_checks.py (res-acgr-*,
# res-cloudwatch-001, res-hardcoded-routing-001) and
# contact_flow_behavior_checks.py (res-flow-errors-001, res-flow-loops-001).
# EncryptionConfigurationCheck (security-encryption-001) and NetworkSecurityCheck
# (security-network-001) were removed as noise generators — see the
# security_checks.py module docstring for the rationale. Real signal now
# comes from security_deep_checks (sec-storage-001, sec-federation-001,
# sec-origins-001, etc.).
from .security_checks import (
    DataProtectionCheck,
    IAMServiceRoleCheck,
)


def get_mvp_checks() -> List[BaseCheck]:
    """
    Get all MVP checks prioritized by severity.

    Returns checks in order of priority:
    1. Critical severity checks
    2. High severity checks
    3. Medium severity checks
    4. Low severity checks

    Returns:
        List[BaseCheck]: All MVP checks ordered by priority
    """
    checks = [
        # Critical Severity Checks (highest priority)
        IAMServiceRoleCheck(),
        # Medium Severity Checks
        DataProtectionCheck(),
        UnusedResourcesCheck(),
        InefficientResourceAllocationCheck(),
        # Low Severity Checks
        OversizedConfigurationCheck(),
    ]

    return checks


def get_critical_checks() -> List[BaseCheck]:
    """
    Get only Critical severity MVP checks.

    Returns:
        List[BaseCheck]: Critical severity checks only
    """
    all_checks = get_mvp_checks()
    return [check for check in all_checks if check.severity == Severity.CRITICAL]


def get_high_priority_checks() -> List[BaseCheck]:
    """
    Get Critical and High severity MVP checks.

    Returns:
        List[BaseCheck]: Critical and High severity checks
    """
    all_checks = get_mvp_checks()
    return [check for check in all_checks if check.severity in [Severity.CRITICAL, Severity.HIGH]]


def register_mvp_checks(registry: CheckRegistry) -> None:
    """
    Register all MVP checks with the provided registry.

    Args:
        registry: CheckRegistry instance to register checks with

    Raises:
        ValueError: If a check with duplicate ID is encountered
    """
    logger = logging.getLogger("mvp_checks")

    checks = get_mvp_checks()

    logger.info(f"Registering {len(checks)} MVP checks")

    for check in checks:
        try:
            registry.register_check(check)
            logger.debug(
                f"Registered check: {check.check_id} ({check.pillar.value}, {check.severity.value})"
            )
        except ValueError as e:
            logger.error(f"Failed to register check {check.check_id}: {str(e)}")
            raise

    # Log registration summary
    pillar_counts = registry.get_pillar_counts()
    severity_counts = registry.get_severity_counts()

    logger.info("MVP check registration complete:")
    logger.info(f"  Total checks: {len(checks)}")
    logger.info(f"  By pillar: {dict(pillar_counts)}")
    logger.info(f"  By severity: {dict(severity_counts)}")


def register_priority_checks(registry: CheckRegistry, include_medium: bool = False) -> None:
    """
    Register only high-priority MVP checks (Critical and High severity).

    This function is useful for quick assessments or when time/resources
    are limited and you want to focus on the most critical issues.

    Args:
        registry: CheckRegistry instance to register checks with
        include_medium: Whether to include Medium severity checks

    Raises:
        ValueError: If a check with duplicate ID is encountered
    """
    logger = logging.getLogger("mvp_checks")

    if include_medium:
        checks = [
            check
            for check in get_mvp_checks()
            if check.severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM]
        ]
        logger.info(f"Registering {len(checks)} high-priority MVP checks (Critical, High, Medium)")
    else:
        checks = get_high_priority_checks()
        logger.info(f"Registering {len(checks)} high-priority MVP checks (Critical, High)")

    for check in checks:
        try:
            registry.register_check(check)
            logger.debug(
                f"Registered priority check: {check.check_id} ({check.pillar.value}, {check.severity.value})"
            )
        except ValueError as e:
            logger.error(f"Failed to register priority check {check.check_id}: {str(e)}")
            raise

    # Log registration summary
    pillar_counts = registry.get_pillar_counts()
    severity_counts = registry.get_severity_counts()

    logger.info("Priority check registration complete:")
    logger.info(f"  Total checks: {len(checks)}")
    logger.info(f"  By pillar: {dict(pillar_counts)}")
    logger.info(f"  By severity: {dict(severity_counts)}")


def get_check_summary() -> dict:
    """
    Get a summary of all available MVP checks.

    Returns:
        dict: Summary information about MVP checks
    """
    checks = get_mvp_checks()

    summary = {
        "total_checks": len(checks),
        "by_pillar": {},
        "by_severity": {},
        "check_list": [],
    }

    # Count by pillar
    for check in checks:
        pillar = check.pillar.value
        summary["by_pillar"][pillar] = summary["by_pillar"].get(pillar, 0) + 1

    # Count by severity
    for check in checks:
        severity = check.severity.value
        summary["by_severity"][severity] = summary["by_severity"].get(severity, 0) + 1

    # Create check list
    for check in checks:
        summary["check_list"].append(
            {
                "check_id": check.check_id,
                "name": check.name,
                "pillar": check.pillar.value,
                "severity": check.severity.value,
                "description": check.description,
            }
        )

    return summary


def validate_mvp_checks() -> List[str]:
    """
    Validate all MVP checks for consistency and completeness.

    Returns:
        List[str]: List of validation errors (empty if all checks are valid)
    """
    errors = []
    checks = get_mvp_checks()

    # Check for duplicate IDs
    check_ids = [check.check_id for check in checks]
    duplicate_ids = [check_id for check_id in check_ids if check_ids.count(check_id) > 1]
    if duplicate_ids:
        errors.append(f"Duplicate check IDs found: {set(duplicate_ids)}")

    # Validate each check
    for check in checks:
        # Check ID format
        if not check.check_id or not isinstance(check.check_id, str):
            errors.append(f"Invalid check ID for {check.__class__.__name__}: {check.check_id}")

        # Check name
        if not check.name or not isinstance(check.name, str):
            errors.append(f"Invalid check name for {check.check_id}: {check.name}")

        # Check description
        if not check.description or not isinstance(check.description, str):
            errors.append(f"Missing or invalid description for {check.check_id}")

        # Check remediation template
        if not check.remediation_template or not isinstance(check.remediation_template, str):
            errors.append(f"Missing or invalid remediation template for {check.check_id}")

    # Check pillar coverage.
    #
    # The MVP set covers security and cost_optimization by design.
    # Resilience-pillar checks were removed from the MVP set after
    # user feedback that the three original resilience MVP checks
    # (Multi-AZ, DR, Failover Mechanism) either flagged normal deployment
    # shapes as deficiencies or asserted things the tool cannot verify.
    # Substantive resilience signal now lives in the res-acgr-* set and
    # the flow-content checks, which register through register_all_checks
    # (not the MVP-only path), so resilience is intentionally absent here.
    pillars_covered = {check.pillar for check in checks}
    expected_pillars = {"security", "cost_optimization"}
    missing_pillars = expected_pillars - {pillar.value for pillar in pillars_covered}
    if missing_pillars:
        errors.append(f"Missing pillar coverage: {missing_pillars}")

    # Check severity distribution.
    #
    # The MVP set no longer covers HIGH severity by design. The two
    # original HIGH-severity MVP checks — EncryptionConfigurationCheck
    # and NetworkSecurityCheck — were both removed as noise generators
    # (see the security_checks.py module docstring). The full catalog
    # still has plenty of HIGH-severity signal via register_all_checks,
    # notably the sec-iam-deep, sec-storage, sec-origins, sec-cloudtrail
    # set in security_deep_checks.py; the MVP subset just doesn't
    # duplicate them.
    severities = [check.severity for check in checks]
    if not any(severity == Severity.CRITICAL for severity in severities):
        errors.append("No Critical severity checks found")

    return errors


# Module-level validation on import
_validation_errors = validate_mvp_checks()
if _validation_errors:
    logger = logging.getLogger("mvp_checks")
    logger.warning(f"MVP checks validation found issues: {_validation_errors}")
