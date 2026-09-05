"""
Central check registration module (Phase 7 / Task 14).

Provides a single ``register_all_checks(registry)`` entry point that
calls each module's ``register_*()`` function. Supports optional pillar
filtering so capabilities can be toggled at runtime without modifying
the engine or individual check modules.
"""

import logging
from typing import Optional, Set

from .registry import CheckRegistry

logger = logging.getLogger("check_registration")


def register_all_checks(
    registry: CheckRegistry,
    pillars: Optional[Set[str]] = None,
    severities: Optional[Set[str]] = None,
    check_ids: Optional[Set[str]] = None,
    exclude_check_ids: Optional[Set[str]] = None,
    skip_flow_analysis: bool = False,
) -> None:
    """
    Register all available checks with the given registry.

    Args:
        registry: CheckRegistry to populate.
        pillars: If provided, only register checks whose pillar value is in
                 this set. Pass None to register all pillars.
        severities: If provided, only register checks whose severity value is
                 in this set (e.g. {"critical", "high"}). Pass None for all.
        check_ids: If provided, register only these specific check IDs
                 (an allowlist) — applied after the pillar/severity filters.
                 Pass None to skip this filter.
        exclude_check_ids: If provided, remove these specific check IDs after
                 every other filter has run. Pass None to skip this filter.
        skip_flow_analysis: If True, skip checks that require parsing contact
                           flow content (reduces API calls and execution time).

    All filters are AND-ed together: a check must survive the pillar filter,
    the severity filter, and the check_ids allowlist (if any of them are
    given) to remain registered, and is then removed if it's in
    exclude_check_ids. This is what makes ``--severity critical --checks
    sec-toll-fraud-001`` behave as "critical AND that specific ID" rather
    than silently ignoring one of the two filters.
    """
    from .ai_agent_security_checks import register_ai_agent_security_checks
    from .ai_ops_maturity_checks import register_ai_ops_maturity_checks
    from .contact_flow_behavior_checks import register_contact_flow_behavior_checks
    from .contact_flow_security_checks import register_contact_flow_security_checks
    from .cost_containment_checks import register_cost_containment_checks
    from .cost_intelligence_checks import register_cost_intelligence_checks
    from .mvp_checks import register_mvp_checks
    from .operational_excellence_checks import register_operational_excellence_checks
    from .performance_efficiency_checks import register_performance_efficiency_checks
    from .resilience_advanced_checks import register_advanced_resilience_checks
    from .security_deep_checks import register_security_deep_checks

    # Always register the original MVP checks (backward compat).
    register_mvp_checks(registry)

    # Instance-level checks (no flow parsing needed).
    register_security_deep_checks(registry)
    register_cost_intelligence_checks(registry)
    register_operational_excellence_checks(registry)
    register_ai_ops_maturity_checks(registry)

    # Resilience includes both instance-level checks and a flow-dependent
    # Lambda call-site check. Keep the latter aligned with --skip-flow-analysis.
    register_advanced_resilience_checks(registry, include_flow_checks=not skip_flow_analysis)

    # Flow-content checks (skip if requested).
    if not skip_flow_analysis:
        register_contact_flow_security_checks(registry)
        register_ai_agent_security_checks(registry)
        register_cost_containment_checks(registry)
        register_contact_flow_behavior_checks(registry)
        register_performance_efficiency_checks(registry)
    else:
        logger.info("Skipping flow-analysis checks (--skip-flow-analysis)")

    # Apply pillar filter if requested.
    if pillars:
        all_checks = registry.get_all_checks()
        to_remove = [c for c in all_checks if c.pillar.value not in pillars]
        for check in to_remove:
            registry.unregister_check(check.check_id)
        logger.info(f"Pillar filter applied ({pillars}); removed {len(to_remove)} checks")

    # Apply severity filter if requested (--severity).
    if severities:
        all_checks = registry.get_all_checks()
        to_remove = [c for c in all_checks if c.severity.value not in severities]
        for check in to_remove:
            registry.unregister_check(check.check_id)
        logger.info(f"Severity filter applied ({severities}); removed {len(to_remove)} checks")

    # Apply explicit check-ID allowlist if requested (--checks).
    if check_ids:
        all_checks = registry.get_all_checks()
        to_remove = [c for c in all_checks if c.check_id not in check_ids]
        for check in to_remove:
            registry.unregister_check(check.check_id)
        remaining_ids = {c.check_id for c in registry.get_all_checks()}
        missing = check_ids - remaining_ids
        if missing:
            logger.warning(
                f"Requested check ID(s) not found (or excluded by an earlier "
                f"filter): {sorted(missing)}"
            )
        logger.info(f"Check-ID allowlist applied; {len(remaining_ids)} check(s) remain")

    # Apply explicit exclusion list if requested (--exclude-checks).
    if exclude_check_ids:
        excluded = 0
        for check_id in exclude_check_ids:
            if check_id in registry:
                registry.unregister_check(check_id)
                excluded += 1
        logger.info(f"Excluded {excluded} check(s) by ID via --exclude-checks")

    total = len(registry.get_all_checks())
    logger.info(f"Total checks registered: {total}")
