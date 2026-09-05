"""
Property-based tests for pluggable architecture extensibility.

Feature: amazon-connect-assessment
Property 15: Pluggable Architecture Extensibility

Tests that validate the system's ability to add new checks without modifying
core system code, and that checks support external configuration.

Validates: Requirements 8.2, 8.3, 8.5
"""

import logging
from typing import Any, Dict

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from amazon_connect_assessment.analyzers.base import BaseAnalyzer
from amazon_connect_assessment.checks.base import BaseCheck, CheckContext
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import (
    CheckStatus,
    ConnectInstance,
    Finding,
    Pillar,
    Severity,
)

# Strategy for generating valid check IDs
check_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Nd"), whitelist_characters="-"),
    min_size=5,
    max_size=30,
).filter(lambda x: x and not x.startswith("-") and not x.endswith("-"))


# Strategy for generating check names
check_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Lu", "Ll", "Nd", "Zs")),
    min_size=10,
    max_size=100,
).filter(lambda x: x.strip())


# Strategy for generating check configurations
check_config_strategy = st.fixed_dictionaries(
    {
        "enabled": st.booleans(),
        "severity": st.sampled_from([s.value for s in Severity]),
        "parameters": st.dictionaries(
            keys=st.text(min_size=1, max_size=20),
            values=st.one_of(
                st.text(max_size=50),
                st.integers(min_value=0, max_value=1000),
                st.booleans(),
            ),
            max_size=5,
        ),
    }
)


class DynamicCheck(BaseCheck):
    """
    Dynamically configurable check for testing pluggable architecture.

    This check can be instantiated with any configuration without modifying
    core system code, demonstrating the pluggable architecture property.
    """

    def __init__(
        self,
        check_id: str,
        name: str,
        pillar: Pillar,
        severity: Severity,
        description: str = "",
        remediation_template: str = "",
        custom_config: Dict[str, Any] = None,
    ):
        super().__init__(
            check_id=check_id,
            name=name,
            pillar=pillar,
            severity=severity,
            description=description,
            remediation_template=remediation_template,
        )
        self.custom_config = custom_config or {}

    def execute(self, context: CheckContext) -> Finding:
        """Execute check using custom configuration."""
        # Use custom configuration to determine behavior
        enabled = self.custom_config.get("enabled", True)

        if not enabled:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=context.instance.instance_id,
                resource_type="ConnectInstance",
                description="Check is disabled via configuration",
            )

        # Simulate check logic that uses configuration parameters
        threshold = self.custom_config.get("parameters", {}).get("threshold", 0)

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=context.instance.instance_id,
            resource_type="ConnectInstance",
            description=f"Check executed with threshold={threshold}",
            evidence={"config": self.custom_config},
        )


class DynamicAnalyzer(BaseAnalyzer):
    """
    Dynamically configurable analyzer for testing pluggable architecture.

    This analyzer can be instantiated with any configuration without modifying
    core system code, demonstrating the pluggable architecture property.
    """

    def analyze(self, instance: ConnectInstance) -> ConnectInstance:
        """Analyze instance using custom configuration."""
        # Use configuration to determine analysis behavior
        analyze_flows = self.config.get("analyze_contact_flows", True)
        analyze_queues = self.config.get("analyze_queues", True)

        # Simulate analysis that respects configuration
        if analyze_flows:
            self.logger.debug(f"Analyzing contact flows for {instance.instance_id}")

        if analyze_queues:
            self.logger.debug(f"Analyzing queues for {instance.instance_id}")

        return instance


# Property 15: Pluggable Architecture Extensibility
# For any new check addition, it should be possible to add it without modifying
# core system code, and checks should support external configuration.


@given(
    check_id=check_id_strategy,
    check_name=check_name_strategy,
    pillar=st.sampled_from(list(Pillar)),
    severity=st.sampled_from(list(Severity)),
    config=check_config_strategy,
)
@settings(max_examples=100)
def test_property_new_checks_can_be_added_without_core_modification(
    check_id, check_name, pillar, severity, config
):
    """
    Property: New checks can be added to the system without modifying core code.

    This test validates that:
    1. New check classes can be created by inheriting from BaseCheck
    2. Checks can be registered in the CheckRegistry without modifying registry code
    3. The system accepts any valid check configuration
    4. Checks can be retrieved and executed after registration

    Validates: Requirement 8.2 - pluggable architecture for easy extension
    """
    # Assume valid inputs
    assume(check_id and check_name)

    # Create a new check without modifying core system code
    new_check = DynamicCheck(
        check_id=check_id,
        name=check_name,
        pillar=pillar,
        severity=severity,
        description=f"Dynamic check for {pillar.value}",
        remediation_template="Follow AWS best practices",
        custom_config=config,
    )

    # Register the check without modifying CheckRegistry code
    registry = CheckRegistry()
    registry.register_check(new_check)

    # Verify the check was registered successfully
    assert check_id in registry
    assert registry.get_check_count() == 1

    # Verify the check can be retrieved
    retrieved_check = registry.get_check(check_id)
    assert retrieved_check.check_id == check_id
    assert retrieved_check.name == check_name
    assert retrieved_check.pillar == pillar
    assert retrieved_check.severity == severity

    # Verify the check can be filtered by pillar
    pillar_checks = registry.get_checks_by_pillar(pillar)
    assert len(pillar_checks) == 1
    assert pillar_checks[0].check_id == check_id

    # Verify the check can be filtered by severity
    severity_checks = registry.get_checks_by_severity(severity)
    assert len(severity_checks) == 1
    assert severity_checks[0].check_id == check_id


@given(
    check_id=check_id_strategy,
    config=check_config_strategy,
)
@settings(max_examples=100)
def test_property_checks_support_external_configuration(check_id, config):
    """
    Property: Checks support external configuration without code changes.

    This test validates that:
    1. Checks can be configured via external configuration dictionaries
    2. Configuration affects check behavior without modifying check code
    3. Checks respect enabled/disabled state from configuration
    4. Checks can access custom parameters from configuration

    Validates: Requirement 8.3 - support check configuration through external files
    """
    from unittest.mock import Mock

    # Assume valid inputs
    assume(check_id)

    # Create a check with external configuration
    check = DynamicCheck(
        check_id=check_id,
        name=f"Configurable Check {check_id}",
        pillar=Pillar.SECURITY,
        severity=Severity(config["severity"]),
        custom_config=config,
    )

    # Create sample instance and mock factory
    sample_instance = ConnectInstance(
        instance_id="test-instance-123",
        instance_arn="arn:aws:connect:us-east-1:123456789012:instance/test-instance-123",
        identity_management_type="CONNECT_MANAGED",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
        instance_alias="test-instance",
        service_role="arn:aws:iam::123456789012:role/ConnectServiceRole",
        status="ACTIVE",
    )

    mock_factory = Mock()

    # Create check context
    context = CheckContext(
        instance=sample_instance,
        aws_client_factory=mock_factory,
        config={},
        logger=logging.getLogger("test"),
    )

    # Execute the check
    finding = check.execute(context)

    # Verify configuration affects behavior
    if not config["enabled"]:
        # Check should be skipped when disabled in configuration
        assert finding.status == CheckStatus.SKIPPED
        assert "disabled" in finding.description.lower()
    else:
        # Check should execute when enabled
        assert finding.status in [CheckStatus.PASS, CheckStatus.FAIL]

        # Verify custom parameters are accessible
        if "threshold" in config["parameters"]:
            assert "threshold" in finding.description.lower()

        # Verify configuration is preserved in evidence
        assert finding.evidence.get("config") == config


@given(
    num_checks=st.integers(min_value=1, max_value=50),
    pillars=st.lists(st.sampled_from(list(Pillar)), min_size=1, max_size=3, unique=True),
    severities=st.lists(st.sampled_from(list(Severity)), min_size=1, max_size=4, unique=True),
)
@settings(max_examples=100)
def test_property_framework_supports_multiple_checks_registration(num_checks, pillars, severities):
    """
    Property: Framework supports registering multiple checks without modification.

    This test validates that:
    1. Multiple checks can be registered simultaneously
    2. Registry maintains correct counts and organization
    3. Filtering works correctly with multiple checks
    4. No core code modification is needed for any number of checks

    Validates: Requirement 8.5 - framework for adding exhaustive checks
    """
    registry = CheckRegistry()
    registered_checks = []

    # Register multiple checks without modifying core code
    for i in range(num_checks):
        pillar = pillars[i % len(pillars)]
        severity = severities[i % len(severities)]

        check = DynamicCheck(
            check_id=f"dynamic-check-{i}",
            name=f"Dynamic Check {i}",
            pillar=pillar,
            severity=severity,
            custom_config={"enabled": True, "parameters": {"index": i}},
        )

        registry.register_check(check)
        registered_checks.append(check)

    # Verify all checks were registered
    assert registry.get_check_count() == num_checks
    assert len(registry.get_all_checks()) == num_checks

    # Verify pillar-based filtering works correctly
    for pillar in pillars:
        pillar_checks = registry.get_checks_by_pillar(pillar)
        expected_count = sum(1 for c in registered_checks if c.pillar == pillar)
        assert len(pillar_checks) == expected_count

    # Verify severity-based filtering works correctly
    for severity in severities:
        severity_checks = registry.get_checks_by_severity(severity)
        expected_count = sum(1 for c in registered_checks if c.severity == severity)
        assert len(severity_checks) == expected_count

    # Verify combined filtering works
    filtered_checks = registry.get_filtered_checks(pillars=pillars[:1], severities=severities[:1])
    expected_checks = [
        c for c in registered_checks if c.pillar == pillars[0] and c.severity == severities[0]
    ]
    assert len(filtered_checks) == len(expected_checks)


@given(
    analyzer_config=st.fixed_dictionaries(
        {
            "analyze_contact_flows": st.booleans(),
            "analyze_queues": st.booleans(),
            "analyze_routing_profiles": st.booleans(),
            "max_items": st.integers(min_value=1, max_value=100),
        }
    )
)
@settings(max_examples=100)
def test_property_analyzers_support_external_configuration(analyzer_config):
    """
    Property: Analyzers support external configuration without code changes.

    This test validates that:
    1. Analyzers can be configured via external configuration dictionaries
    2. Configuration affects analyzer behavior without modifying analyzer code
    3. Analyzers respect configuration parameters during analysis

    Validates: Requirement 8.3 - support configuration through external files
    """
    from unittest.mock import Mock

    # Create sample instance and mock factory
    sample_instance = ConnectInstance(
        instance_id="test-instance-123",
        instance_arn="arn:aws:connect:us-east-1:123456789012:instance/test-instance-123",
        identity_management_type="CONNECT_MANAGED",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
        instance_alias="test-instance",
        service_role="arn:aws:iam::123456789012:role/ConnectServiceRole",
        status="ACTIVE",
    )

    mock_factory = Mock()

    # Create an analyzer with external configuration
    analyzer = DynamicAnalyzer(aws_client_factory=mock_factory, config=analyzer_config)

    # Verify configuration is accessible
    assert analyzer.config == analyzer_config
    assert analyzer.config.get("analyze_contact_flows") == analyzer_config["analyze_contact_flows"]
    assert analyzer.config.get("analyze_queues") == analyzer_config["analyze_queues"]
    assert analyzer.config.get("max_items") == analyzer_config["max_items"]

    # Execute analysis
    result = analyzer.analyze(sample_instance)

    # Verify analysis completed without errors
    assert result is not None
    assert result.instance_id == sample_instance.instance_id


@given(
    check_configs=st.lists(
        st.fixed_dictionaries(
            {
                "check_id": check_id_strategy,
                "pillar": st.sampled_from(list(Pillar)),
                "severity": st.sampled_from(list(Severity)),
                "config": check_config_strategy,
            }
        ),
        min_size=1,
        max_size=20,
        unique_by=lambda x: x["check_id"],
    )
)
@settings(max_examples=100)
def test_property_registry_handles_diverse_check_configurations(check_configs):
    """
    Property: Registry handles diverse check configurations without modification.

    This test validates that:
    1. Registry can handle checks with various configurations
    2. No core code modification is needed for different check types
    3. Registry maintains integrity with diverse check sets

    Validates: Requirements 8.2, 8.3, 8.5 - pluggable architecture with configuration
    """
    registry = CheckRegistry()

    # Register checks with diverse configurations
    for check_config in check_configs:
        check = DynamicCheck(
            check_id=check_config["check_id"],
            name=f"Check {check_config['check_id']}",
            pillar=check_config["pillar"],
            severity=check_config["severity"],
            custom_config=check_config["config"],
        )
        registry.register_check(check)

    # Verify all checks were registered
    assert registry.get_check_count() == len(check_configs)

    # Verify each check can be retrieved with its configuration
    for check_config in check_configs:
        check = registry.get_check(check_config["check_id"])
        assert check.check_id == check_config["check_id"]
        assert check.pillar == check_config["pillar"]
        assert check.severity == check_config["severity"]
        assert check.custom_config == check_config["config"]

    # Verify pillar counts are correct
    pillar_counts = registry.get_pillar_counts()
    for pillar in Pillar:
        expected_count = sum(1 for c in check_configs if c["pillar"] == pillar)
        assert pillar_counts.get(pillar, 0) == expected_count

    # Verify severity counts are correct
    severity_counts = registry.get_severity_counts()
    for severity in Severity:
        expected_count = sum(1 for c in check_configs if c["severity"] == severity)
        assert severity_counts.get(severity, 0) == expected_count
