"""
Integration tests for the check framework and configuration system.

Tests the interaction between checks, registry, and configuration
to ensure they work together correctly.
"""

import json
import tempfile
from unittest.mock import Mock

from amazon_connect_assessment.checks import (
    BaseCheck,
    CheckConfigurationManager,
    CheckContext,
    CheckRegistry,
)
from amazon_connect_assessment.models import (
    CheckStatus,
    Finding,
    Pillar,
    Severity,
)


class ConfigurableTestCheck(BaseCheck):
    """Test check that uses configuration parameters."""

    def __init__(self, check_id: str = "configurable-test"):
        super().__init__(
            check_id=check_id,
            name="Configurable Test Check",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description="Test check that uses configuration",
            remediation_template="Default remediation",
        )

    def execute(self, context: CheckContext) -> "Finding":
        # Get configuration parameters
        config_manager = getattr(context, "config_manager", None)
        if config_manager:
            parameters = config_manager.get_check_parameters(self.check_id)
            fail_condition = parameters.get("should_fail", False)
            custom_message = parameters.get("custom_message", "Default message")
        else:
            fail_condition = False
            custom_message = "No configuration available"

        status = CheckStatus.FAIL if fail_condition else CheckStatus.PASS

        return self.create_finding(
            status=status,
            resource_id=context.instance.instance_id,
            resource_type="ConnectInstance",
            description=custom_message,
            evidence={"configured": config_manager is not None},
        )


class TestCheckFrameworkIntegration:
    """Test integration between check framework components."""

    def test_registry_with_configuration(self):
        """Test check registry working with configuration system."""
        # Create registry and configuration manager
        registry = CheckRegistry()
        config_manager = CheckConfigurationManager()

        # Configure some checks
        config_data = {
            "checks": {
                "security-001": {
                    "check_id": "security-001",
                    "enabled": True,
                    "severity": "critical",
                    "parameters": {
                        "should_fail": True,
                        "custom_message": "Security issue found",
                    },
                },
                "security-002": {
                    "check_id": "security-002",
                    "enabled": False,
                    "parameters": {"should_fail": False},
                },
                "resilience-001": {
                    "check_id": "resilience-001",
                    "enabled": True,
                    "severity": "high",
                    "parameters": {"custom_message": "Resilience check passed"},
                },
            }
        }
        config_manager.load_from_dict(config_data)

        # Create and register checks
        security_check_1 = ConfigurableTestCheck("security-001")
        security_check_2 = ConfigurableTestCheck("security-002")
        resilience_check = ConfigurableTestCheck("resilience-001")
        resilience_check.pillar = Pillar.RESILIENCE

        registry.register_check(security_check_1)
        registry.register_check(security_check_2)
        registry.register_check(resilience_check)

        # Test filtering enabled checks
        all_checks = registry.get_all_checks()
        enabled_checks = [
            check for check in all_checks if config_manager.is_check_enabled(check.check_id)
        ]

        assert len(all_checks) == 3
        assert len(enabled_checks) == 2  # security-002 is disabled
        assert security_check_1 in enabled_checks
        assert resilience_check in enabled_checks
        assert security_check_2 not in enabled_checks

        # Test severity overrides
        security_override = config_manager.get_check_severity_override("security-001")
        resilience_override = config_manager.get_check_severity_override("resilience-001")

        assert security_override == Severity.CRITICAL
        assert resilience_override == Severity.HIGH

    def test_check_execution_with_configuration(
        self, sample_connect_instance, mock_aws_client_factory
    ):
        """Test check execution using configuration parameters."""
        # Create configuration manager with test config
        config_manager = CheckConfigurationManager()
        config_data = {
            "checks": {
                "config-test": {
                    "check_id": "config-test",
                    "enabled": True,
                    "parameters": {
                        "should_fail": True,
                        "custom_message": "Configured failure message",
                    },
                }
            }
        }
        config_manager.load_from_dict(config_data)

        # Create check and context
        check = ConfigurableTestCheck("config-test")
        context = CheckContext(
            instance=sample_connect_instance,
            aws_client_factory=mock_aws_client_factory,
            config={},
            logger=Mock(),
        )
        # Add config manager to context
        context.config_manager = config_manager

        # Execute check
        result = check.execute(context)

        assert result.status == CheckStatus.FAIL
        assert result.description == "Configured failure message"
        assert result.evidence["configured"] is True

    def test_configuration_file_integration(self, sample_connect_instance, mock_aws_client_factory):
        """Test loading configuration from file and using it with checks."""
        # Create temporary configuration file
        config_data = {
            "global_settings": {"timeout": 600},
            "enabled_pillars": ["security"],
            "checks": {
                "file-test": {
                    "check_id": "file-test",
                    "enabled": True,
                    "severity": "high",
                    "parameters": {
                        "should_fail": False,
                        "custom_message": "File configuration loaded successfully",
                    },
                }
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            config_file = f.name

        try:
            # Load configuration from file
            config_manager = CheckConfigurationManager()
            config_manager.load_from_file(config_file)

            # Verify configuration loaded correctly
            assert config_manager.get_global_setting("timeout") == 600
            assert config_manager.get_enabled_pillars() == [Pillar.SECURITY]
            assert config_manager.is_check_enabled("file-test") is True

            # Create and execute check
            check = ConfigurableTestCheck("file-test")
            context = CheckContext(
                instance=sample_connect_instance,
                aws_client_factory=mock_aws_client_factory,
                config={},
                logger=Mock(),
            )
            context.config_manager = config_manager

            result = check.execute(context)

            assert result.status == CheckStatus.PASS
            assert result.description == "File configuration loaded successfully"

        finally:
            import os

            os.unlink(config_file)

    def test_registry_filtering_with_configuration(self):
        """Test registry filtering combined with configuration-based filtering."""
        registry = CheckRegistry()
        config_manager = CheckConfigurationManager()

        # Create checks for different pillars and severities
        checks_data = [
            ("sec-critical", Pillar.SECURITY, Severity.CRITICAL, True),
            ("sec-high", Pillar.SECURITY, Severity.HIGH, False),  # disabled
            ("res-high", Pillar.RESILIENCE, Severity.HIGH, True),
            ("cost-medium", Pillar.COST_OPTIMIZATION, Severity.MEDIUM, True),
        ]

        config_data = {"checks": {}}
        for check_id, pillar, severity, enabled in checks_data:
            # Create and register check
            check = ConfigurableTestCheck(check_id)
            check.pillar = pillar
            check.severity = severity
            registry.register_check(check)

            # Add to configuration
            config_data["checks"][check_id] = {
                "check_id": check_id,
                "enabled": enabled,
            }

        config_manager.load_from_dict(config_data)

        # Test combined filtering
        security_checks = registry.get_checks_by_pillar(Pillar.SECURITY)
        enabled_security_checks = [
            check for check in security_checks if config_manager.is_check_enabled(check.check_id)
        ]

        assert len(security_checks) == 2
        assert len(enabled_security_checks) == 1  # sec-high is disabled
        assert enabled_security_checks[0].check_id == "sec-critical"

        # Test severity filtering with configuration
        high_severity_checks = registry.get_checks_by_severity(Severity.HIGH)
        enabled_high_checks = [
            check
            for check in high_severity_checks
            if config_manager.is_check_enabled(check.check_id)
        ]

        assert len(high_severity_checks) == 2
        assert len(enabled_high_checks) == 1  # sec-high is disabled
        assert enabled_high_checks[0].check_id == "res-high"

    def test_check_result_collection_and_validation(
        self, sample_connect_instance, mock_aws_client_factory
    ):
        """Test collecting and validating check results."""
        registry = CheckRegistry()
        config_manager = CheckConfigurationManager()

        # Configure multiple checks
        config_data = {
            "checks": {
                "result-test-1": {
                    "check_id": "result-test-1",
                    "enabled": True,
                    "parameters": {"should_fail": False},
                },
                "result-test-2": {
                    "check_id": "result-test-2",
                    "enabled": True,
                    "parameters": {"should_fail": True},
                },
                "result-test-3": {
                    "check_id": "result-test-3",
                    "enabled": False,  # disabled
                    "parameters": {"should_fail": False},
                },
            }
        }
        config_manager.load_from_dict(config_data)

        # Create and register checks
        for check_id in ["result-test-1", "result-test-2", "result-test-3"]:
            check = ConfigurableTestCheck(check_id)
            registry.register_check(check)

        # Execute enabled checks and collect results
        context = CheckContext(
            instance=sample_connect_instance,
            aws_client_factory=mock_aws_client_factory,
            config={},
            logger=Mock(),
        )
        context.config_manager = config_manager

        results = []
        enabled_checks = [
            check
            for check in registry.get_all_checks()
            if config_manager.is_check_enabled(check.check_id)
        ]

        for check in enabled_checks:
            result = check.safe_execute(context)
            results.append(result)

        # Validate results
        assert len(results) == 2  # Only enabled checks executed

        # Check specific results
        result_by_id = {result.check_id: result for result in results}

        assert result_by_id["result-test-1"].status == CheckStatus.PASS
        assert result_by_id["result-test-2"].status == CheckStatus.FAIL
        assert "result-test-3" not in result_by_id  # disabled check not executed

        # Validate all results have required fields
        for result in results:
            assert result.check_id is not None
            assert result.check_name is not None
            assert result.pillar is not None
            assert result.severity is not None
            assert result.status is not None
            assert result.resource_id == sample_connect_instance.instance_id
            assert result.timestamp is not None
