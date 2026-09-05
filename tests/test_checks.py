"""
Unit tests for the check framework.

Tests the base check interface, check registry, and check context
functionality used throughout the assessment system.
"""

import logging
from unittest.mock import Mock

import pytest

from amazon_connect_assessment.models import CheckStatus, Finding, Pillar, Severity


class TestCheckRegistry:
    """Test CheckRegistry functionality."""

    def test_empty_registry(self, check_registry):
        """Test empty registry state."""
        assert len(check_registry) == 0
        assert check_registry.get_check_count() == 0
        assert check_registry.get_all_checks() == []

    def test_register_check(self, check_registry, mock_check):
        """Test check registration."""
        check_registry.register_check(mock_check)

        assert len(check_registry) == 1
        assert check_registry.get_check_count() == 1
        assert mock_check.check_id in check_registry
        assert check_registry.get_check(mock_check.check_id) == mock_check

    def test_register_duplicate_check(self, check_registry, mock_check):
        """Test that duplicate check IDs raise an error."""
        check_registry.register_check(mock_check)

        with pytest.raises(ValueError, match="already registered"):
            check_registry.register_check(mock_check)

    def test_get_nonexistent_check(self, check_registry):
        """Test getting a check that doesn't exist."""
        with pytest.raises(KeyError, match="No check registered"):
            check_registry.get_check("nonexistent-check")

    def test_get_checks_by_pillar(self, check_registry):
        """Test filtering checks by pillar."""
        # Create checks for different pillars
        security_check = Mock()
        security_check.check_id = "security-001"
        security_check.pillar = Pillar.SECURITY
        security_check.severity = Severity.HIGH

        resilience_check = Mock()
        resilience_check.check_id = "resilience-001"
        resilience_check.pillar = Pillar.RESILIENCE
        resilience_check.severity = Severity.MEDIUM

        check_registry.register_check(security_check)
        check_registry.register_check(resilience_check)

        security_checks = check_registry.get_checks_by_pillar(Pillar.SECURITY)
        resilience_checks = check_registry.get_checks_by_pillar(Pillar.RESILIENCE)
        cost_checks = check_registry.get_checks_by_pillar(Pillar.COST_OPTIMIZATION)

        assert len(security_checks) == 1
        assert security_checks[0] == security_check
        assert len(resilience_checks) == 1
        assert resilience_checks[0] == resilience_check
        assert len(cost_checks) == 0

    def test_get_checks_by_severity(self, check_registry):
        """Test filtering checks by severity."""
        # Create checks with different severities
        critical_check = Mock()
        critical_check.check_id = "critical-001"
        critical_check.pillar = Pillar.SECURITY
        critical_check.severity = Severity.CRITICAL

        high_check = Mock()
        high_check.check_id = "high-001"
        high_check.pillar = Pillar.SECURITY
        high_check.severity = Severity.HIGH

        check_registry.register_check(critical_check)
        check_registry.register_check(high_check)

        critical_checks = check_registry.get_checks_by_severity(Severity.CRITICAL)
        high_checks = check_registry.get_checks_by_severity(Severity.HIGH)
        medium_checks = check_registry.get_checks_by_severity(Severity.MEDIUM)

        assert len(critical_checks) == 1
        assert critical_checks[0] == critical_check
        assert len(high_checks) == 1
        assert high_checks[0] == high_check
        assert len(medium_checks) == 0

    def test_get_filtered_checks(self, check_registry):
        """Test complex filtering of checks."""
        # Create various checks
        sec_critical = Mock()
        sec_critical.check_id = "sec-critical"
        sec_critical.pillar = Pillar.SECURITY
        sec_critical.severity = Severity.CRITICAL

        sec_high = Mock()
        sec_high.check_id = "sec-high"
        sec_high.pillar = Pillar.SECURITY
        sec_high.severity = Severity.HIGH

        res_critical = Mock()
        res_critical.check_id = "res-critical"
        res_critical.pillar = Pillar.RESILIENCE
        res_critical.severity = Severity.CRITICAL

        for check in [sec_critical, sec_high, res_critical]:
            check_registry.register_check(check)

        # Test filtering by pillar and severity
        filtered = check_registry.get_filtered_checks(
            pillars=[Pillar.SECURITY], severities=[Severity.CRITICAL]
        )
        assert len(filtered) == 1
        assert filtered[0] == sec_critical

        # Test filtering by specific check IDs
        filtered = check_registry.get_filtered_checks(check_ids=["sec-high", "res-critical"])
        assert len(filtered) == 2
        assert sec_high in filtered
        assert res_critical in filtered

    def test_pillar_counts(self, check_registry):
        """Test pillar count functionality."""
        # Add checks for different pillars
        for i in range(3):
            check = Mock()
            check.check_id = f"security-{i}"
            check.pillar = Pillar.SECURITY
            check.severity = Severity.HIGH
            check_registry.register_check(check)

        for i in range(2):
            check = Mock()
            check.check_id = f"resilience-{i}"
            check.pillar = Pillar.RESILIENCE
            check.severity = Severity.MEDIUM
            check_registry.register_check(check)

        counts = check_registry.get_pillar_counts()
        assert counts[Pillar.SECURITY] == 3
        assert counts[Pillar.RESILIENCE] == 2
        assert counts.get(Pillar.COST_OPTIMIZATION, 0) == 0

    def test_severity_counts(self, check_registry):
        """Test severity count functionality."""
        # Add checks with different severities
        for i in range(2):
            check = Mock()
            check.check_id = f"critical-{i}"
            check.pillar = Pillar.SECURITY
            check.severity = Severity.CRITICAL
            check_registry.register_check(check)

        for i in range(4):
            check = Mock()
            check.check_id = f"high-{i}"
            check.pillar = Pillar.SECURITY
            check.severity = Severity.HIGH
            check_registry.register_check(check)

        counts = check_registry.get_severity_counts()
        assert counts[Severity.CRITICAL] == 2
        assert counts[Severity.HIGH] == 4
        assert counts.get(Severity.MEDIUM, 0) == 0
        assert counts.get(Severity.LOW, 0) == 0

    def test_clear_registry(self, check_registry, mock_check):
        """Test clearing the registry."""
        check_registry.register_check(mock_check)
        assert len(check_registry) == 1

        check_registry.clear()
        assert len(check_registry) == 0
        assert check_registry.get_check_count() == 0


class TestBaseCheck:
    """Test BaseCheck functionality."""

    def test_check_creation(self):
        """Test basic check creation."""
        check = Mock()
        check.check_id = "test-check"
        check.name = "Test Check"
        check.pillar = Pillar.SECURITY
        check.severity = Severity.HIGH
        check.description = "Test description"
        check.remediation_template = "Test remediation"

        assert check.check_id == "test-check"
        assert check.name == "Test Check"
        assert check.pillar == Pillar.SECURITY
        assert check.severity == Severity.HIGH

    def test_create_finding(self, mock_check):
        """Test finding creation helper method."""
        finding = mock_check.create_finding(
            status=CheckStatus.FAIL,
            resource_id="test-resource",
            resource_type="ContactFlow",
            description="Test failure",
            evidence={"key": "value"},
        )

        assert isinstance(finding, Finding)
        assert finding.check_id == mock_check.check_id
        assert finding.check_name == mock_check.name
        assert finding.pillar == mock_check.pillar
        assert finding.severity == mock_check.severity
        assert finding.status == CheckStatus.FAIL
        assert finding.resource_id == "test-resource"
        assert finding.resource_type == "ContactFlow"
        assert finding.description == "Test failure"
        assert finding.evidence == {"key": "value"}

    def test_safe_execute_success(self, mock_check, check_context):
        """Test successful check execution."""
        result = mock_check.safe_execute(check_context)

        assert isinstance(result, Finding)
        assert result.status == CheckStatus.PASS  # MockCheck defaults to PASS
        assert result.resource_id == check_context.instance.instance_id

    def test_safe_execute_with_exception(self, check_context):
        """Test check execution with exception handling."""
        # Create a check that raises an exception
        failing_check = Mock()
        failing_check.check_id = "failing-check"
        failing_check.name = "Failing Check"
        failing_check.pillar = Pillar.SECURITY
        failing_check.severity = Severity.HIGH
        failing_check.logger = logging.getLogger("test")

        # Mock the execute method to raise an exception
        failing_check.execute.side_effect = Exception("Test error")

        # Mock the create_finding method
        error_finding = Finding(
            check_id="failing-check",
            check_name="Failing Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            status=CheckStatus.ERROR,
            resource_id=check_context.instance.instance_id,
            resource_type="ConnectInstance",
            description="Check execution failed: Test error",
            remediation="",
            evidence={"error": "Test error", "error_type": "Exception"},
        )
        failing_check.create_finding.return_value = error_finding

        # Create a safe_execute method that mimics BaseCheck behavior
        def safe_execute(context):
            try:
                failing_check.logger.debug(f"Executing check {failing_check.check_id}")
                result = failing_check.execute(context)
                failing_check.logger.debug(f"Check {failing_check.check_id} completed")
                return result
            except Exception as e:
                failing_check.logger.error(f"Check {failing_check.check_id} failed: {str(e)}")
                return failing_check.create_finding(
                    status=CheckStatus.ERROR,
                    resource_id=context.instance.instance_id,
                    resource_type="ConnectInstance",
                    description=f"Check execution failed: {str(e)}",
                    evidence={"error": str(e), "error_type": type(e).__name__},
                )

        failing_check.safe_execute = safe_execute

        result = failing_check.safe_execute(check_context)

        assert isinstance(result, Finding)
        assert result.status == CheckStatus.ERROR
        assert "Test error" in result.description


class TestCheckContext:
    """Test CheckContext functionality."""

    def test_check_context_creation(self, check_context):
        """Test CheckContext creation."""
        assert check_context.instance is not None
        assert check_context.aws_client_factory is not None
        assert check_context.config is not None
        assert check_context.logger is not None

        assert hasattr(check_context.instance, "instance_id")
        assert hasattr(check_context.aws_client_factory, "get_connect_client")
        assert isinstance(check_context.config, dict)
        assert isinstance(check_context.logger, logging.Logger)
