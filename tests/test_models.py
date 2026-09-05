"""
Unit tests for core data models.

Tests the data structures and enumerations used throughout
the Amazon Connect Assessment Tool.
"""

from datetime import datetime

from amazon_connect_assessment.models import (
    AssessmentMetadata,
    AssessmentResult,
    AssessmentSummary,
    CheckStatus,
    ConnectInstance,
    Finding,
    Pillar,
    Severity,
)


class TestEnumerations:
    """Test enumeration classes."""

    def test_pillar_values(self):
        """Test Pillar enumeration values."""
        assert Pillar.RESILIENCE.value == "resilience"
        assert Pillar.SECURITY.value == "security"
        assert Pillar.COST_OPTIMIZATION.value == "cost_optimization"

    def test_severity_values(self):
        """Test Severity enumeration values."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"

    def test_check_status_values(self):
        """Test CheckStatus enumeration values."""
        assert CheckStatus.PASS.value == "pass"
        assert CheckStatus.FAIL.value == "fail"
        assert CheckStatus.ERROR.value == "error"
        assert CheckStatus.SKIPPED.value == "skipped"
        # NOT_APPLICABLE is distinct from SKIPPED: the check evaluated and
        # determined it doesn't apply (e.g. ACGR sub-checks when ACGR isn't
        # configured), whereas SKIPPED means it couldn't be evaluated.
        assert CheckStatus.NOT_APPLICABLE.value == "not_applicable"


class TestFinding:
    """Test Finding data model."""

    def test_finding_creation(self):
        """Test basic Finding creation."""
        finding = Finding(
            check_id="test-001",
            check_name="Test Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            status=CheckStatus.FAIL,
            resource_id="resource-123",
            resource_type="ContactFlow",
            description="Test description",
            remediation="Test remediation",
        )

        assert finding.check_id == "test-001"
        assert finding.check_name == "Test Check"
        assert finding.pillar == Pillar.SECURITY
        assert finding.severity == Severity.HIGH
        assert finding.status == CheckStatus.FAIL
        assert finding.resource_id == "resource-123"
        assert finding.resource_type == "ContactFlow"
        assert finding.description == "Test description"
        assert finding.remediation == "Test remediation"
        assert isinstance(finding.evidence, dict)
        assert isinstance(finding.timestamp, datetime)

    def test_finding_with_evidence(self):
        """Test Finding creation with evidence."""
        evidence = {"config_value": "test", "expected": "production"}
        finding = Finding(
            check_id="test-002",
            check_name="Test Check",
            pillar=Pillar.RESILIENCE,
            severity=Severity.MEDIUM,
            status=CheckStatus.FAIL,
            resource_id="resource-456",
            resource_type="Queue",
            description="Test description",
            remediation="Test remediation",
            evidence=evidence,
        )

        assert finding.evidence == evidence
        assert finding.evidence["config_value"] == "test"


class TestConnectInstance:
    """Test ConnectInstance data model."""

    def test_connect_instance_creation(self):
        """Test basic ConnectInstance creation."""
        instance = ConnectInstance(
            instance_id="test-instance",
            instance_arn="arn:aws:connect:us-east-1:123456789012:instance/test-instance",
            identity_management_type="CONNECT_MANAGED",
            inbound_calls_enabled=True,
            outbound_calls_enabled=False,
        )

        assert instance.instance_id == "test-instance"
        assert "test-instance" in instance.instance_arn
        assert instance.identity_management_type == "CONNECT_MANAGED"
        assert instance.inbound_calls_enabled is True
        assert instance.outbound_calls_enabled is False
        assert isinstance(instance.contact_flows, list)
        assert isinstance(instance.queues, list)
        assert isinstance(instance.routing_profiles, list)
        assert isinstance(instance.users, list)
        assert isinstance(instance.security_profiles, list)
        assert isinstance(instance.integrations, list)

    def test_connect_instance_optional_fields(self):
        """Test ConnectInstance with optional fields."""
        instance = ConnectInstance(
            instance_id="test-instance",
            instance_arn="arn:aws:connect:us-east-1:123456789012:instance/test-instance",
            identity_management_type="SAML",
            inbound_calls_enabled=True,
            outbound_calls_enabled=True,
            instance_alias="test-alias",
            service_role="arn:aws:iam::123456789012:role/ConnectRole",
            status="ACTIVE",
        )

        assert instance.instance_alias == "test-alias"
        assert instance.service_role == "arn:aws:iam::123456789012:role/ConnectRole"
        assert instance.status == "ACTIVE"


class TestAssessmentSummary:
    """Test AssessmentSummary data model."""

    def test_assessment_summary_creation(self):
        """Test AssessmentSummary creation."""
        summary = AssessmentSummary(
            total_checks=20,
            passed_checks=15,
            failed_checks=4,
            error_checks=1,
            skipped_checks=0,
            critical_findings=1,
            high_findings=2,
            medium_findings=1,
            low_findings=0,
        )

        assert summary.total_checks == 20
        assert summary.passed_checks == 15
        assert summary.failed_checks == 4
        assert summary.error_checks == 1
        assert summary.skipped_checks == 0
        assert summary.critical_findings == 1
        assert summary.high_findings == 2
        assert summary.medium_findings == 1
        assert summary.low_findings == 0

    def test_summary_totals_consistency(self):
        """Test that summary totals are consistent across every status."""
        summary = AssessmentSummary(
            total_checks=12,
            passed_checks=6,
            failed_checks=3,
            error_checks=1,
            skipped_checks=0,
            not_applicable_checks=2,
            critical_findings=1,
            high_findings=2,
            medium_findings=0,
            low_findings=0,
        )

        # Total checks should equal sum of status counts, including N/A.
        status_sum = (
            summary.passed_checks
            + summary.failed_checks
            + summary.error_checks
            + summary.skipped_checks
            + summary.not_applicable_checks
        )
        assert summary.total_checks == status_sum

        # Findings should only count failed checks.
        findings_sum = (
            summary.critical_findings
            + summary.high_findings
            + summary.medium_findings
            + summary.low_findings
        )
        assert findings_sum == summary.failed_checks

    def test_not_applicable_defaults_to_zero(self):
        """AssessmentSummary must accept legacy constructors without N/A."""
        summary = AssessmentSummary(
            total_checks=5,
            passed_checks=5,
            failed_checks=0,
            error_checks=0,
            skipped_checks=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
        )
        # Field is defaulted so pre-existing callers keep working.
        assert summary.not_applicable_checks == 0


class TestAssessmentMetadata:
    """Test AssessmentMetadata data model."""

    def test_assessment_metadata_creation(self):
        """Test AssessmentMetadata creation."""
        metadata = AssessmentMetadata(
            tool_version="0.1.0",
            execution_time_seconds=45.7,
            aws_account_id="123456789012",
            aws_region="us-west-2",
            execution_environment="AWS CloudShell",
            python_version="3.12.7",
        )

        assert metadata.tool_version == "0.1.0"
        assert metadata.execution_time_seconds == 45.7
        assert metadata.aws_account_id == "123456789012"
        assert metadata.aws_region == "us-west-2"
        assert metadata.execution_environment == "AWS CloudShell"
        assert metadata.python_version == "3.12.7"


class TestAssessmentResult:
    """Test AssessmentResult data model."""

    def test_assessment_result_creation(
        self,
        sample_connect_instance,
        sample_finding,
        sample_assessment_summary,
        sample_assessment_metadata,
    ):
        """Test AssessmentResult creation."""
        result = AssessmentResult(
            assessment_id="test-assessment",
            timestamp=datetime.now(),
            account_id="123456789012",
            region="us-east-1",
            instances=[sample_connect_instance],
            findings=[sample_finding],
            summary=sample_assessment_summary,
            metadata=sample_assessment_metadata,
        )

        assert result.assessment_id == "test-assessment"
        assert isinstance(result.timestamp, datetime)
        assert result.account_id == "123456789012"
        assert result.region == "us-east-1"
        assert len(result.instances) == 1
        assert len(result.findings) == 1
        assert isinstance(result.summary, AssessmentSummary)
        assert isinstance(result.metadata, AssessmentMetadata)
        assert isinstance(result.execution_errors, list)

    def test_assessment_result_with_errors(
        self,
        sample_connect_instance,
        sample_finding,
        sample_assessment_summary,
        sample_assessment_metadata,
    ):
        """Test AssessmentResult with execution errors."""
        errors = ["Error 1", "Error 2"]
        result = AssessmentResult(
            assessment_id="test-assessment",
            timestamp=datetime.now(),
            account_id="123456789012",
            region="us-east-1",
            instances=[sample_connect_instance],
            findings=[sample_finding],
            summary=sample_assessment_summary,
            metadata=sample_assessment_metadata,
            execution_errors=errors,
        )

        assert result.execution_errors == errors
        assert len(result.execution_errors) == 2
