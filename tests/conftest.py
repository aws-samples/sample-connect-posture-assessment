"""
Pytest configuration and shared fixtures for Amazon Connect Assessment Tool tests.

Provides common test fixtures, mock configurations, and test utilities
used across different test modules.
"""

import logging as _logging
from datetime import datetime
from unittest.mock import Mock

import pytest

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks import BaseCheck, CheckContext, CheckRegistry
from amazon_connect_assessment.engine import AssessmentEngine
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


@pytest.fixture
def mock_aws_clients():
    """Provide mock AWS clients for testing."""
    return {
        "connect": Mock(),
        "cloudwatch": Mock(),
        "s3": Mock(),
        "lambda": Mock(),
        "lex": Mock(),
    }


@pytest.fixture
def mock_aws_client_factory(mock_aws_clients):
    """Provide a mock AWSClientFactory for testing."""
    factory = Mock(spec=AWSClientFactory)
    factory.get_connect_client.return_value = mock_aws_clients["connect"]
    factory.get_cloudwatch_client.return_value = mock_aws_clients["cloudwatch"]
    factory.get_s3_client.return_value = mock_aws_clients["s3"]
    factory.get_client.side_effect = lambda service: mock_aws_clients.get(service, Mock())
    factory.get_sts_client.return_value = mock_aws_clients.get("sts", Mock())

    # Add resilient API methods
    factory.list_connect_instances_resilient = Mock()
    factory.describe_connect_instance_resilient = Mock()
    factory.list_contact_flows_resilient = Mock()
    factory.list_queues_resilient = Mock()
    factory.get_cloudwatch_metrics_resilient = Mock()
    factory.get_s3_bucket_policy_resilient = Mock()
    factory.get_s3_bucket_encryption_resilient = Mock()
    factory.call_api_with_resilience = Mock()

    return factory


@pytest.fixture
def sample_config():
    """Provide sample configuration for testing."""
    return {
        "account_id": "123456789012",
        "region": "us-east-1",
        "log_level": "INFO",
        "timeout": 300,
    }


@pytest.fixture
def sample_connect_instance():
    """Provide a sample ConnectInstance for testing."""
    return ConnectInstance(
        instance_id="test-instance-123",
        instance_arn="arn:aws:connect:us-east-1:123456789012:instance/test-instance-123",
        identity_management_type="CONNECT_MANAGED",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
        instance_alias="test-instance",
        service_role="arn:aws:iam::123456789012:role/ConnectServiceRole",
        status="ACTIVE",
    )


@pytest.fixture
def sample_finding():
    """Provide a sample Finding for testing."""
    return Finding(
        check_id="test-check-001",
        check_name="Test Security Check",
        pillar=Pillar.SECURITY,
        severity=Severity.HIGH,
        status=CheckStatus.FAIL,
        resource_id="test-resource-123",
        resource_type="ContactFlow",
        description="Test finding description",
        remediation="Test remediation guidance",
        evidence={"test_key": "test_value"},
    )


@pytest.fixture
def sample_assessment_summary():
    """Provide a sample AssessmentSummary for testing."""
    return AssessmentSummary(
        total_checks=10,
        passed_checks=6,
        failed_checks=3,
        error_checks=1,
        skipped_checks=0,
        critical_findings=1,
        high_findings=2,
        medium_findings=0,
        low_findings=0,
    )


@pytest.fixture
def sample_assessment_metadata():
    """Provide a sample AssessmentMetadata for testing."""
    return AssessmentMetadata(
        tool_version="0.1.0",
        execution_time_seconds=45.5,
        aws_account_id="123456789012",
        aws_region="us-east-1",
        execution_environment="Test Environment",
        python_version="3.12.0",
    )


@pytest.fixture
def sample_assessment_result(
    sample_connect_instance,
    sample_finding,
    sample_assessment_summary,
    sample_assessment_metadata,
):
    """Provide a sample AssessmentResult for testing."""
    return AssessmentResult(
        assessment_id="test-assessment-456",
        timestamp=datetime.now(),
        account_id="123456789012",
        region="us-east-1",
        instances=[sample_connect_instance],
        findings=[sample_finding],
        summary=sample_assessment_summary,
        metadata=sample_assessment_metadata,
        execution_errors=[],
    )


class MockCheck(BaseCheck):
    """Mock check implementation for testing."""

    def __init__(self, check_id: str = "mock-check", status: CheckStatus = CheckStatus.PASS):
        super().__init__(
            check_id=check_id,
            name=f"Mock Check {check_id}",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description="Mock check for testing",
            remediation_template="Mock remediation guidance",
        )
        self.mock_status = status

    def execute(self, context: CheckContext) -> Finding:
        return self.create_finding(
            status=self.mock_status,
            resource_id=context.instance.instance_id,
            resource_type="ConnectInstance",
            description=f"Mock check result: {self.mock_status.value}",
        )


@pytest.fixture
def mock_check():
    """Provide a mock check for testing."""
    return MockCheck()


@pytest.fixture
def check_registry():
    """Provide a fresh CheckRegistry for testing."""
    return CheckRegistry()


@pytest.fixture
def assessment_engine(mock_aws_client_factory, sample_config):
    """Provide an AssessmentEngine for testing."""
    return AssessmentEngine(mock_aws_client_factory, sample_config)


@pytest.fixture
def check_context(sample_connect_instance, mock_aws_client_factory, sample_config):
    """Provide a CheckContext for testing."""
    import logging

    return CheckContext(
        instance=sample_connect_instance,
        aws_client_factory=mock_aws_client_factory,
        config=sample_config,
        logger=logging.getLogger("test"),
    )


# ---------------------------------------------------------------------------
# Phase 0 / Task 1.5 — Shared fixtures and builders for new check + parser work
#
# These helpers are consumed by all new check tests (Tasks 4-13) and parser
# tests (Phase 1). moto v5 exposes a single `mock_aws` decorator/context
# manager (the per-service decorators from v4 were removed), so all new
# AWS-mocking tests should use `from moto import mock_aws`.
# ---------------------------------------------------------------------------


@pytest.fixture
def aws_credentials(monkeypatch):
    """Set dummy AWS credentials so moto never touches real AWS."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def make_check_context(sample_connect_instance, mock_aws_client_factory, sample_config):
    """
    Factory fixture that builds a CheckContext, allowing per-test overrides.

    Usage:
        def test_x(make_check_context):
            ctx = make_check_context(instance=my_instance)
    """

    def _make(instance=None, aws_client_factory=None, config=None, logger=None):
        return CheckContext(
            instance=instance or sample_connect_instance,
            aws_client_factory=aws_client_factory or mock_aws_client_factory,
            config=config or sample_config,
            logger=logger or _logging.getLogger("test"),
        )

    return _make


# --- Contact flow JSON builders (shared by parser + flow-content check tests) ---


def build_contact_flow(
    actions,
    start_action=None,
    name="Test Flow",
    flow_type="CONTACT_FLOW",
    flow_id="flow-001",
):
    """
    Build a minimal Amazon Connect contact flow JSON document.

    `actions` is a list of action dicts (use build_action). `start_action`
    defaults to the first action's Identifier.
    """
    if start_action is None and actions:
        start_action = actions[0]["Identifier"]
    return {
        "Version": "2019-10-30",
        "Identifier": flow_id,
        "Name": name,
        "Type": flow_type,
        "StartAction": start_action or "",
        "Actions": actions,
        "Metadata": {},
    }


def build_action(
    identifier,
    action_type,
    parameters=None,
    next_action=None,
    errors=None,
    conditions=None,
):
    """
    Build a single contact flow action with optional transitions.

    - next_action: id for the default NextAction transition
    - errors: list of {"NextAction": id, "ErrorType": str}
    - conditions: list of {"NextAction": id, "Condition": {...}}
    """
    transitions = {}
    if next_action is not None:
        transitions["NextAction"] = next_action
    if errors is not None:
        transitions["Errors"] = errors
    if conditions is not None:
        transitions["Conditions"] = conditions
    return {
        "Identifier": identifier,
        "Type": action_type,
        "Parameters": parameters or {},
        "Transitions": transitions,
    }


@pytest.fixture
def contact_flow_builders():
    """Expose the contact flow builders to tests as a fixture."""
    return {"build_contact_flow": build_contact_flow, "build_action": build_action}


@pytest.fixture
def simple_linear_flow():
    """A small valid linear flow: entry → play prompt → disconnect."""
    return build_contact_flow(
        [
            build_action("a1", "MessageParticipant", {"Text": "Welcome"}, next_action="a2"),
            build_action("a2", "DisconnectParticipant"),
        ]
    )
