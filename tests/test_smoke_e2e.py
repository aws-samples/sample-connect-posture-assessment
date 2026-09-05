"""
End-to-end smoke test for the Amazon Connect Assessment Tool.

Runs the full pipeline (CLI → config → engine → checks → report generation)
against a fully mocked AWS environment to verify all components integrate correctly.
"""

import json
import os
import tempfile
from unittest.mock import Mock, patch

import pytest

from amazon_connect_assessment.cli import (
    ConfigurationManager,
    main,
)
from amazon_connect_assessment.engine import AssessmentEngine


@pytest.fixture
def mock_aws_environment(monkeypatch):
    """Set up fake AWS credentials so nothing touches real AWS."""
    monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
    monkeypatch.setenv("AWS_SECURITY_TOKEN", "testing")
    monkeypatch.setenv("AWS_SESSION_TOKEN", "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")


@pytest.fixture
def output_dir():
    """Provide a temporary output directory for reports."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


class TestFullPipelineSmoke:
    """Smoke test: full assessment pipeline with mocked AWS calls."""

    def test_full_assessment_produces_findings_and_report(self, mock_aws_environment, output_dir):
        """Run a complete assessment and verify outputs are generated."""
        instance_data = {
            "InstanceSummaryList": [
                {
                    "Id": "test-instance-001",
                    "Arn": "arn:aws:connect:us-east-1:123456789012:instance/test-instance-001",
                    "IdentityManagementType": "CONNECT_MANAGED",
                    "InstanceAlias": "smoke-test",
                    "InstanceStatus": "ACTIVE",
                    "InboundCallsEnabled": True,
                    "OutboundCallsEnabled": True,
                }
            ]
        }

        instance_detail = {
            "Instance": {
                "Id": "test-instance-001",
                "Arn": "arn:aws:connect:us-east-1:123456789012:instance/test-instance-001",
                "IdentityManagementType": "CONNECT_MANAGED",
                "InstanceAlias": "smoke-test",
                "InstanceStatus": "ACTIVE",
                "InboundCallsEnabled": True,
                "OutboundCallsEnabled": True,
                "ServiceRole": "arn:aws:iam::123456789012:role/ConnectServiceRole",
            }
        }

        # Build a mock factory that returns our fake data
        mock_factory = Mock()
        mock_factory.list_connect_instances_resilient.return_value = instance_data
        mock_factory.describe_connect_instance_resilient.return_value = instance_detail
        mock_factory.validate_credentials.return_value = Mock(
            is_valid=True,
            account_id="123456789012",
            credential_source=Mock(value="environment_variables"),
        )
        mock_factory.validate_permissions.return_value = Mock(
            is_valid=True,
            missing_permissions=[],
            tested_permissions=["connect:ListInstances"],
            error_message=None,
        )
        # Analyzers will call various list APIs — return empty lists
        mock_factory.call_api_with_resilience.return_value = {}
        mock_factory.get_client.return_value = Mock()
        mock_factory.get_connect_client.return_value = Mock(
            list_contact_flows=Mock(return_value={"ContactFlowSummaryList": []}),
            list_queues=Mock(return_value={"QueueSummaryList": []}),
            list_routing_profiles=Mock(return_value={"RoutingProfileSummaryList": []}),
            list_users=Mock(return_value={"UserSummaryList": []}),
            list_security_profiles=Mock(return_value={"SecurityProfileSummaryList": []}),
            list_lambda_functions=Mock(return_value={"LambdaFunctions": []}),
            list_lex_bots=Mock(return_value={"LexBots": []}),
            list_instance_storage_configs=Mock(return_value={"StorageConfigs": []}),
            list_approved_origins=Mock(return_value={"Origins": []}),
            describe_instance_attribute=Mock(return_value={"Attribute": {"Value": "true"}}),
        )
        mock_factory.list_contact_flows_resilient = Mock(
            return_value={"ContactFlowSummaryList": []}
        )
        mock_factory.list_queues_resilient = Mock(return_value={"QueueSummaryList": []})

        # Create engine with the mock factory
        config = {
            "account_id": "123456789012",
            "region": "us-east-1",
            "global_settings": {
                "parallel_execution": False,
                "timeout": 60,
                "retry_count": 1,
                "max_retry_attempts": 1,
                "retry_base_delay": 0.1,
                "retry_max_delay": 1.0,
                "enable_rate_limiting": False,
                "batch_size": 5,
                "log_level": "WARNING",
            },
            "enabled_pillars": ["resilience", "security", "cost_optimization"],
            "enabled_severities": ["critical", "high", "medium", "low"],
            "output": {
                "format": ["json"],
                "directory": output_dir,
            },
        }

        engine = AssessmentEngine(
            aws_client_factory=mock_factory,
            config=config,
        )

        # Register MVP checks at minimum
        from amazon_connect_assessment.checks.registration import register_all_checks

        register_all_checks(engine.check_registry)

        # Run assessment
        result = engine.run_assessment()

        # Verify we got a result
        assert result is not None
        assert result.assessment_id is not None
        assert result.account_id == "123456789012"
        assert result.region == "us-east-1"
        assert len(result.instances) == 1
        assert result.instances[0].instance_id == "test-instance-001"

        # Verify checks actually ran
        assert result.summary.total_checks > 0

        # Verify we can generate a JSON report from the result
        from amazon_connect_assessment.report_generator import ReportGenerator

        report_gen = ReportGenerator()
        json_path = report_gen.generate_json_report(result, output_dir)
        assert os.path.exists(json_path)

        with open(json_path) as f:
            report_data = json.load(f)
        assert "findings" in report_data or "assessment_id" in report_data


class TestCLIConfigurationSmoke:
    """Test that CLI configuration loading and merging works end-to-end."""

    def test_config_manager_loads_defaults(self):
        """ConfigurationManager produces valid defaults without a file."""
        manager = ConfigurationManager()
        config = manager.load_config(None)

        assert "global_settings" in config
        assert "enabled_pillars" in config
        assert config["global_settings"]["parallel_execution"] is True
        assert "resilience" in config["enabled_pillars"]
        assert "security" in config["enabled_pillars"]

    def test_config_validation_passes_on_defaults(self):
        """Default configuration should pass validation."""
        manager = ConfigurationManager()
        manager.load_config(None)
        errors = manager.validate_config()
        assert errors == []

    def test_cli_main_dry_run(self, mock_aws_environment, monkeypatch):
        """CLI --dry-run validates config and permissions without running assessment."""
        with patch("amazon_connect_assessment.cli.initialize_assessment_components") as mock_init:
            mock_engine = Mock()
            mock_engine.validate_configuration.return_value = {
                "is_valid": True,
                "errors": [],
                "warnings": [],
            }
            mock_init.return_value = (mock_engine, Mock(), Mock())

            monkeypatch.setattr(
                "sys.argv",
                ["amazon-connect-assessment", "--dry-run", "--region", "us-east-1"],
            )
            exit_code = main()
            assert exit_code == 0
