"""
Unit tests for the assessment engine.

Tests the core assessment orchestration functionality including
instance discovery, component analysis, check execution, progress tracking,
and checkpoint recovery.
"""

import json
import os
import uuid
from dataclasses import replace
from unittest.mock import Mock, mock_open, patch

from amazon_connect_assessment.checks import CheckRegistry
from amazon_connect_assessment.engine import AssessmentEngine
from amazon_connect_assessment.models import AssessmentResult, ConnectInstance


class TestAssessmentEngine:
    """Test AssessmentEngine functionality."""

    def test_engine_initialization(self, mock_aws_client_factory, sample_config):
        """Test assessment engine initialization."""
        engine = AssessmentEngine(mock_aws_client_factory, sample_config)

        assert engine.aws_client_factory == mock_aws_client_factory
        assert engine.config == sample_config
        assert isinstance(engine.check_registry, CheckRegistry)
        assert isinstance(engine.analyzers, list)
        assert len(engine.analyzers) == 0
        assert engine.progress_callback is None
        assert engine._checkpoint_enabled is True
        assert engine._current_step == 0
        assert engine._total_steps == 0

    def test_engine_initialization_with_progress_callback(
        self, mock_aws_client_factory, sample_config
    ):
        """Test assessment engine initialization with progress callback."""
        callback = Mock()
        checkpoint_dir = "/tmp/test_checkpoints"

        engine = AssessmentEngine(
            mock_aws_client_factory,
            sample_config,
            progress_callback=callback,
            checkpoint_dir=checkpoint_dir,
        )

        assert engine.progress_callback == callback
        assert engine.checkpoint_dir == checkpoint_dir

    def test_add_analyzer(self, assessment_engine):
        """Test adding analyzers to the engine."""
        mock_analyzer = Mock()
        assessment_engine.add_analyzer(mock_analyzer)

        assert len(assessment_engine.analyzers) == 1
        assert assessment_engine.analyzers[0] == mock_analyzer

    @patch("amazon_connect_assessment.engine.uuid.uuid4")
    def test_discover_instances(self, mock_uuid, assessment_engine):
        """Test Connect instance discovery."""
        # Mock UUID generation
        mock_uuid.return_value = uuid.UUID("12345678-1234-5678-9012-123456789012")

        # Mock AWS client factory resilient methods
        assessment_engine.aws_client_factory.list_connect_instances_resilient.return_value = {
            "InstanceSummaryList": [{"Id": "instance-123"}, {"Id": "instance-456"}]
        }

        assessment_engine.aws_client_factory.describe_connect_instance_resilient.side_effect = [
            {
                "Instance": {
                    "Id": "instance-123",
                    "Arn": "arn:aws:connect:us-east-1:123456789012:instance/instance-123",
                    "IdentityManagementType": "CONNECT_MANAGED",
                    "InboundCallsEnabled": True,
                    "OutboundCallsEnabled": False,
                    "InstanceAlias": "test-instance-1",
                    "ServiceRole": "arn:aws:iam::123456789012:role/ConnectRole",
                    "InstanceStatus": "ACTIVE",
                }
            },
            {
                "Instance": {
                    "Id": "instance-456",
                    "Arn": "arn:aws:connect:us-east-1:123456789012:instance/instance-456",
                    "IdentityManagementType": "SAML",
                    "InboundCallsEnabled": True,
                    "OutboundCallsEnabled": True,
                    "InstanceAlias": "test-instance-2",
                    "InstanceStatus": "ACTIVE",
                }
            },
        ]

        instances = assessment_engine.discover_instances()

        assert len(instances) == 2
        assert all(isinstance(instance, ConnectInstance) for instance in instances)
        assert instances[0].instance_id == "instance-123"
        assert instances[1].instance_id == "instance-456"
        assert instances[0].inbound_calls_enabled is True
        assert instances[0].outbound_calls_enabled is False
        assert instances[1].inbound_calls_enabled is True
        assert instances[1].outbound_calls_enabled is True

    def test_discover_instances_empty(self, assessment_engine):
        """Test instance discovery with no instances."""
        assessment_engine.aws_client_factory.list_connect_instances_resilient.return_value = {
            "InstanceSummaryList": []
        }

        instances = assessment_engine.discover_instances()

        assert len(instances) == 0
        assert isinstance(instances, list)

    def test_analyze_instance(self, assessment_engine, sample_connect_instance):
        """Test instance analysis with analyzers."""
        # Create mock analyzers
        analyzer1 = Mock()
        analyzer1.safe_analyze.return_value = sample_connect_instance

        analyzer2 = Mock()
        analyzer2.safe_analyze.return_value = sample_connect_instance

        assessment_engine.add_analyzer(analyzer1)
        assessment_engine.add_analyzer(analyzer2)

        result = assessment_engine.analyze_instance(sample_connect_instance)

        assert result == sample_connect_instance
        analyzer1.safe_analyze.assert_called_once_with(sample_connect_instance)
        analyzer2.safe_analyze.assert_called_once_with(sample_connect_instance)

    def test_analyze_instance_no_analyzers(self, assessment_engine, sample_connect_instance):
        """Test instance analysis with no analyzers."""
        result = assessment_engine.analyze_instance(sample_connect_instance)

        assert result == sample_connect_instance

    def test_execute_checks(self, assessment_engine, sample_connect_instance, mock_check):
        """Test check execution against an instance."""
        # Register a mock check
        assessment_engine.check_registry.register_check(mock_check)

        findings = assessment_engine.execute_checks(sample_connect_instance)

        assert len(findings) == 1
        assert findings[0].check_id == mock_check.check_id
        assert findings[0].resource_id == sample_connect_instance.instance_id

    def test_execute_checks_no_checks(self, assessment_engine, sample_connect_instance):
        """Test check execution with no registered checks."""
        findings = assessment_engine.execute_checks(sample_connect_instance)

        assert len(findings) == 0
        assert isinstance(findings, list)

    def test_generate_summary(self, assessment_engine, sample_finding):
        """Test assessment summary generation."""
        # Create findings with different statuses and severities
        findings = [sample_finding]  # This is a FAIL finding with HIGH severity

        summary = assessment_engine._generate_summary(findings)

        assert summary.total_checks == 1
        assert summary.failed_checks == 1
        assert summary.passed_checks == 0
        assert summary.error_checks == 0
        assert summary.skipped_checks == 0
        assert summary.high_findings == 1
        assert summary.critical_findings == 0
        assert summary.medium_findings == 0
        assert summary.low_findings == 0
        assert summary.registered_checks == 1
        assert summary.journey_findings == 0

    def test_generate_summary_separates_journey_findings(self, assessment_engine, sample_finding):
        journey_finding = replace(sample_finding, check_id="journey-sec-001")

        summary = assessment_engine._generate_summary([sample_finding, journey_finding])

        assert summary.total_checks == 2
        assert summary.registered_checks == 1
        assert summary.journey_findings == 1

    def test_generate_metadata(self, assessment_engine):
        """Test assessment metadata generation."""
        assessment_engine._start_time = 1000.0

        with patch("time.time", return_value=1045.5):
            metadata = assessment_engine._generate_metadata()

        assert metadata.tool_version == "0.1.0"
        assert metadata.execution_time_seconds == 45.5
        assert metadata.aws_account_id == assessment_engine.config["account_id"]
        assert metadata.aws_region == assessment_engine.config["region"]
        assert isinstance(metadata.execution_environment, str)
        assert isinstance(metadata.python_version, str)

    def test_generate_metadata_reads_region_from_nested_aws_key(self, mock_aws_client_factory):
        """
        Regression test: the CLI stores region/profile under
        config["aws"]["region"] (see cli.ConfigurationManager and
        merge_cli_args_with_config), not at the top level. Before this
        fix, _generate_metadata only checked the top-level "region" key,
        so a real CLI run (or a config file using the documented
        aws.region structure) always produced aws_region: "unknown" in
        the report metadata even when the user passed --region or set
        aws.region in their config file.
        """
        config = {
            "aws": {"region": "eu-west-1", "account_id": "999999999999"},
            "global_settings": {"timeout": 300},
        }
        engine = AssessmentEngine(mock_aws_client_factory, config)
        engine._start_time = 1000.0
        # Force validate_credentials to not resolve an account id, so we
        # can isolate the config-based lookup path being tested.
        mock_aws_client_factory.validate_credentials.return_value = Mock(
            is_valid=False, account_id=None
        )

        with patch("time.time", return_value=1010.0):
            metadata = engine._generate_metadata()

        assert metadata.aws_region == "eu-west-1"
        assert metadata.aws_account_id == "999999999999"

    def test_generate_metadata_top_level_key_still_takes_precedence(self, mock_aws_client_factory):
        """Top-level config["region"]/config["account_id"] must keep working
        for any caller that still uses that older shape (e.g. existing
        tests, or a config assembled programmatically rather than via the
        CLI)."""
        config = {
            "region": "ap-southeast-2",
            "account_id": "111111111111",
            "aws": {"region": "us-west-2", "account_id": "222222222222"},
        }
        engine = AssessmentEngine(mock_aws_client_factory, config)
        engine._start_time = 1000.0

        with patch("time.time", return_value=1010.0):
            metadata = engine._generate_metadata()

        assert metadata.aws_region == "ap-southeast-2"
        assert metadata.aws_account_id == "111111111111"

    def test_generate_metadata_falls_back_to_unknown_when_neither_key_set(
        self, mock_aws_client_factory
    ):
        config = {"global_settings": {"timeout": 300}}
        engine = AssessmentEngine(mock_aws_client_factory, config)
        engine._start_time = 1000.0
        mock_aws_client_factory.validate_credentials.return_value = Mock(
            is_valid=False, account_id=None
        )

        with patch("time.time", return_value=1010.0):
            metadata = engine._generate_metadata()

        assert metadata.aws_region == "unknown"
        assert metadata.aws_account_id == "unknown"

    @patch("amazon_connect_assessment.engine.uuid.uuid4")
    def test_run_assessment_integration(self, mock_uuid, assessment_engine, mock_check):
        """Test complete assessment run integration."""
        # Mock UUID only. time.time() is intentionally left unmocked here:
        # the exact number and ordering of time.time() calls during a run is
        # an implementation detail (retries, rate limiting, logging, etc. can
        # all add calls), and pinning it made this test flaky across Python
        # versions/environments. The precise timing math is already covered,
        # without that ordering dependency, by test_generate_metadata below.
        mock_uuid.return_value = uuid.UUID("12345678-1234-5678-9012-123456789012")

        # Mock AWS client factory resilient methods
        assessment_engine.aws_client_factory.list_connect_instances_resilient.return_value = {
            "InstanceSummaryList": [{"Id": "instance-123"}]
        }
        assessment_engine.aws_client_factory.describe_connect_instance_resilient.return_value = {
            "Instance": {
                "Id": "instance-123",
                "Arn": "arn:aws:connect:us-east-1:123456789012:instance/instance-123",
                "IdentityManagementType": "CONNECT_MANAGED",
                "InboundCallsEnabled": True,
                "OutboundCallsEnabled": True,
                "InstanceStatus": "ACTIVE",
            }
        }

        # Register a check
        assessment_engine.check_registry.register_check(mock_check)

        result = assessment_engine.run_assessment()

        assert isinstance(result, AssessmentResult)
        assert result.assessment_id == "12345678-1234-5678-9012-123456789012"
        assert len(result.instances) == 1
        assert len(result.findings) == 1
        assert result.summary.total_checks == 1
        assert result.metadata.execution_time_seconds >= 0.0

    def test_enable_checkpoints(self, assessment_engine):
        """Test enabling and disabling checkpoint functionality."""
        # Test enabling
        assessment_engine.enable_checkpoints(True)
        assert assessment_engine._checkpoint_enabled is True

        # Test disabling
        assessment_engine.enable_checkpoints(False)
        assert assessment_engine._checkpoint_enabled is False

    def test_progress_tracking(self, assessment_engine):
        """Test progress tracking functionality."""
        callback = Mock()
        assessment_engine.progress_callback = callback
        assessment_engine._total_steps = 3

        # Test progress update
        assessment_engine._update_progress("Test step")

        assert assessment_engine._current_step == 1
        callback.assert_called_once_with("Test step", 1, 3)

    def test_progress_tracking_callback_failure(self, assessment_engine):
        """Test progress tracking with failing callback."""
        callback = Mock(side_effect=Exception("Callback failed"))
        assessment_engine.progress_callback = callback
        assessment_engine._total_steps = 3

        # Should not raise exception even if callback fails
        assessment_engine._update_progress("Test step")
        assert assessment_engine._current_step == 1

    def test_initialize_progress_tracking(self, assessment_engine):
        """Test progress tracking initialization."""
        assessment_engine._initialize_progress_tracking(2)

        # Should calculate steps: 1 discovery + 2 analysis + 2 checks + 1 finalization = 6
        assert assessment_engine._total_steps == 6
        assert assessment_engine._current_step == 1

    def test_save_checkpoint(self, assessment_engine, tmp_path):
        """Test checkpoint saving functionality."""
        assessment_engine._assessment_id = "test-id"
        assessment_engine._checkpoint_enabled = True
        assessment_engine.checkpoint_dir = str(tmp_path)

        checkpoint_data = {"phase": "test", "data": "value"}
        assessment_engine._save_checkpoint(checkpoint_data)

        checkpoint_file = tmp_path / "assessment_checkpoint_test-id.json"
        assert checkpoint_file.exists()

        import stat

        mode = checkpoint_file.stat().st_mode
        assert mode & stat.S_IRWXG == 0  # no group access
        assert mode & stat.S_IRWXO == 0  # no other access

        parsed_data = json.loads(checkpoint_file.read_text())
        assert parsed_data["phase"] == "test"
        assert parsed_data["data"] == "value"
        assert parsed_data["assessment_id"] == "test-id"

    @patch(
        "builtins.open",
        new_callable=mock_open,
        read_data='{"assessment_id": "test-id", "phase": "test"}',
    )
    @patch("os.path.exists", return_value=True)
    def test_load_checkpoint(self, mock_exists, mock_file, assessment_engine):
        """Test checkpoint loading functionality."""
        assessment_engine._checkpoint_enabled = True

        result = assessment_engine._load_checkpoint("test-id")

        assert result is not None
        assert result["assessment_id"] == "test-id"
        assert result["phase"] == "test"

    @patch("os.path.exists", return_value=False)
    def test_load_checkpoint_not_found(self, mock_exists, assessment_engine):
        """Test checkpoint loading when file doesn't exist."""
        assessment_engine._checkpoint_enabled = True

        result = assessment_engine._load_checkpoint("nonexistent-id")

        assert result is None

    def test_load_checkpoint_disabled(self, assessment_engine):
        """Test checkpoint loading when checkpoints are disabled."""
        assessment_engine._checkpoint_enabled = False

        result = assessment_engine._load_checkpoint("test-id")

        assert result is None

    @patch("os.remove")
    @patch("os.path.exists", return_value=True)
    def test_cleanup_checkpoint(self, mock_exists, mock_remove, assessment_engine):
        """Test checkpoint cleanup functionality."""
        assessment_engine._current_checkpoint_file = "/tmp/test_checkpoint.json"  # nosec B108

        assessment_engine._cleanup_checkpoint()

        mock_remove.assert_called_once_with("/tmp/test_checkpoint.json")

    def test_get_assessment_statistics(self, assessment_engine):
        """Test assessment statistics retrieval."""
        assessment_engine._assessment_id = "test-id"
        assessment_engine._current_step = 3
        assessment_engine._total_steps = 10
        assessment_engine._execution_errors = ["error1", "error2"]
        assessment_engine._start_time = 1000.0

        with patch("time.time", return_value=1045.0):
            stats = assessment_engine.get_assessment_statistics()

        assert stats["assessment_id"] == "test-id"
        assert stats["current_step"] == 3
        assert stats["total_steps"] == 10
        assert stats["progress_percentage"] == 30.0
        assert stats["execution_errors_count"] == 2
        assert stats["execution_time_seconds"] == 45.0

    def test_get_execution_errors(self, assessment_engine):
        """Test execution errors retrieval."""
        assessment_engine._execution_errors = ["error1", "error2"]

        errors = assessment_engine.get_execution_errors()

        assert errors == ["error1", "error2"]
        # Should return a copy, not the original list
        assert errors is not assessment_engine._execution_errors

    def test_clear_execution_errors(self, assessment_engine):
        """Test clearing execution errors."""
        assessment_engine._execution_errors = ["error1", "error2"]

        assessment_engine.clear_execution_errors()

        assert len(assessment_engine._execution_errors) == 0

    def test_validate_configuration_success(self, assessment_engine):
        """Test successful configuration validation."""
        # Mock successful credential and permission validation
        cred_result = Mock()
        cred_result.is_valid = True
        cred_result.credential_source.value = "environment_variables"
        cred_result.account_id = "123456789012"
        cred_result.error_message = None

        perm_result = Mock()
        perm_result.is_valid = True
        perm_result.missing_permissions = []
        perm_result.tested_permissions = ["connect:ListInstances"]
        perm_result.error_message = None

        assessment_engine.aws_client_factory.validate_credentials.return_value = cred_result
        assessment_engine.aws_client_factory.validate_permissions.return_value = perm_result

        # Add some analyzers and checks
        assessment_engine.add_analyzer(Mock())
        assessment_engine.check_registry.register_check(Mock(check_id="test-check"))

        result = assessment_engine.validate_configuration()

        assert result["is_valid"] is True
        assert len(result["errors"]) == 0
        assert result["aws_credentials"]["is_valid"] is True
        assert result["aws_permissions"]["is_valid"] is True

    def test_validate_configuration_invalid_credentials(self, assessment_engine):
        """Test configuration validation with invalid credentials."""
        cred_result = Mock()
        cred_result.is_valid = False
        cred_result.error_message = "No credentials found"

        perm_result = Mock()
        perm_result.is_valid = True
        perm_result.missing_permissions = []

        assessment_engine.aws_client_factory.validate_credentials.return_value = cred_result
        assessment_engine.aws_client_factory.validate_permissions.return_value = perm_result

        result = assessment_engine.validate_configuration()

        assert result["is_valid"] is False
        assert len(result["errors"]) == 1
        assert "Invalid AWS credentials" in result["errors"][0]

    def test_get_tool_version(self, assessment_engine):
        """Test tool version retrieval."""
        version = assessment_engine._get_tool_version()

        # Should return either the package version or fallback
        assert isinstance(version, str)
        assert len(version) > 0

    def test_enhanced_execution_environment_detection(self, assessment_engine):
        """Test enhanced execution environment detection."""
        with patch.dict(os.environ, {"AWS_LAMBDA_FUNCTION_NAME": "test-function"}):
            env = assessment_engine._get_execution_environment()
            assert "Lambda" in env

        with patch.dict(os.environ, {"CLOUDSHELL": "true"}):
            env = assessment_engine._get_execution_environment()
            assert "CloudShell" in env

        with patch.dict(os.environ, {"ECS_CONTAINER_METADATA_URI": "http://test"}):
            env = assessment_engine._get_execution_environment()
            assert "ECS" in env
