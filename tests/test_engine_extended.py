"""
Extended engine coverage — validate_configuration, checkpoint logic, metadata.
"""

from unittest.mock import Mock

from amazon_connect_assessment.aws_client_factory import (
    AWSClientFactory,
    CredentialSource,
    CredentialValidationResult,
    PermissionValidationResult,
)
from amazon_connect_assessment.engine import AssessmentEngine


def _factory():
    f = Mock(spec=AWSClientFactory)
    f.validate_credentials.return_value = CredentialValidationResult(
        is_valid=True,
        credential_source=CredentialSource.ENVIRONMENT_VARIABLES,
        account_id="123456789012",
        user_arn="arn:aws:iam::123456789012:user/test",
    )
    f.validate_permissions.return_value = PermissionValidationResult(
        is_valid=True,
        missing_permissions=[],
        tested_permissions=["connect:ListInstances"],
    )
    return f


class TestEngineValidation:
    def test_validate_configuration_valid(self):
        engine = AssessmentEngine(_factory(), config={})
        result = engine.validate_configuration()
        assert result["is_valid"] is True
        assert result["aws_credentials"]["is_valid"] is True

    def test_validate_configuration_no_analyzers_warning(self):
        engine = AssessmentEngine(_factory(), config={})
        result = engine.validate_configuration()
        assert any("analyzer" in w.lower() for w in result["warnings"])

    def test_validate_configuration_invalid_credentials(self):
        f = _factory()
        f.validate_credentials.return_value = CredentialValidationResult(
            is_valid=False,
            credential_source=CredentialSource.UNKNOWN,
            error_message="No creds",
        )
        f.validate_permissions.return_value = PermissionValidationResult(
            is_valid=False, error_message="Cannot validate"
        )
        engine = AssessmentEngine(f, config={})
        result = engine.validate_configuration()
        assert result["is_valid"] is False


class TestEngineMetadata:
    def test_get_execution_environment_macos(self):
        engine = AssessmentEngine(_factory(), config={})
        env = engine._get_execution_environment()
        # Running on macOS in tests.
        assert "macOS" in env or "Darwin" in env or "Linux" in env

    def test_get_tool_version(self):
        engine = AssessmentEngine(_factory(), config={})
        version = engine._get_tool_version()
        assert version  # Non-empty string.

    def test_get_assessment_statistics(self):
        engine = AssessmentEngine(_factory(), config={})
        stats = engine.get_assessment_statistics()
        assert "assessment_id" in stats
        assert "registered_checks_count" in stats

    def test_clear_execution_errors(self):
        engine = AssessmentEngine(_factory(), config={})
        engine._execution_errors.append("test error")
        engine.clear_execution_errors()
        assert engine.get_execution_errors() == []


class TestEngineCheckpoints:
    def test_enable_disable_checkpoints(self):
        engine = AssessmentEngine(_factory(), config={})
        engine.enable_checkpoints(False)
        assert engine._checkpoint_enabled is False
        engine.enable_checkpoints(True)
        assert engine._checkpoint_enabled is True

    def test_resume_no_checkpoint_returns_none(self):
        engine = AssessmentEngine(_factory(), config={}, checkpoint_dir="/tmp")
        result = engine.resume_assessment("nonexistent-id-xyz")
        assert result is None
