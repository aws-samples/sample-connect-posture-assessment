"""
Tests for AWS Client Factory functionality.

Tests credential validation, permission checking, and client creation
with proper error handling and retry logic.
"""

import os
from unittest.mock import Mock, patch

from botocore.exceptions import ClientError, NoCredentialsError

from amazon_connect_assessment.aws_client_factory import (
    AWSClientFactory,
    CredentialSource,
    CredentialValidationResult,
    PermissionValidationResult,
)


class TestAWSClientFactory:
    """Test cases for AWSClientFactory class."""

    def test_factory_initialization(self):
        """Test factory initialization with default parameters."""
        factory = AWSClientFactory()

        assert factory.region == "us-east-1"  # Default region
        assert factory.profile_name is None
        assert factory.session_name == "amazon-connect-assessment"
        assert factory.retry_config["retries"]["max_attempts"] == 5

    def test_factory_initialization_with_params(self):
        """Test factory initialization with custom parameters."""
        factory = AWSClientFactory(
            region="us-west-2",
            profile_name="test-profile",
            session_name="test-session",
            retry_config={"retries": {"max_attempts": 5}},
        )

        assert factory.region == "us-west-2"
        assert factory.profile_name == "test-profile"
        assert factory.session_name == "test-session"
        assert factory.retry_config["retries"]["max_attempts"] == 5

    @patch("amazon_connect_assessment.aws_client_factory.boto3.Session")
    def test_get_session_default(self, mock_session_class):
        """Test session creation with default credentials."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        factory = AWSClientFactory(region="us-east-1")
        session = factory.get_session()

        assert session == mock_session
        mock_session_class.assert_called_once_with(region_name="us-east-1")

    @patch("amazon_connect_assessment.aws_client_factory.boto3.Session")
    def test_get_session_with_profile(self, mock_session_class):
        """Test session creation with AWS profile."""
        mock_session = Mock()
        mock_session_class.return_value = mock_session

        factory = AWSClientFactory(region="us-east-1", profile_name="test-profile")
        session = factory.get_session()

        assert session == mock_session
        mock_session_class.assert_called_once_with(
            profile_name="test-profile", region_name="us-east-1"
        )

    @patch("amazon_connect_assessment.aws_client_factory.boto3.Session")
    def test_get_client_creation(self, mock_session_class):
        """Test AWS client creation."""
        mock_session = Mock()
        mock_client = Mock()
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        factory = AWSClientFactory()
        client = factory.get_client("connect")

        assert client == mock_client
        mock_session.client.assert_called_once()

    @patch("amazon_connect_assessment.aws_client_factory.boto3.Session")
    def test_client_caching(self, mock_session_class):
        """Test that clients are cached properly."""
        mock_session = Mock()
        mock_client = Mock()
        mock_session.client.return_value = mock_client
        mock_session_class.return_value = mock_session

        factory = AWSClientFactory()

        # First call should create client
        client1 = factory.get_client("connect")
        # Second call should return cached client
        client2 = factory.get_client("connect")

        assert client1 == client2
        # Session.client should only be called once due to caching
        assert mock_session.client.call_count == 1

    @patch("amazon_connect_assessment.aws_client_factory.boto3.Session")
    def test_region_specific_clients_are_cached_separately(self, mock_session_class):
        mock_session = Mock()
        mock_session.client.side_effect = [Mock(name="default"), Mock(name="eu")]
        mock_session_class.return_value = mock_session

        factory = AWSClientFactory(region="us-east-1")

        default_client = factory.get_client("lex-models")
        regional_client = factory.get_client("lex-models", region_name="eu-west-1")
        regional_client_again = factory.get_client("lex-models", region_name="eu-west-1")

        assert default_client is not regional_client
        assert regional_client_again is regional_client
        assert mock_session.client.call_count == 2
        assert mock_session.client.call_args_list[1].kwargs["region_name"] == "eu-west-1"

    def test_convenience_client_methods(self):
        """Test convenience methods for getting specific clients."""
        factory = AWSClientFactory()

        with patch.object(factory, "get_client") as mock_get_client:
            factory.get_connect_client()
            mock_get_client.assert_called_with("connect")

            factory.get_cloudwatch_client()
            mock_get_client.assert_called_with("cloudwatch")

            factory.get_s3_client()
            mock_get_client.assert_called_with("s3")

            factory.get_sts_client()
            mock_get_client.assert_called_with("sts")

    @patch.dict(
        os.environ,
        {"AWS_ACCESS_KEY_ID": "test-key", "AWS_SECRET_ACCESS_KEY": "test-secret"},
    )
    @patch("amazon_connect_assessment.aws_client_factory.boto3.Session")
    def test_credential_validation_success(self, mock_session_class):
        """Test successful credential validation."""
        mock_session = Mock()
        mock_sts_client = Mock()
        mock_session.client.return_value = mock_sts_client
        mock_session_class.return_value = mock_session

        mock_sts_client.get_caller_identity.return_value = {
            "Account": "123456789012",
            "Arn": "arn:aws:iam::123456789012:user/test-user",
        }

        factory = AWSClientFactory()
        result = factory.validate_credentials()

        assert result.is_valid is True
        assert result.account_id == "123456789012"
        assert result.user_arn == "arn:aws:iam::123456789012:user/test-user"
        assert result.credential_source == CredentialSource.ENVIRONMENT_VARIABLES

    @patch("amazon_connect_assessment.aws_client_factory.boto3.Session")
    def test_credential_validation_no_credentials(self, mock_session_class):
        """Test credential validation with no credentials."""
        mock_session = Mock()
        mock_sts_client = Mock()
        mock_session.client.return_value = mock_sts_client
        mock_session_class.return_value = mock_session

        mock_sts_client.get_caller_identity.side_effect = NoCredentialsError()

        factory = AWSClientFactory()
        result = factory.validate_credentials()

        assert result.is_valid is False
        assert result.credential_source == CredentialSource.UNKNOWN
        assert "No valid AWS credentials found" in result.error_message

    @patch("amazon_connect_assessment.aws_client_factory.boto3.Session")
    def test_credential_validation_expired_token(self, mock_session_class):
        """Test credential validation with expired token."""
        mock_session = Mock()
        mock_sts_client = Mock()
        mock_session.client.return_value = mock_sts_client
        mock_session_class.return_value = mock_session

        error_response = {"Error": {"Code": "ExpiredToken"}}
        mock_sts_client.get_caller_identity.side_effect = ClientError(
            error_response, "GetCallerIdentity"
        )

        factory = AWSClientFactory()
        result = factory.validate_credentials()

        assert result.is_valid is False
        assert result.credential_source == CredentialSource.UNKNOWN
        assert "ExpiredToken" in result.error_message

    def test_determine_credential_source_environment(self):
        """Test credential source detection for environment variables."""
        with patch.dict(
            "os.environ", {"AWS_ACCESS_KEY_ID": "test", "AWS_SECRET_ACCESS_KEY": "test"}
        ):
            factory = AWSClientFactory()
            source = factory._determine_credential_source()
            assert source == CredentialSource.ENVIRONMENT_VARIABLES

    def test_determine_credential_source_cloudshell(self):
        """Test credential source detection for CloudShell."""
        with patch.dict("os.environ", {"CLOUDSHELL": "true"}):
            factory = AWSClientFactory()
            source = factory._determine_credential_source()
            assert source == CredentialSource.CLOUDSHELL

    def test_determine_credential_source_profile(self):
        """Test credential source detection for AWS profile."""
        factory = AWSClientFactory(profile_name="test-profile")
        source = factory._determine_credential_source()
        assert source == CredentialSource.AWS_PROFILE

    def test_clear_cache(self):
        """Test cache clearing functionality."""
        factory = AWSClientFactory()

        # Add some mock cached data
        factory._clients["connect"] = Mock()
        factory._session = Mock()
        factory._credential_validation = Mock()
        factory._permission_validation = Mock()

        factory.clear_cache()

        assert len(factory._clients) == 0
        assert factory._session is None
        assert factory._credential_validation is None
        assert factory._permission_validation is None

    def test_get_all_clients(self):
        """Test getting all commonly used clients."""
        factory = AWSClientFactory()

        with (
            patch.object(factory, "get_connect_client") as mock_connect,
            patch.object(factory, "get_cloudwatch_client") as mock_cloudwatch,
            patch.object(factory, "get_s3_client") as mock_s3,
            patch.object(factory, "get_sts_client") as mock_sts,
        ):
            mock_connect.return_value = "connect_client"
            mock_cloudwatch.return_value = "cloudwatch_client"
            mock_s3.return_value = "s3_client"
            mock_sts.return_value = "sts_client"

            clients = factory.get_all_clients()

            assert clients["connect"] == "connect_client"
            assert clients["cloudwatch"] == "cloudwatch_client"
            assert clients["s3"] == "s3_client"
            assert clients["sts"] == "sts_client"


class TestCredentialValidationResult:
    """Test cases for CredentialValidationResult dataclass."""

    def test_credential_validation_result_creation(self):
        """Test creating CredentialValidationResult."""
        result = CredentialValidationResult(
            is_valid=True,
            credential_source=CredentialSource.AWS_PROFILE,
            account_id="123456789012",
            user_arn="arn:aws:iam::123456789012:user/test",
        )

        assert result.is_valid is True
        assert result.credential_source == CredentialSource.AWS_PROFILE
        assert result.account_id == "123456789012"
        assert result.user_arn == "arn:aws:iam::123456789012:user/test"
        assert result.warnings == []  # Default empty list

    def test_credential_validation_result_with_warnings(self):
        """Test CredentialValidationResult with warnings."""
        warnings = ["Warning 1", "Warning 2"]
        result = CredentialValidationResult(
            is_valid=True,
            credential_source=CredentialSource.ENVIRONMENT_VARIABLES,
            warnings=warnings,
        )

        assert result.warnings == warnings


class TestPermissionValidationResult:
    """Test cases for PermissionValidationResult dataclass."""

    def test_permission_validation_result_creation(self):
        """Test creating PermissionValidationResult."""
        result = PermissionValidationResult(
            is_valid=False,
            missing_permissions=["connect:ListInstances"],
            error_message="Missing permissions",
        )

        assert result.is_valid is False
        assert result.missing_permissions == ["connect:ListInstances"]
        assert result.error_message == "Missing permissions"
        assert result.tested_permissions == []  # Default empty list

    def test_permission_validation_result_defaults(self):
        """Test PermissionValidationResult with default values."""
        result = PermissionValidationResult(is_valid=True)

        assert result.is_valid is True
        assert result.missing_permissions == []
        assert result.tested_permissions == []
        assert result.error_message is None


def test_ai_ops_factory_wrappers_use_exact_services_operations_and_parameter_casing():
    # Arrange
    factory = AWSClientFactory()
    connect_client = Mock(name="connect_client")
    qconnect_client = Mock(name="qconnect_client")
    bedrock_client = Mock(name="bedrock_client")
    factory.get_connect_client = Mock(return_value=connect_client)
    factory.get_qconnect_client = Mock(return_value=qconnect_client)
    factory.get_bedrock_client = Mock(return_value=bedrock_client)
    factory.call_api_with_resilience = Mock(return_value={})

    # Act
    factory.list_integration_associations_resilient(
        "instance-1", "WISDOM_ASSISTANT", NextToken="connect-token", MaxResults=100
    )
    factory.get_qconnect_knowledge_base_resilient("kb-1")
    factory.list_ai_guardrails_resilient("assistant-1", nextToken="guardrail-token", maxResults=100)
    factory.list_ai_prompts_resilient("assistant-1", nextToken="prompt-token", maxResults=100)
    factory.get_model_invocation_logging_configuration_resilient()
    factory.list_inference_profiles_resilient(
        typeEquals="SYSTEM_DEFINED", nextToken="profile-token", maxResults=100
    )

    # Assert
    calls = factory.call_api_with_resilience.call_args_list
    assert calls[0].args == (connect_client, "list_integration_associations", "connect")
    assert calls[0].kwargs == {
        "InstanceId": "instance-1",
        "IntegrationType": "WISDOM_ASSISTANT",
        "NextToken": "connect-token",
        "MaxResults": 100,
    }
    assert calls[1].args == (qconnect_client, "get_knowledge_base", "qconnect")
    assert calls[1].kwargs == {"knowledgeBaseId": "kb-1"}
    assert calls[2].args == (qconnect_client, "list_ai_guardrails", "qconnect")
    assert calls[2].kwargs["nextToken"] == "guardrail-token"
    assert calls[3].args == (qconnect_client, "list_ai_prompts", "qconnect")
    assert calls[3].kwargs["nextToken"] == "prompt-token"
    assert calls[4].args == (
        bedrock_client,
        "get_model_invocation_logging_configuration",
        "bedrock",
    )
    assert calls[5].args == (bedrock_client, "list_inference_profiles", "bedrock")
    assert calls[5].kwargs == {
        "typeEquals": "SYSTEM_DEFINED",
        "nextToken": "profile-token",
        "maxResults": 100,
    }
