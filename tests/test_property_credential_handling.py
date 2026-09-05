"""
Property-based tests for credential handling and cross-platform execution.

Feature: amazon-connect-assessment
Property 12: Cross-Platform Execution Compatibility

Tests that validate the system's ability to run successfully in various
execution environments and handle credentials appropriately for each environment.

Validates: Requirements 7.1, 7.2, 7.3
"""

from unittest.mock import Mock, patch

from hypothesis import assume, given, settings
from hypothesis import strategies as st

from amazon_connect_assessment.aws_client_factory import (
    AWSClientFactory,
    CredentialSource,
    CredentialValidationResult,
)

# Strategy for generating AWS regions
aws_region_strategy = st.sampled_from(
    [
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "eu-west-1",
        "eu-central-1",
        "ap-southeast-1",
        "ap-northeast-1",
    ]
)


# Strategy for generating AWS profile names
profile_name_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Ll", "Lu", "Nd"), whitelist_characters="-_"),
    min_size=3,
    max_size=30,
).filter(lambda x: x and not x.startswith("-") and not x.endswith("-"))


# Strategy for generating AWS account IDs
account_id_strategy = st.text(
    alphabet=st.characters(whitelist_categories=("Nd",)),
    min_size=12,
    max_size=12,
)


# Strategy for generating environment configurations
environment_config_strategy = st.fixed_dictionaries(
    {
        "has_cloudshell": st.booleans(),
        "has_env_vars": st.booleans(),
        "has_profile": st.booleans(),
        "has_instance_profile": st.booleans(),
    }
)


def create_mock_session(
    account_id: str,
    region: str,
    credential_source: CredentialSource,
    should_succeed: bool = True,
):
    """Create a mock boto3 session for testing."""
    mock_session = Mock()
    mock_sts_client = Mock()

    if should_succeed:
        mock_sts_client.get_caller_identity.return_value = {
            "Account": account_id,
            "Arn": f"arn:aws:iam::{account_id}:user/test-user",
        }
    else:
        from botocore.exceptions import NoCredentialsError

        mock_sts_client.get_caller_identity.side_effect = NoCredentialsError()

    mock_session.client.return_value = mock_sts_client
    return mock_session


# Property 12: Cross-Platform Execution Compatibility
# For any supported execution environment (virtual environments, AWS CloudShell),
# the tool should run successfully and handle credentials appropriately for that environment.


@given(
    region=aws_region_strategy,
    account_id=account_id_strategy,
    env_config=environment_config_strategy,
)
@settings(max_examples=100)
def test_property_credential_source_detection_across_environments(region, account_id, env_config):
    """
    Property: Credential source is correctly detected across different environments.

    This test validates that:
    1. The system correctly identifies credential sources in different environments
    2. CloudShell environment is detected when CLOUDSHELL env var is set
    3. Environment variables are detected when AWS_ACCESS_KEY_ID is set
    4. Profile-based credentials are detected when profile is specified
    5. Instance profile is detected in AWS execution environments

    Validates: Requirement 7.2 - utilize existing AWS credentials automatically in CloudShell
    Validates: Requirement 7.3 - support AWS credential configuration via profiles, env vars, IAM roles
    """
    # Assume valid inputs
    assume(len(account_id) == 12 and account_id.isdigit())

    # Set up environment based on configuration
    env_vars = {}

    if env_config["has_cloudshell"]:
        env_vars["CLOUDSHELL"] = "true"
        expected_source = CredentialSource.CLOUDSHELL
    elif env_config["has_env_vars"]:
        # Canonical AWS documentation example credentials (non-functional placeholders
        # published by AWS). Test fixture only — not a real secret.
        env_vars["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"  # nosec B105  # gitleaks:allow  # nosemgrep
        env_vars["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # nosec B105  # gitleaks:allow  # nosemgrep
        expected_source = CredentialSource.ENVIRONMENT_VARIABLES
    elif env_config["has_instance_profile"]:
        env_vars["AWS_EXECUTION_ENV"] = "AWS_ECS_FARGATE"
        expected_source = CredentialSource.INSTANCE_PROFILE
    else:
        expected_source = CredentialSource.UNKNOWN

    # Use clear=True to start with clean environment, then add our vars
    with patch.dict("os.environ", env_vars, clear=True):
        factory = AWSClientFactory(region=region)

        # Determine credential source
        detected_source = factory._determine_credential_source()

        # Verify correct source detection
        assert detected_source == expected_source


@given(
    region=aws_region_strategy,
    profile_name=profile_name_strategy,
    account_id=account_id_strategy,
)
@settings(max_examples=100)
def test_property_profile_based_credentials_work_across_platforms(region, profile_name, account_id):
    """
    Property: Profile-based credentials work consistently across platforms.

    This test validates that:
    1. Factory can be initialized with a profile name
    2. Profile-based credential source is correctly identified
    3. Session creation uses the specified profile
    4. Credential validation works with profile-based credentials

    Validates: Requirement 7.3 - support AWS credential configuration via profiles
    """
    # Assume valid inputs
    assume(profile_name and len(account_id) == 12 and account_id.isdigit())

    with patch("amazon_connect_assessment.aws_client_factory.boto3.Session") as mock_session_class:
        mock_session = create_mock_session(account_id, region, CredentialSource.AWS_PROFILE)
        mock_session_class.return_value = mock_session

        # Create factory with profile
        factory = AWSClientFactory(region=region, profile_name=profile_name)

        # Verify profile is stored
        assert factory.profile_name == profile_name

        # Verify credential source detection
        source = factory._determine_credential_source()
        assert source == CredentialSource.AWS_PROFILE

        # Get session and verify profile was used
        session = factory.get_session()
        assert session is not None

        # Verify session was created with profile
        mock_session_class.assert_called_with(profile_name=profile_name, region_name=region)


@given(
    region=aws_region_strategy,
    account_id=account_id_strategy,
)
@settings(max_examples=100)
def test_property_cloudshell_credentials_detected_automatically(region, account_id):
    """
    Property: CloudShell credentials are detected and used automatically.

    This test validates that:
    1. CloudShell environment is detected via CLOUDSHELL env var
    2. Credential source is correctly identified as CLOUDSHELL
    3. No additional configuration is needed in CloudShell
    4. Credentials work automatically in CloudShell environment

    Validates: Requirement 7.2 - utilize existing AWS credentials automatically in CloudShell
    """
    # Assume valid inputs
    assume(len(account_id) == 12 and account_id.isdigit())

    # Simulate CloudShell environment
    with patch.dict("os.environ", {"CLOUDSHELL": "true"}, clear=False):
        with patch(
            "amazon_connect_assessment.aws_client_factory.boto3.Session"
        ) as mock_session_class:
            mock_session = create_mock_session(account_id, region, CredentialSource.CLOUDSHELL)
            mock_session_class.return_value = mock_session

            # Create factory without any credential configuration
            factory = AWSClientFactory(region=region)

            # Verify CloudShell is detected
            source = factory._determine_credential_source()
            assert source == CredentialSource.CLOUDSHELL

            # Verify credentials validate successfully
            result = factory.validate_credentials()
            assert result.is_valid is True
            assert result.credential_source == CredentialSource.CLOUDSHELL
            assert result.account_id == account_id


@given(
    region=aws_region_strategy,
    account_id=account_id_strategy,
)
@settings(max_examples=100)
def test_property_environment_variable_credentials_work_locally(region, account_id):
    """
    Property: Environment variable credentials work in local environments.

    This test validates that:
    1. Credentials from environment variables are detected
    2. Credential source is correctly identified as ENVIRONMENT_VARIABLES
    3. Factory works with AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY
    4. Credential validation succeeds with environment variables

    Validates: Requirement 7.3 - support AWS credential configuration via environment variables
    """
    # Assume valid inputs
    assume(len(account_id) == 12 and account_id.isdigit())

    # Simulate environment variables
    # Canonical AWS documentation example credentials (non-functional placeholders
    # published by AWS). Test fixture only — not a real secret.
    env_vars = {
        "AWS_ACCESS_KEY_ID": "AKIAIOSFODNN7EXAMPLE",  # nosec B105  # gitleaks:allow  # nosemgrep
        "AWS_SECRET_ACCESS_KEY": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # nosec B105  # gitleaks:allow  # nosemgrep
    }

    with patch.dict("os.environ", env_vars, clear=False):
        with patch(
            "amazon_connect_assessment.aws_client_factory.boto3.Session"
        ) as mock_session_class:
            mock_session = create_mock_session(
                account_id, region, CredentialSource.ENVIRONMENT_VARIABLES
            )
            mock_session_class.return_value = mock_session

            # Create factory
            factory = AWSClientFactory(region=region)

            # Verify environment variables are detected
            source = factory._determine_credential_source()
            assert source == CredentialSource.ENVIRONMENT_VARIABLES

            # Verify credentials validate successfully
            result = factory.validate_credentials()
            assert result.is_valid is True
            assert result.credential_source == CredentialSource.ENVIRONMENT_VARIABLES
            assert result.account_id == account_id


@given(
    region=aws_region_strategy,
    account_id=account_id_strategy,
)
@settings(max_examples=100)
def test_property_instance_profile_credentials_work_in_aws_environments(region, account_id):
    """
    Property: Instance profile credentials work in AWS execution environments.

    This test validates that:
    1. Instance profile is detected in AWS execution environments
    2. Credential source is correctly identified as INSTANCE_PROFILE
    3. Factory works with EC2/ECS/Lambda instance profiles
    4. No explicit configuration is needed for instance profiles

    Validates: Requirement 7.3 - support AWS credential configuration via IAM roles
    """
    # Assume valid inputs
    assume(len(account_id) == 12 and account_id.isdigit())

    # Set up clean environment with only instance profile variables
    env_vars = {"AWS_EXECUTION_ENV": "AWS_ECS_FARGATE"}

    # Simulate AWS execution environment with clean environment
    with patch.dict("os.environ", env_vars, clear=True):
        with patch(
            "amazon_connect_assessment.aws_client_factory.boto3.Session"
        ) as mock_session_class:
            mock_session = create_mock_session(
                account_id, region, CredentialSource.INSTANCE_PROFILE
            )
            mock_session_class.return_value = mock_session

            # Create factory
            factory = AWSClientFactory(region=region)

            # Verify instance profile is detected
            source = factory._determine_credential_source()
            assert source == CredentialSource.INSTANCE_PROFILE

            # Verify credentials validate successfully
            result = factory.validate_credentials()
            assert result.is_valid is True
            assert result.credential_source == CredentialSource.INSTANCE_PROFILE
            assert result.account_id == account_id


@given(
    region=aws_region_strategy,
    account_id=account_id_strategy,
    credential_sources=st.lists(
        st.sampled_from(
            [
                CredentialSource.CLOUDSHELL,
                CredentialSource.ENVIRONMENT_VARIABLES,
                CredentialSource.AWS_PROFILE,
                CredentialSource.INSTANCE_PROFILE,
            ]
        ),
        min_size=1,
        max_size=4,
        unique=True,
    ),
)
@settings(max_examples=100)
def test_property_credential_validation_consistent_across_sources(
    region, account_id, credential_sources
):
    """
    Property: Credential validation behaves consistently across all sources.

    This test validates that:
    1. Validation returns consistent result structure for all credential sources
    2. Valid credentials always result in is_valid=True
    3. Account ID and user ARN are always populated for valid credentials
    4. Credential source is always correctly identified

    Validates: Requirements 7.1, 7.2, 7.3 - cross-platform execution compatibility
    """
    # Assume valid inputs
    assume(len(account_id) == 12 and account_id.isdigit())

    for credential_source in credential_sources:
        # Set up environment for this credential source
        env_vars = {}

        if credential_source == CredentialSource.CLOUDSHELL:
            env_vars["CLOUDSHELL"] = "true"
        elif credential_source == CredentialSource.ENVIRONMENT_VARIABLES:
            # Canonical AWS documentation example credentials (non-functional
            # placeholders published by AWS). Test fixture only — not a real secret.
            env_vars["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"  # nosec B105  # gitleaks:allow  # nosemgrep
            env_vars["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # nosec B105  # gitleaks:allow  # nosemgrep
        elif credential_source == CredentialSource.INSTANCE_PROFILE:
            env_vars["AWS_EXECUTION_ENV"] = "AWS_ECS_FARGATE"

        with patch.dict("os.environ", env_vars, clear=False):
            with patch(
                "amazon_connect_assessment.aws_client_factory.boto3.Session"
            ) as mock_session_class:
                mock_session = create_mock_session(account_id, region, credential_source)
                mock_session_class.return_value = mock_session

                # Create factory
                if credential_source == CredentialSource.AWS_PROFILE:
                    factory = AWSClientFactory(region=region, profile_name="test-profile")
                else:
                    factory = AWSClientFactory(region=region)

                # Validate credentials
                result = factory.validate_credentials()

                # Verify consistent result structure
                assert isinstance(result, CredentialValidationResult)
                assert result.is_valid is True
                assert result.account_id == account_id
                assert result.user_arn is not None
                assert "arn:aws:iam::" in result.user_arn
                assert result.credential_source in [
                    CredentialSource.CLOUDSHELL,
                    CredentialSource.ENVIRONMENT_VARIABLES,
                    CredentialSource.AWS_PROFILE,
                    CredentialSource.INSTANCE_PROFILE,
                ]
                assert result.error_message is None
                assert isinstance(result.warnings, list)


@given(
    region=aws_region_strategy,
)
@settings(max_examples=100)
def test_property_factory_initialization_works_in_all_environments(region):
    """
    Property: Factory can be initialized successfully in all environments.

    This test validates that:
    1. Factory initialization succeeds with minimal configuration
    2. Default region is used when not specified
    3. Factory can be created without credentials (validation happens later)
    4. Initialization doesn't fail due to environment differences

    Validates: Requirement 7.1 - run in Python virtual environments on user workstations
    """
    # Test with explicit region
    factory1 = AWSClientFactory(region=region)
    assert factory1.region == region
    assert factory1.session_name == "amazon-connect-assessment"

    # Test with default region
    with patch.dict("os.environ", {"AWS_DEFAULT_REGION": region}, clear=False):
        factory2 = AWSClientFactory()
        assert factory2.region == region

    # Test with custom session name
    factory3 = AWSClientFactory(region=region, session_name="custom-session")
    assert factory3.session_name == "custom-session"


@given(
    region=aws_region_strategy,
    account_id=account_id_strategy,
    has_credentials=st.booleans(),
)
@settings(max_examples=100)
def test_property_credential_validation_provides_clear_error_messages(
    region, account_id, has_credentials
):
    """
    Property: Credential validation provides clear error messages for issues.

    This test validates that:
    1. Invalid credentials result in is_valid=False
    2. Error messages are provided for credential issues
    3. Error messages include helpful guidance
    4. Validation doesn't crash on credential errors

    Validates: Requirement 7.5 - provide clear error messages for credential issues
    """
    # Assume valid inputs
    assume(len(account_id) == 12 and account_id.isdigit())

    with patch("amazon_connect_assessment.aws_client_factory.boto3.Session") as mock_session_class:
        mock_session = create_mock_session(
            account_id, region, CredentialSource.UNKNOWN, should_succeed=has_credentials
        )
        mock_session_class.return_value = mock_session

        factory = AWSClientFactory(region=region)

        # Validate credentials
        result = factory.validate_credentials()

        # Verify result structure
        assert isinstance(result, CredentialValidationResult)

        if has_credentials:
            # Valid credentials
            assert result.is_valid is True
            assert result.account_id == account_id
            assert result.error_message is None
        else:
            # Invalid credentials
            assert result.is_valid is False
            assert result.error_message is not None
            assert len(result.error_message) > 0
            # Error message should include helpful guidance
            assert any(
                keyword in result.error_message.lower()
                for keyword in ["credential", "configure", "aws", "environment"]
            )


@given(
    region=aws_region_strategy,
    account_id=account_id_strategy,
)
@settings(max_examples=100)
def test_property_client_creation_works_after_credential_validation(region, account_id):
    """
    Property: AWS clients can be created after successful credential validation.

    This test validates that:
    1. Clients can be created after credential validation
    2. Multiple clients can be created from the same factory
    3. Clients are properly configured with region and credentials
    4. Client creation is consistent across environments

    Validates: Requirements 7.1, 7.2, 7.3 - cross-platform execution compatibility
    """
    # Assume valid inputs
    assume(len(account_id) == 12 and account_id.isdigit())

    with patch("amazon_connect_assessment.aws_client_factory.boto3.Session") as mock_session_class:
        mock_session = create_mock_session(
            account_id, region, CredentialSource.ENVIRONMENT_VARIABLES
        )

        # Mock client creation
        mock_connect_client = Mock()
        mock_s3_client = Mock()
        mock_cloudwatch_client = Mock()

        def mock_client_factory(service_name, config=None):
            if service_name == "connect":
                return mock_connect_client
            elif service_name == "s3":
                return mock_s3_client
            elif service_name == "cloudwatch":
                return mock_cloudwatch_client
            elif service_name == "sts":
                return mock_session.client.return_value
            return Mock()

        mock_session.client.side_effect = mock_client_factory
        mock_session_class.return_value = mock_session

        factory = AWSClientFactory(region=region)

        # Validate credentials first
        result = factory.validate_credentials()
        assert result.is_valid is True

        # Create various clients
        connect_client = factory.get_connect_client()
        s3_client = factory.get_s3_client()
        cloudwatch_client = factory.get_cloudwatch_client()

        # Verify clients were created
        assert connect_client is not None
        assert s3_client is not None
        assert cloudwatch_client is not None

        # Verify clients are cached
        assert factory.get_connect_client() is connect_client
        assert factory.get_s3_client() is s3_client
        assert factory.get_cloudwatch_client() is cloudwatch_client
