"""
AWS Client Factory for Amazon Connect Assessment Tool.

This module provides centralized AWS client management with credential validation,
permission checking, and enhanced retry logic for robust AWS service interactions.
"""

import logging
import os
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    NoCredentialsError,
    PartialCredentialsError,
    ProfileNotFound,
    TokenRetrievalError,
)

from .iam_permissions import REQUIRED_PERMISSIONS as _REQUIRED_PERMISSIONS
from .network_resilience import (
    ConnectivityError,
    NetworkResilienceError,
    NetworkResilienceManager,
    NetworkTimeoutError,
    RateLimitDetector,
    RateLimitExceededError,
    RetryConfig,
)


class CredentialSource(Enum):
    """Sources of AWS credentials.

    ``INSTANCE_PROFILE`` covers OIDC/federated roles resolved by the boto3
    provider chain (EC2 instance profile, Lambda execution role, ECS task
    role, GitHub Actions OIDC, etc.) — anywhere the caller comes in with a
    role already assumed rather than plain user credentials.
    """

    ENVIRONMENT_VARIABLES = "environment_variables"
    AWS_PROFILE = "aws_profile"
    INSTANCE_PROFILE = "instance_profile"
    CLOUDSHELL = "cloudshell"
    UNKNOWN = "unknown"


@dataclass
class CredentialValidationResult:
    """Result of credential validation process."""

    is_valid: bool
    credential_source: CredentialSource
    account_id: Optional[str] = None
    user_arn: Optional[str] = None
    error_message: Optional[str] = None
    warnings: List[str] = None

    def __post_init__(self):
        if self.warnings is None:
            self.warnings = []


@dataclass
class PermissionValidationResult:
    """Result of permission validation process."""

    is_valid: bool
    missing_permissions: List[str] = None
    error_message: Optional[str] = None
    tested_permissions: List[str] = None

    def __post_init__(self):
        if self.missing_permissions is None:
            self.missing_permissions = []
        if self.tested_permissions is None:
            self.tested_permissions = []


class AWSClientFactory:
    """
    Factory for creating and managing AWS service clients.

    Provides centralized credential management, permission validation,
    enhanced retry configuration, and network resilience for all AWS service interactions.
    """

    # Minimal permissions probed by ``--check-permissions``. Sourced from the
    # single source of truth in iam_permissions.py so the smoke-test list, the
    # standalone JSON policy, and the CloudFormation role can never drift apart.
    REQUIRED_PERMISSIONS = _REQUIRED_PERMISSIONS

    def __init__(
        self,
        region: str = None,
        profile_name: str = None,
        session_name: str = None,
        retry_config: Dict[str, Any] = None,
        network_resilience_config: RetryConfig = None,
        enable_rate_limiting: bool = True,
        operation_timeout: float = 30.0,
    ):
        """
        Initialize the AWS client factory.

        The factory uses whatever credentials boto3's default provider chain
        discovers — environment variables, an AWS profile, CloudShell,
        instance profile, or an OIDC/federated role that has already been
        resolved into the environment. The factory does not itself perform
        role assumption.

        Args:
            region: AWS region to use (defaults to environment or us-east-1)
            profile_name: AWS profile name to use
            session_name: Session name label (retained for logging purposes)
            retry_config: Custom retry configuration for boto3
            network_resilience_config: Configuration for network resilience features
            enable_rate_limiting: Whether to enable rate limit detection and throttling
            operation_timeout: Default timeout for operations in seconds
        """
        self.logger = logging.getLogger("aws_client_factory")

        # Configuration
        self.region = region or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
        self.profile_name = profile_name
        self.session_name = session_name or "amazon-connect-assessment"
        self.operation_timeout = operation_timeout

        # Enhanced retry configuration with exponential backoff
        default_retry_config = {
            "retries": {
                "max_attempts": 5,
                "mode": "adaptive",
            },
            "max_pool_connections": 50,
            "connect_timeout": 10,
            "read_timeout": operation_timeout,
        }
        self.retry_config = {**default_retry_config, **(retry_config or {})}

        # Network resilience configuration
        default_network_config = RetryConfig(
            max_attempts=5,
            base_delay=1.0,
            max_delay=60.0,
            exponential_base=2.0,
            jitter=True,
            timeout_seconds=operation_timeout,
        )
        self.network_resilience_config = network_resilience_config or default_network_config
        self.network_resilience_manager = NetworkResilienceManager(
            config=self.network_resilience_config, logger=self.logger
        )

        # Rate limiting
        self.enable_rate_limiting = enable_rate_limiting
        self.rate_limit_detector = (
            RateLimitDetector(logger=self.logger) if enable_rate_limiting else None
        )

        # Client cache. ParallelAssessmentEngine executes checks across a
        # thread pool, and every check for every instance shares this one
        # AWSClientFactory — so get_session()/get_client() need to be
        # thread-safe. See the lock usage in each method below.
        self._clients: Dict[str, Any] = {}
        self._session: Optional[boto3.Session] = None
        self._credential_validation: Optional[CredentialValidationResult] = None
        self._permission_validation: Optional[PermissionValidationResult] = None
        self._session_lock = threading.Lock()
        self._clients_lock = threading.Lock()

    def get_session(self) -> boto3.Session:
        """
        Get or create a boto3 session with appropriate credentials.

        Thread-safe: guarded by ``_session_lock`` so concurrent first-touch
        from multiple worker threads (ParallelAssessmentEngine) can't race
        to create two sessions or observe a partially-constructed one.
        boto3.Session() itself is not documented as thread-safe to
        construct concurrently, and botocore internals have been observed
        to raise intermittently under concurrent first-use without this
        guard.

        Returns:
            boto3.Session: Configured session

        Raises:
            Exception: If session creation fails
        """
        # Fast path: avoid taking the lock on every call once the session
        # already exists (the overwhelmingly common case).
        if self._session is not None:
            return self._session

        with self._session_lock:
            # Re-check inside the lock: another thread may have finished
            # creating the session while we were waiting for it.
            if self._session is not None:
                return self._session

            try:
                # Create session based on configuration
                if self.profile_name:
                    self._session = self._create_profile_session()
                else:
                    self._session = self._create_default_session()

                self.logger.info(f"Created AWS session for region: {self.region}")
                return self._session

            except Exception as e:
                error_msg = f"Failed to create AWS session: {str(e)}"
                self.logger.error(error_msg)
                raise Exception(error_msg) from e

    def _create_default_session(self) -> boto3.Session:
        """Create session using default credential chain."""
        return boto3.Session(region_name=self.region)

    def _create_profile_session(self) -> boto3.Session:
        """Create session using specified AWS profile."""
        try:
            return boto3.Session(profile_name=self.profile_name, region_name=self.region)
        except ProfileNotFound as e:
            raise Exception(f"AWS profile '{self.profile_name}' not found: {str(e)}")

    def get_client(self, service_name: str, region_name: Optional[str] = None) -> Any:
        """
        Get or create an AWS service client with enhanced retry configuration.

        Thread-safe: guarded by ``_clients_lock``. Without this, two worker
        threads racing to first-touch the same service (a common shape —
        e.g. two IAM-related checks scheduled into the same parallel batch)
        both see ``service_name not in self._clients``, both call
        ``session.client(...)`` concurrently, and botocore's internal
        client/model-loading machinery is not guaranteed safe against that,
        which has been observed to raise intermittently and surface as a
        spurious ERROR finding instead of a real check result.

        Args:
            service_name: AWS service name (e.g., 'connect', 's3', 'cloudwatch')
            region_name: Optional region override. Region-specific clients use
                a separate cache entry.

        Returns:
            AWS service client

        Raises:
            Exception: If client creation fails
        """
        cache_key = service_name if region_name is None else f"{service_name}:{region_name}"

        # Fast path without the lock for the common "already cached" case.
        if cache_key in self._clients:
            return self._clients[cache_key]

        with self._clients_lock:
            # Re-check inside the lock — another thread may have created
            # this client while we were waiting.
            if cache_key in self._clients:
                return self._clients[cache_key]

            try:
                session = self.get_session()
                config = Config(**self.retry_config)

                client_kwargs = {"config": config}
                if region_name is not None:
                    client_kwargs["region_name"] = region_name
                client = session.client(service_name, **client_kwargs)
                self._clients[cache_key] = client

                client_region = region_name or self.region
                self.logger.debug(f"Created {service_name} client for region {client_region}")
                return client

            except Exception as e:
                error_msg = f"Failed to create {service_name} client: {str(e)}"
                self.logger.error(error_msg)
                raise Exception(error_msg) from e

    def call_api_with_resilience(
        self, client: Any, operation_name: str, service_name: str = None, **kwargs
    ) -> Any:
        """
        Call an AWS API operation with network resilience and rate limiting.

        Args:
            client: AWS service client
            operation_name: Name of the API operation
            service_name: Name of the AWS service (for rate limiting)
            **kwargs: Arguments to pass to the API operation

        Returns:
            API response

        Raises:
            NetworkResilienceError: If operation fails after all retries
        """
        service_name = service_name or getattr(
            getattr(client, "_service_model", None), "service_name", None
        )

        def api_operation():
            # Check rate limiting if enabled
            if self.rate_limit_detector and service_name:
                if self.rate_limit_detector.should_throttle(service_name, operation_name):
                    delay = self.rate_limit_detector.get_throttle_delay(
                        service_name, operation_name
                    )
                    self.logger.debug(f"Rate limiting: delaying {operation_name} by {delay:.2f}s")
                    time.sleep(delay)

                # Record the API call
                self.rate_limit_detector.record_api_call(service_name, operation_name)

            # Execute the API call
            operation = getattr(client, operation_name)
            return operation(**kwargs)

        operation_description = (
            f"{service_name}:{operation_name}" if service_name else operation_name
        )
        return self.network_resilience_manager.execute_with_retry(
            api_operation, operation_description
        )

    def list_connect_instances_resilient(self, **kwargs) -> Dict[str, Any]:
        """List Connect instances with network resilience."""
        client = self.get_connect_client()
        return self.call_api_with_resilience(client, "list_instances", "connect", **kwargs)

    def describe_connect_instance_resilient(self, instance_id: str, **kwargs) -> Dict[str, Any]:
        """Describe Connect instance with network resilience."""
        client = self.get_connect_client()
        return self.call_api_with_resilience(
            client, "describe_instance", "connect", InstanceId=instance_id, **kwargs
        )

    def list_contact_flows_resilient(self, instance_id: str, **kwargs) -> Dict[str, Any]:
        """List contact flows with network resilience."""
        client = self.get_connect_client()
        return self.call_api_with_resilience(
            client, "list_contact_flows", "connect", InstanceId=instance_id, **kwargs
        )

    def list_queues_resilient(self, instance_id: str, **kwargs) -> Dict[str, Any]:
        """List queues with network resilience."""
        client = self.get_connect_client()
        return self.call_api_with_resilience(
            client, "list_queues", "connect", InstanceId=instance_id, **kwargs
        )

    def get_cloudwatch_metrics_resilient(self, **kwargs) -> Dict[str, Any]:
        """Get CloudWatch metrics with network resilience."""
        client = self.get_cloudwatch_client()
        return self.call_api_with_resilience(
            client, "get_metric_statistics", "cloudwatch", **kwargs
        )

    def get_s3_bucket_policy_resilient(self, bucket_name: str, **kwargs) -> Dict[str, Any]:
        """Get S3 bucket policy with network resilience."""
        client = self.get_s3_client()
        return self.call_api_with_resilience(
            client, "get_bucket_policy", "s3", Bucket=bucket_name, **kwargs
        )

    def get_s3_bucket_encryption_resilient(self, bucket_name: str, **kwargs) -> Dict[str, Any]:
        """Get S3 bucket encryption with network resilience."""
        client = self.get_s3_client()
        return self.call_api_with_resilience(
            client, "get_bucket_encryption", "s3", Bucket=bucket_name, **kwargs
        )

    def get_connect_client(self) -> Any:
        """Get Amazon Connect client."""
        return self.get_client("connect")

    def get_cloudwatch_client(self) -> Any:
        """Get CloudWatch client."""
        return self.get_client("cloudwatch")

    def get_s3_client(self) -> Any:
        """Get S3 client."""
        return self.get_client("s3")

    def get_sts_client(self) -> Any:
        """Get STS client."""
        return self.get_client("sts")

    def get_iam_client(self) -> Any:
        """Get IAM client."""
        return self.get_client("iam")

    def get_cloudtrail_client(self) -> Any:
        """Get CloudTrail client."""
        return self.get_client("cloudtrail")

    def get_lambda_client(self) -> Any:
        """Get AWS Lambda client."""
        return self.get_client("lambda")

    def get_lex_client(self) -> Any:
        """Get the Amazon Lex (V1) client used for get_bot details."""
        return self.get_client("lex-models")

    def get_lex_v2_client(self) -> Any:
        """Get the Amazon Lex V2 control-plane client."""
        return self.get_client("lexv2-models")

    def get_qconnect_client(self) -> Any:
        """Get the Amazon Q in Connect (qconnect) client."""
        return self.get_client("qconnect")

    def get_bedrock_client(self) -> Any:
        """Get the Amazon Bedrock control-plane client."""
        return self.get_client("bedrock")

    # -- Resilient wrappers for deep-inspection checks (Phase 2/3/4) --------

    def describe_alarms_resilient(self, **kwargs) -> Dict[str, Any]:
        """Describe CloudWatch alarms with network resilience."""
        client = self.get_cloudwatch_client()
        return self.call_api_with_resilience(client, "describe_alarms", "cloudwatch", **kwargs)

    def describe_trails_resilient(self, **kwargs) -> Dict[str, Any]:
        """Describe CloudTrail trails with network resilience."""
        client = self.get_cloudtrail_client()
        return self.call_api_with_resilience(client, "describe_trails", "cloudtrail", **kwargs)

    def get_trail_event_selectors_resilient(self, trail_name: str) -> Dict[str, Any]:
        """Get CloudTrail event selectors for a trail with network resilience."""
        client = self.get_cloudtrail_client()
        return self.call_api_with_resilience(
            client, "get_event_selectors", "cloudtrail", TrailName=trail_name
        )

    def get_role_resilient(self, role_name: str) -> Dict[str, Any]:
        """Get an IAM role with network resilience."""
        client = self.get_iam_client()
        return self.call_api_with_resilience(client, "get_role", "iam", RoleName=role_name)

    def list_attached_role_policies_resilient(self, role_name: str) -> Dict[str, Any]:
        """List attached managed policies for an IAM role with resilience."""
        client = self.get_iam_client()
        return self.call_api_with_resilience(
            client, "list_attached_role_policies", "iam", RoleName=role_name
        )

    def list_role_policies_resilient(self, role_name: str) -> Dict[str, Any]:
        """List inline policy names for an IAM role with resilience."""
        client = self.get_iam_client()
        return self.call_api_with_resilience(
            client, "list_role_policies", "iam", RoleName=role_name
        )

    def get_role_policy_resilient(self, role_name: str, policy_name: str) -> Dict[str, Any]:
        """Get an inline IAM role policy document with resilience."""
        client = self.get_iam_client()
        return self.call_api_with_resilience(
            client,
            "get_role_policy",
            "iam",
            RoleName=role_name,
            PolicyName=policy_name,
        )

    def get_policy_version_resilient(self, policy_arn: str, version_id: str) -> Dict[str, Any]:
        """Get a managed policy version document with resilience."""
        client = self.get_iam_client()
        return self.call_api_with_resilience(
            client,
            "get_policy_version",
            "iam",
            PolicyArn=policy_arn,
            VersionId=version_id,
        )

    def get_lambda_function_resilient(self, function_name: str) -> Dict[str, Any]:
        """Get a Lambda function (config + role) with network resilience."""
        client = self.get_lambda_client()
        return self.call_api_with_resilience(
            client, "get_function", "lambda", FunctionName=function_name
        )

    def describe_queue_resilient(self, instance_id: str, queue_id: str) -> Dict[str, Any]:
        """Describe an Amazon Connect queue with network resilience."""
        client = self.get_connect_client()
        return self.call_api_with_resilience(
            client,
            "describe_queue",
            "connect",
            InstanceId=instance_id,
            QueueId=queue_id,
        )

    def describe_lex_v2_bot_resilient(self, bot_id: str) -> Dict[str, Any]:
        """Describe a Lex V2 bot with network resilience."""
        client = self.get_lex_v2_client()
        return self.call_api_with_resilience(client, "describe_bot", "lexv2-models", botId=bot_id)

    def describe_lex_v2_bot_alias_resilient(self, bot_id: str, bot_alias_id: str) -> Dict[str, Any]:
        """Describe a Lex V2 bot alias with network resilience."""
        client = self.get_lex_v2_client()
        return self.call_api_with_resilience(
            client,
            "describe_bot_alias",
            "lexv2-models",
            botId=bot_id,
            botAliasId=bot_alias_id,
        )

    def list_integration_associations_resilient(
        self, instance_id: str, integration_type: str, **kwargs
    ) -> Dict[str, Any]:
        """List Connect integration associations for one integration type."""
        client = self.get_connect_client()
        return self.call_api_with_resilience(
            client,
            "list_integration_associations",
            "connect",
            InstanceId=instance_id,
            IntegrationType=integration_type,
            **kwargs,
        )

    def get_qconnect_assistant_resilient(self, assistant_id: str) -> Dict[str, Any]:
        """Get a Q in Connect assistant's configuration with resilience."""
        client = self.get_qconnect_client()
        return self.call_api_with_resilience(
            client, "get_assistant", "qconnect", assistantId=assistant_id
        )

    def get_qconnect_knowledge_base_resilient(self, knowledge_base_id: str) -> Dict[str, Any]:
        """Get a Q in Connect knowledge base's configuration with resilience."""
        client = self.get_qconnect_client()
        return self.call_api_with_resilience(
            client,
            "get_knowledge_base",
            "qconnect",
            knowledgeBaseId=knowledge_base_id,
        )

    def list_ai_guardrails_resilient(self, assistant_id: str, **kwargs) -> Dict[str, Any]:
        """List assistant-scoped Q in Connect AI guardrails with resilience."""
        client = self.get_qconnect_client()
        return self.call_api_with_resilience(
            client,
            "list_ai_guardrails",
            "qconnect",
            assistantId=assistant_id,
            **kwargs,
        )

    def list_ai_prompts_resilient(self, assistant_id: str, **kwargs) -> Dict[str, Any]:
        """List assistant-scoped Q in Connect AI prompts with resilience."""
        client = self.get_qconnect_client()
        return self.call_api_with_resilience(
            client,
            "list_ai_prompts",
            "qconnect",
            assistantId=assistant_id,
            **kwargs,
        )

    def get_model_invocation_logging_configuration_resilient(self) -> Dict[str, Any]:
        """Get the regional Bedrock model invocation logging configuration."""
        client = self.get_bedrock_client()
        return self.call_api_with_resilience(
            client,
            "get_model_invocation_logging_configuration",
            "bedrock",
        )

    def list_inference_profiles_resilient(self, **kwargs) -> Dict[str, Any]:
        """List Bedrock inference profiles with resilience."""
        client = self.get_bedrock_client()
        return self.call_api_with_resilience(client, "list_inference_profiles", "bedrock", **kwargs)

    def get_s3_public_access_block_resilient(self, bucket_name: str) -> Dict[str, Any]:
        """Get an S3 bucket's public access block settings with resilience."""
        client = self.get_s3_client()
        return self.call_api_with_resilience(
            client, "get_public_access_block", "s3", Bucket=bucket_name
        )

    def list_instance_storage_configs_resilient(
        self, instance_id: str, resource_type: str
    ) -> Dict[str, Any]:
        """List Connect instance storage configs for a resource type."""
        client = self.get_connect_client()
        return self.call_api_with_resilience(
            client,
            "list_instance_storage_configs",
            "connect",
            InstanceId=instance_id,
            ResourceType=resource_type,
        )

    def list_approved_origins_resilient(self, instance_id: str) -> Dict[str, Any]:
        """List approved origins (CCP embedding allowlist) for an instance."""
        client = self.get_connect_client()
        return self.call_api_with_resilience(
            client, "list_approved_origins", "connect", InstanceId=instance_id
        )

    def list_security_profiles_resilient(self, instance_id: str) -> Dict[str, Any]:
        """List security profiles for an instance."""
        client = self.get_connect_client()
        return self.call_api_with_resilience(
            client, "list_security_profiles", "connect", InstanceId=instance_id
        )

    def list_security_profile_permissions_resilient(
        self, instance_id: str, security_profile_id: str
    ) -> Dict[str, Any]:
        """List granted permissions for a single security profile."""
        client = self.get_connect_client()
        return self.call_api_with_resilience(
            client,
            "list_security_profile_permissions",
            "connect",
            InstanceId=instance_id,
            SecurityProfileId=security_profile_id,
        )

    @staticmethod
    def is_access_denied(error: Exception) -> bool:
        """
        Return True if the given exception represents an AWS access-denied error,
        unwrapping NetworkResilienceError if necessary.

        Used by checks to map permission errors to SKIPPED findings.
        """
        denied_codes = {
            "AccessDenied",
            "AccessDeniedException",
            "UnauthorizedOperation",
            "AuthorizationError",
        }
        candidate = error
        if isinstance(error, NetworkResilienceError) and error.original_error:
            candidate = error.original_error
        if isinstance(candidate, ClientError):
            code = candidate.response.get("Error", {}).get("Code", "")
            return code in denied_codes
        return False

    def validate_credentials(self) -> CredentialValidationResult:
        """
        Validate AWS credentials and determine their source.

        Returns:
            CredentialValidationResult: Validation results
        """
        if self._credential_validation is not None:
            return self._credential_validation

        try:
            sts_client = self.get_sts_client()

            # Test credentials by getting caller identity
            response = sts_client.get_caller_identity()

            account_id = response.get("Account")
            user_arn = response.get("Arn")

            # Determine credential source
            credential_source = self._determine_credential_source()

            self._credential_validation = CredentialValidationResult(
                is_valid=True,
                credential_source=credential_source,
                account_id=account_id,
                user_arn=user_arn,
            )

            self.logger.info(f"Credentials validated successfully for account: {account_id}")
            self.logger.info(f"Credential source: {credential_source.value}")

        except (NoCredentialsError, PartialCredentialsError):
            error_msg = (
                "No valid AWS credentials found. Please configure credentials using one of:\n"
                "1. AWS CLI: aws configure\n"
                "2. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY\n"
                "3. IAM role (if running on EC2/Lambda/ECS)\n"
                "4. AWS profile: --profile <profile_name>"
            )
            self._credential_validation = CredentialValidationResult(
                is_valid=False,
                credential_source=CredentialSource.UNKNOWN,
                error_message=error_msg,
            )
            self.logger.error(error_msg)

        except TokenRetrievalError as e:
            error_msg = f"Failed to retrieve AWS credentials: {str(e)}"
            self._credential_validation = CredentialValidationResult(
                is_valid=False,
                credential_source=CredentialSource.UNKNOWN,
                error_message=error_msg,
            )
            self.logger.error(error_msg)

        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "Unknown")
            if error_code == "InvalidUserID.NotFound":
                error_msg = "AWS credentials are invalid or expired"
            elif error_code == "AccessDenied":
                error_msg = "Access denied when validating credentials. Check IAM permissions."
            else:
                error_msg = f"AWS credential validation failed: {str(e)}"

            self._credential_validation = CredentialValidationResult(
                is_valid=False,
                credential_source=CredentialSource.UNKNOWN,
                error_message=error_msg,
            )
            self.logger.error(error_msg)

        except Exception as e:
            error_msg = f"Unexpected error during credential validation: {str(e)}"
            self._credential_validation = CredentialValidationResult(
                is_valid=False,
                credential_source=CredentialSource.UNKNOWN,
                error_message=error_msg,
            )
            self.logger.error(error_msg)

        return self._credential_validation

    def _determine_credential_source(self) -> CredentialSource:
        """Determine the source of AWS credentials."""
        # Check for CloudShell environment
        if os.environ.get("CLOUDSHELL"):
            return CredentialSource.CLOUDSHELL

        # Check for environment variables
        if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
            return CredentialSource.ENVIRONMENT_VARIABLES

        # Check for profile usage
        if self.profile_name or os.environ.get("AWS_PROFILE"):
            return CredentialSource.AWS_PROFILE

        # Check for instance profile (EC2/ECS/Lambda) or OIDC-assumed role
        if os.environ.get("AWS_EXECUTION_ENV") or os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
            return CredentialSource.INSTANCE_PROFILE

        return CredentialSource.UNKNOWN

    def validate_permissions(self) -> PermissionValidationResult:
        """
        Validate that the current credentials have required permissions.

        Returns:
            PermissionValidationResult: Permission validation results
        """
        if self._permission_validation is not None:
            return self._permission_validation

        # First validate credentials
        cred_result = self.validate_credentials()
        if not cred_result.is_valid:
            self._permission_validation = PermissionValidationResult(
                is_valid=False,
                error_message=f"Cannot validate permissions: {cred_result.error_message}",
            )
            return self._permission_validation

        missing_permissions = []
        tested_permissions = []

        try:
            # Test Connect permissions
            connect_permissions = [
                ("connect:ListInstances", self._test_connect_list_instances),
                ("connect:DescribeInstance", self._test_connect_describe_instance),
                (
                    "connect:ListPhoneNumbersV2",
                    self._test_connect_list_phone_numbers_v2,
                ),
            ]

            for permission, test_func in connect_permissions:
                tested_permissions.append(permission)
                if not test_func():
                    missing_permissions.append(permission)

            # Test CloudWatch permissions
            tested_permissions.append("cloudwatch:GetMetricStatistics")
            if not self._test_cloudwatch_permissions():
                missing_permissions.append("cloudwatch:GetMetricStatistics")

            # Test S3 permissions against a bucket the instance is actually
            # configured to use (see _test_s3_permissions docstring for why
            # this no longer uses s3:ListBuckets — that action isn't in the
            # documented assessment policy, so probing it produced false
            # "missing" reports for correctly-provisioned least-privilege
            # roles). If no bucket can be discovered this way, the S3
            # permissions are reported as untested rather than missing.
            s3_permissions = ["s3:GetBucketPolicy", "s3:GetEncryptionConfiguration"]
            s3_tested, s3_missing = self._test_s3_permissions()
            tested_permissions.extend(s3_tested)
            missing_permissions.extend(s3_missing)
            if not s3_tested:
                self.logger.info(
                    "No S3 bucket could be discovered via the instance's "
                    "recording/transcript storage config; %s were not "
                    "tested (this is not treated as a failure).",
                    s3_permissions,
                )

            is_valid = len(missing_permissions) == 0

            self._permission_validation = PermissionValidationResult(
                is_valid=is_valid,
                missing_permissions=missing_permissions,
                tested_permissions=tested_permissions,
                error_message=(
                    None
                    if is_valid
                    else self._generate_permission_error_message(missing_permissions)
                ),
            )

            if is_valid:
                self.logger.info("All required permissions validated successfully")
            else:
                self.logger.warning(f"Missing permissions: {missing_permissions}")

        except Exception as e:
            error_msg = f"Permission validation failed: {str(e)}"
            self._permission_validation = PermissionValidationResult(
                is_valid=False,
                error_message=error_msg,
                tested_permissions=tested_permissions,
            )
            self.logger.error(error_msg)

        return self._permission_validation

    def _test_connect_list_instances(self) -> bool:
        """Test connect:ListInstances permission with network resilience."""
        try:
            self.list_connect_instances_resilient(MaxResults=1)
            return True
        except NetworkResilienceError as e:
            # Check if the underlying error is a permission issue
            if e.original_error and isinstance(e.original_error, ClientError):
                error_code = e.original_error.response.get("Error", {}).get("Code", "")
                if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                    return False
            # Network errors don't indicate permission problems
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                return False
            # Other errors might be due to no instances, which is fine
            return True
        except Exception:
            return False

    def _test_connect_describe_instance(self) -> bool:
        """Test connect:DescribeInstance permission by listing instances first."""
        try:
            response = self.list_connect_instances_resilient(MaxResults=1)

            instances = response.get("InstanceSummaryList", [])
            if instances:
                # Test describe on the first instance
                instance_id = instances[0]["Id"]
                self.describe_connect_instance_resilient(instance_id)

            return True
        except NetworkResilienceError as e:
            # Check if the underlying error is a permission issue
            if e.original_error and isinstance(e.original_error, ClientError):
                error_code = e.original_error.response.get("Error", {}).get("Code", "")
                if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                    return False
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                return False
            return True
        except Exception:
            return False

    def _test_connect_list_phone_numbers_v2(self) -> bool:
        """
        Test connect:ListPhoneNumbersV2 permission with network resilience.

        This is the API the Caller Journey Map, cost checks, and several
        resilience checks all depend on. A role that has the legacy
        connect:ListPhoneNumbers permission but not the V2 action would
        pass every other Connect probe and still see the Journey Map
        silently produce nothing — this check surfaces that gap directly
        during --check-permissions instead of the user discovering it in
        the report.
        """
        try:
            response = self.list_connect_instances_resilient(MaxResults=1)
            instances = response.get("InstanceSummaryList", [])
            if instances:
                instance_arn = instances[0].get("Arn")
                if instance_arn:
                    self.call_api_with_resilience(
                        self.get_connect_client(),
                        "list_phone_numbers_v2",
                        "connect",
                        TargetArn=instance_arn,
                        MaxResults=1,
                    )
            return True
        except NetworkResilienceError as e:
            if e.original_error and isinstance(e.original_error, ClientError):
                error_code = e.original_error.response.get("Error", {}).get("Code", "")
                if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                    return False
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                return False
            return True
        except Exception:
            return False

    def _test_cloudwatch_permissions(self) -> bool:
        """Test CloudWatch permissions with network resilience."""
        try:
            # Try to get a simple metric (this will fail gracefully if no data)
            self.get_cloudwatch_metrics_resilient(
                Namespace="AWS/Connect",
                MetricName="CallsPerInterval",
                StartTime=time.time() - 3600,  # 1 hour ago
                EndTime=time.time(),
                Period=3600,
                Statistics=["Sum"],
            )
            return True
        except NetworkResilienceError as e:
            # Check if the underlying error is a permission issue
            if e.original_error and isinstance(e.original_error, ClientError):
                error_code = e.original_error.response.get("Error", {}).get("Code", "")
                if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                    return False
            return True
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                return False
            return True
        except Exception:
            return False

    def _test_s3_permissions(self) -> tuple:
        """
        Test S3 permissions with network resilience.

        Historically this used ``s3:ListBuckets`` to pick a bucket to probe,
        but that action is not part of the documented assessment IAM policy
        (see iam_permissions.py — the S3ConfigurationAccess statement has no
        ListBuckets). A least-privilege role that follows the documented
        policy exactly would fail ``list_buckets`` and this method would then
        report both s3:GetBucketPolicy and s3:GetEncryptionConfiguration as
        "missing" even though the role has never been asked to use them
        against a real bucket — a false negative on a correctly-provisioned
        role.

        Instead, discover a bucket the assessment will actually touch: the
        S3 bucket configured for one of the Connect instance's storage
        types (call recordings, chat transcripts, or exported reports), via
        ``connect:ListInstanceStorageConfigs`` — an action already in the
        documented policy and already used by sec-storage-001. If no
        Connect instance or no S3-backed storage config exists, there is
        nothing meaningful to probe and the permissions are reported as
        untested (not missing) — the caller (validate_permissions) logs
        this distinction so it doesn't read as a failure.

        Returns:
            (tested, missing) — ``tested`` lists the S3 permissions that were
            actually exercised (empty if no bucket could be discovered);
            ``missing`` lists any of those that came back AccessDenied.
        """
        tested: List[str] = []
        missing: List[str] = []

        bucket = self._discover_s3_bucket_for_permission_test()
        if not bucket:
            return tested, missing

        # Test GetBucketPolicy
        tested.append("s3:GetBucketPolicy")
        try:
            self.get_s3_bucket_policy_resilient(bucket)
        except NetworkResilienceError as e:
            if e.original_error and isinstance(e.original_error, ClientError):
                error_code = e.original_error.response.get("Error", {}).get("Code", "")
                if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                    missing.append("s3:GetBucketPolicy")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                missing.append("s3:GetBucketPolicy")
            # NoSuchBucketPolicy is fine - means no policy exists

        # Test GetBucketEncryption
        tested.append("s3:GetEncryptionConfiguration")
        try:
            self.get_s3_bucket_encryption_resilient(bucket)
        except NetworkResilienceError as e:
            if e.original_error and isinstance(e.original_error, ClientError):
                error_code = e.original_error.response.get("Error", {}).get("Code", "")
                if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                    missing.append("s3:GetEncryptionConfiguration")
        except ClientError as e:
            error_code = e.response.get("Error", {}).get("Code", "")
            if error_code in ["AccessDenied", "UnauthorizedOperation"]:
                missing.append("s3:GetEncryptionConfiguration")
            # ServerSideEncryptionConfigurationNotFoundError is fine

        return tested, missing

    def _discover_s3_bucket_for_permission_test(self) -> Optional[str]:
        """
        Find an S3 bucket to test S3 permissions against, using only
        documented-policy actions (connect:ListInstances,
        connect:ListInstanceStorageConfigs — no s3:ListBuckets).

        Checks CALL_RECORDINGS, CHAT_TRANSCRIPTS, and MEDIA_STREAMS storage
        configs on the first discovered Connect instance and returns the
        first S3 bucket name found. Returns None if no instance exists, no
        storage config is S3-backed, or the lookup itself fails — all of
        which mean "nothing to probe", not "permissions are missing".
        """
        try:
            response = self.list_connect_instances_resilient(MaxResults=1)
            instances = response.get("InstanceSummaryList", [])
            if not instances:
                return None
            instance_id = instances[0]["Id"]

            for resource_type in ("CALL_RECORDINGS", "CHAT_TRANSCRIPTS", "MEDIA_STREAMS"):
                try:
                    resp = self.list_instance_storage_configs_resilient(instance_id, resource_type)
                except Exception:
                    continue
                for storage_config in resp.get("StorageConfigs", []):
                    if storage_config.get("StorageType") == "S3":
                        bucket = storage_config.get("S3Config", {}).get("BucketName")
                        if bucket:
                            return bucket
            return None
        except Exception:
            return None

    def _generate_permission_error_message(self, missing_permissions: List[str]) -> str:
        """Generate helpful error message for missing permissions."""
        base_message = (
            f"Missing required AWS permissions: {', '.join(missing_permissions)}\n\n"
            "To fix this issue:\n"
            "1. Ensure your AWS credentials have the required permissions\n"
            "2. If using IAM roles, update the role policy\n"
            "3. If using IAM users, attach the necessary policies\n\n"
            "Required IAM policy statement:\n"
        )

        policy_statement = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": self.REQUIRED_PERMISSIONS,
                    "Resource": "*",
                }
            ],
        }

        import json

        policy_json = json.dumps(policy_statement, indent=2)

        return base_message + policy_json

    def get_all_clients(self) -> Dict[str, Any]:
        """
        Get all commonly used AWS clients for the assessment tool.

        Returns:
            Dict[str, Any]: Dictionary of service name to client mappings
        """
        return {
            "connect": self.get_connect_client(),
            "cloudwatch": self.get_cloudwatch_client(),
            "s3": self.get_s3_client(),
            "sts": self.get_sts_client(),
        }

    def clear_cache(self) -> None:
        """Clear all cached clients and validation results."""
        with self._clients_lock:
            self._clients.clear()
        with self._session_lock:
            self._session = None
        self._credential_validation = None
        self._permission_validation = None
        self.logger.debug("Cleared client cache and validation results")

    def get_network_resilience_statistics(self) -> Dict[str, Any]:
        """
        Get network resilience statistics including retry attempts and rate limiting.

        Returns:
            Dictionary containing network resilience statistics
        """
        stats = {
            "retry_statistics": self.network_resilience_manager.get_retry_statistics(),
            "rate_limit_statistics": {},
            "configuration": {
                "max_attempts": self.network_resilience_config.max_attempts,
                "base_delay": self.network_resilience_config.base_delay,
                "max_delay": self.network_resilience_config.max_delay,
                "timeout_seconds": self.network_resilience_config.timeout_seconds,
                "rate_limiting_enabled": self.enable_rate_limiting,
                "operation_timeout": self.operation_timeout,
            },
        }

        if self.rate_limit_detector:
            stats["rate_limit_statistics"] = self.rate_limit_detector.get_rate_statistics()

        return stats

    def reset_network_resilience_statistics(self) -> None:
        """Reset network resilience statistics."""
        self.network_resilience_manager = NetworkResilienceManager(
            config=self.network_resilience_config, logger=self.logger
        )
        if self.rate_limit_detector:
            self.rate_limit_detector = RateLimitDetector(logger=self.logger)
        self.logger.debug("Reset network resilience statistics")

    def test_network_connectivity(self) -> Dict[str, Any]:
        """
        Test network connectivity to AWS services.

        Returns:
            Dictionary containing connectivity test results
        """
        connectivity_results = {
            "overall_status": "unknown",
            "tests": {},
            "errors": [],
            "recommendations": [],
        }

        test_operations = [
            ("sts", "get_caller_identity", {}),
            ("connect", "list_instances", {"MaxResults": 1}),
        ]

        successful_tests = 0
        total_tests = len(test_operations)

        for service, operation, params in test_operations:
            test_name = f"{service}:{operation}"
            try:
                client = self.get_client(service)
                start_time = time.time()

                # Use resilient API call
                self.call_api_with_resilience(client, operation, service, **params)

                end_time = time.time()
                response_time = end_time - start_time

                connectivity_results["tests"][test_name] = {
                    "status": "success",
                    "response_time_seconds": response_time,
                    "error": None,
                }
                successful_tests += 1

            except NetworkResilienceError as e:
                connectivity_results["tests"][test_name] = {
                    "status": "failed",
                    "response_time_seconds": None,
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "retry_attempts": len(e.retry_attempts) if e.retry_attempts else 0,
                }
                connectivity_results["errors"].append(f"{test_name}: {str(e)}")

                # Add specific recommendations based on error type
                if isinstance(e, RateLimitExceededError):
                    connectivity_results["recommendations"].append(
                        "Consider reducing concurrent operations or increasing retry delays"
                    )
                elif isinstance(e, NetworkTimeoutError):
                    connectivity_results["recommendations"].append(
                        "Check network connectivity and consider increasing timeout values"
                    )
                elif isinstance(e, ConnectivityError):
                    connectivity_results["recommendations"].append(
                        "Verify AWS service availability and network configuration"
                    )

            except Exception as e:
                connectivity_results["tests"][test_name] = {
                    "status": "failed",
                    "response_time_seconds": None,
                    "error": str(e),
                    "error_type": type(e).__name__,
                    "retry_attempts": 0,
                }
                connectivity_results["errors"].append(f"{test_name}: {str(e)}")

        # Determine overall status
        if successful_tests == total_tests:
            connectivity_results["overall_status"] = "healthy"
        elif successful_tests > 0:
            connectivity_results["overall_status"] = "degraded"
        else:
            connectivity_results["overall_status"] = "failed"

        connectivity_results["success_rate"] = (
            successful_tests / total_tests if total_tests > 0 else 0
        )

        return connectivity_results

    def configure_network_resilience(
        self,
        max_attempts: int = None,
        base_delay: float = None,
        max_delay: float = None,
        timeout_seconds: float = None,
        enable_rate_limiting: bool = None,
    ) -> None:
        """
        Update network resilience configuration.

        Args:
            max_attempts: Maximum retry attempts
            base_delay: Base delay between retries
            max_delay: Maximum delay between retries
            timeout_seconds: Operation timeout
            enable_rate_limiting: Whether to enable rate limiting
        """
        # Update configuration
        if max_attempts is not None:
            self.network_resilience_config.max_attempts = max_attempts
        if base_delay is not None:
            self.network_resilience_config.base_delay = base_delay
        if max_delay is not None:
            self.network_resilience_config.max_delay = max_delay
        if timeout_seconds is not None:
            self.network_resilience_config.timeout_seconds = timeout_seconds
            self.operation_timeout = timeout_seconds
        if enable_rate_limiting is not None:
            self.enable_rate_limiting = enable_rate_limiting

        # Recreate managers with new configuration
        self.network_resilience_manager = NetworkResilienceManager(
            config=self.network_resilience_config, logger=self.logger
        )

        if self.enable_rate_limiting and not self.rate_limit_detector:
            self.rate_limit_detector = RateLimitDetector(logger=self.logger)
        elif not self.enable_rate_limiting:
            self.rate_limit_detector = None

        self.logger.info("Updated network resilience configuration")

    def get_recommended_timeout_settings(self) -> Dict[str, float]:
        """
        Get recommended timeout settings based on current network conditions.

        Returns:
            Dictionary with recommended timeout values
        """
        # Test basic connectivity to determine baseline
        connectivity_test = self.test_network_connectivity()

        # Calculate average response time from successful tests
        response_times = []
        for test_result in connectivity_test["tests"].values():
            if test_result["status"] == "success" and test_result["response_time_seconds"]:
                response_times.append(test_result["response_time_seconds"])

        if response_times:
            avg_response_time = sum(response_times) / len(response_times)
            max_response_time = max(response_times)

            # Recommend timeouts based on observed performance
            recommended_timeout = max(
                30.0, max_response_time * 3
            )  # 3x max observed time, minimum 30s
            recommended_connect_timeout = max(
                10.0, avg_response_time * 2
            )  # 2x average time, minimum 10s
        else:
            # Fallback to conservative defaults
            recommended_timeout = 60.0
            recommended_connect_timeout = 15.0

        return {
            "operation_timeout": recommended_timeout,
            "connect_timeout": recommended_connect_timeout,
            "read_timeout": recommended_timeout,
            "based_on_samples": len(response_times),
            "network_status": connectivity_test["overall_status"],
        }
