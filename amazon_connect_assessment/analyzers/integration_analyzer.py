"""
Integration Analyzer for Amazon Connect Assessment Tool.

This module provides functionality to analyze Amazon Connect integrations
with external services like Lambda functions, Lex bots, and S3 buckets.
"""

import logging
from typing import Any, Dict, List

from ..models import ConnectInstance, Integration
from .base import BaseAnalyzer

# Resource types accepted by Connect's ListInstanceStorageConfigs API. The
# analyzer filters the returned configs to S3-backed integrations below.
_STORAGE_RESOURCE_TYPES = (
    "CALL_RECORDINGS",
    "CHAT_TRANSCRIPTS",
    "SCHEDULED_REPORTS",
    "MEDIA_STREAMS",
    "CONTACT_TRACE_RECORDS",
    "AGENT_EVENTS",
    "REAL_TIME_CONTACT_ANALYSIS_SEGMENTS",
    "ATTACHMENTS",
    "CONTACT_EVALUATIONS",
    "SCREEN_RECORDINGS",
    "REAL_TIME_CONTACT_ANALYSIS_CHAT_SEGMENTS",
    "REAL_TIME_CONTACT_ANALYSIS_VOICE_SEGMENTS",
    "EMAIL_MESSAGES",
)


class IntegrationAnalyzer(BaseAnalyzer):
    """
    Analyzer for Amazon Connect integrations.

    Analyzes integrations with Lambda functions, Lex bots, S3 buckets,
    and other external services to identify configuration issues and
    security concerns.
    """

    def __init__(self, aws_client_factory, config: Dict[str, Any] = None):
        """
        Initialize the Integration Analyzer.

        Args:
            aws_client_factory: AWSClientFactory instance for AWS service clients
            config: Optional configuration dictionary for analyzer behavior
        """
        super().__init__(aws_client_factory, config)
        self.logger = logging.getLogger("analyzer.IntegrationAnalyzer")

    def analyze(self, instance: ConnectInstance) -> ConnectInstance:
        """
        Analyze integrations for a Connect instance.

        Args:
            instance: ConnectInstance object to populate with integration data

        Returns:
            ConnectInstance: Updated instance with integration analysis data
        """
        try:
            self.logger.debug(f"Analyzing integrations for instance {instance.instance_id}")

            integrations = []

            # Analyze Lambda function integrations
            lambda_integrations = self._analyze_lambda_integrations(instance.instance_id)
            integrations.extend(lambda_integrations)

            # Analyze Lex bot integrations
            lex_integrations = self._analyze_lex_integrations(instance.instance_id)
            integrations.extend(lex_integrations)

            # Analyze S3 bucket integrations (from instance storage config)
            s3_integrations = self._analyze_s3_integrations(instance.instance_id)
            integrations.extend(s3_integrations)

            instance.integrations = integrations

            self.logger.info(
                f"Analyzed {len(integrations)} integrations for instance {instance.instance_id}"
            )
            return instance

        except Exception as e:
            self.logger.error(
                f"Failed to analyze integrations for instance {instance.instance_id}: {str(e)}"
            )
            raise

    def _analyze_lambda_integrations(self, instance_id: str) -> List[Integration]:
        """
        Analyze Lambda function integrations for a Connect instance.

        Args:
            instance_id: The Connect instance ID

        Returns:
            List[Integration]: List of Lambda integrations
        """
        lambda_integrations = []

        try:
            # List Lambda functions associated with the Connect instance
            response = self.call_api_resilient(
                self.connect_client,
                "list_lambda_functions",
                "connect",
                InstanceId=instance_id,
            )
            lambda_functions = response.get("LambdaFunctions", [])

            for lambda_function in lambda_functions:
                try:
                    integration = self._analyze_lambda_function(instance_id, lambda_function)
                    lambda_integrations.append(integration)
                    self.logger.debug(f"Analyzed Lambda integration: {lambda_function}")
                except Exception as e:
                    self.logger.error(
                        f"Failed to analyze Lambda function {lambda_function}: {str(e)}"
                    )
                    if not self.is_resource_not_found(e):
                        raise

            return lambda_integrations

        except Exception as e:
            self.logger.error(f"Failed to analyze Lambda integrations: {str(e)}")
            raise

    def _analyze_lambda_function(self, instance_id: str, lambda_function_arn: str) -> Integration:
        """
        Analyze a single Lambda function integration.

        Args:
            instance_id: The Connect instance ID
            lambda_function_arn: The Lambda function ARN

        Returns:
            Integration: Analyzed Lambda integration
        """
        # Extract function name from ARN
        function_name = lambda_function_arn.split(":")[-1]

        # Get Lambda function details
        lambda_details = self._get_lambda_function_details(lambda_function_arn)

        configuration = {
            "function_arn": lambda_function_arn,
            "function_name": function_name,
            "runtime": lambda_details.get("runtime"),
            "timeout": lambda_details.get("timeout"),
            "memory_size": lambda_details.get("memory_size"),
            "last_modified": lambda_details.get("last_modified"),
            "code_size": lambda_details.get("code_size"),
            "environment_variables": lambda_details.get("environment_variables", {}),
            "vpc_config": lambda_details.get("vpc_config"),
            "dead_letter_config": lambda_details.get("dead_letter_config"),
        }

        return Integration(
            integration_type="lambda",
            resource_arn=lambda_function_arn,
            resource_id=function_name,
            configuration=configuration,
        )

    def _get_lambda_function_details(self, function_arn: str) -> Dict[str, Any]:
        """
        Get detailed information about a Lambda function.

        Args:
            function_arn: The Lambda function ARN

        Returns:
            Dict[str, Any]: Lambda function details
        """
        try:
            response = self.aws_client_factory.get_lambda_function_resilient(function_arn)

            function_config = response.get("Configuration", {})

            return {
                "runtime": function_config.get("Runtime"),
                "timeout": function_config.get("Timeout"),
                "memory_size": function_config.get("MemorySize"),
                "last_modified": function_config.get("LastModified"),
                "code_size": function_config.get("CodeSize"),
                "environment_variables": function_config.get("Environment", {}).get(
                    "Variables", {}
                ),
                "vpc_config": function_config.get("VpcConfig"),
                "dead_letter_config": function_config.get("DeadLetterConfig"),
                "role": function_config.get("Role"),
                "handler": function_config.get("Handler"),
            }

        except Exception as e:
            self.logger.warning(
                f"Failed to get Lambda function details for {function_arn}: {str(e)}"
            )
            raise

    def _analyze_lex_integrations(self, instance_id: str) -> List[Integration]:
        """
        Analyze Lex bot integrations for a Connect instance.

        Args:
            instance_id: The Connect instance ID

        Returns:
            List[Integration]: List of Lex integrations
        """
        lex_integrations = []

        try:
            # List Lex bots associated with the Connect instance
            response = self.call_api_resilient(
                self.connect_client,
                "list_lex_bots",
                "connect",
                InstanceId=instance_id,
            )
            lex_bots = response.get("LexBots", [])

            for lex_bot in lex_bots:
                try:
                    integration = self._analyze_lex_bot(instance_id, lex_bot)
                    lex_integrations.append(integration)
                    self.logger.debug(f"Analyzed Lex integration: {lex_bot.get('Name', 'Unknown')}")
                except Exception as e:
                    self.logger.error(f"Failed to analyze Lex bot {lex_bot}: {str(e)}")
                    if not self.is_resource_not_found(e):
                        raise

            return lex_integrations

        except Exception as e:
            self.logger.error(f"Failed to analyze Lex integrations: {str(e)}")
            raise

    def _analyze_lex_bot(self, instance_id: str, lex_bot: Dict[str, Any]) -> Integration:
        """
        Analyze a single Lex bot integration.

        Args:
            instance_id: The Connect instance ID
            lex_bot: Lex bot information from list_lex_bots API

        Returns:
            Integration: Analyzed Lex integration
        """
        bot_name = lex_bot.get("Name", "Unknown")
        lex_region = lex_bot.get("LexRegion", "us-east-1")

        # Get Lex bot details
        lex_details = self._get_lex_bot_details(bot_name, lex_region)

        configuration = {
            "bot_name": bot_name,
            "lex_region": lex_region,
            "bot_status": lex_details.get("bot_status"),
            "creation_date": lex_details.get("creation_date"),
            "last_updated_date": lex_details.get("last_updated_date"),
            "locale": lex_details.get("locale"),
            "child_directed": lex_details.get("child_directed"),
            "idle_session_ttl": lex_details.get("idle_session_ttl"),
            "voice_id": lex_details.get("voice_id"),
            "clarification_prompt": lex_details.get("clarification_prompt"),
            "abort_statement": lex_details.get("abort_statement"),
        }

        # Create a pseudo-ARN for Lex bot (Lex doesn't use standard ARNs)
        resource_arn = f"arn:aws:lex:{lex_region}:*:bot:{bot_name}"

        return Integration(
            integration_type="lex",
            resource_arn=resource_arn,
            resource_id=bot_name,
            configuration=configuration,
        )

    def _get_lex_bot_details(self, bot_name: str, lex_region: str) -> Dict[str, Any]:
        """
        Get detailed information about a Lex bot.

        Args:
            bot_name: The Lex bot name
            lex_region: The Lex region

        Returns:
            Dict[str, Any]: Lex bot details
        """
        try:
            lex_client = self.aws_client_factory.get_client(
                "lex-models",
                region_name=lex_region,
            )
            response = self.call_api_resilient(
                lex_client,
                "get_bot",
                "lex-models",
                name=bot_name,
                versionOrAlias="$LATEST",
            )

            return {
                "bot_status": response.get("status"),
                "creation_date": response.get("createdDate"),
                "last_updated_date": response.get("lastUpdatedDate"),
                "locale": response.get("locale"),
                "child_directed": response.get("childDirected"),
                "idle_session_ttl": response.get("idleSessionTTLInSeconds"),
                "voice_id": response.get("voiceId"),
                "clarification_prompt": response.get("clarificationPrompt"),
                "abort_statement": response.get("abortStatement"),
                "failure_reason": response.get("failureReason"),
            }

        except Exception as e:
            self.logger.warning(f"Failed to get Lex bot details for {bot_name}: {str(e)}")
            raise

    def _analyze_s3_integrations(self, instance_id: str) -> List[Integration]:
        """
        Analyze S3 bucket integrations for a Connect instance.

        Args:
            instance_id: The Connect instance ID

        Returns:
            List[Integration]: List of S3 integrations
        """
        s3_integrations = []

        for resource_type in _STORAGE_RESOURCE_TYPES:
            try:
                # NOTE: this is the *discovery* call — it lists every storage
                # config of a given resource type without needing to know an
                # AssociationId up front. describe_instance_storage_config
                # (singular) requires an AssociationId as a required
                # parameter and always raised here since none was ever
                # supplied, so this integration discovery silently returned
                # zero S3 integrations regardless of what was actually
                # configured. list_instance_storage_configs is the correct
                # discovery-shaped API for this use case.
                response = self.aws_client_factory.list_instance_storage_configs_resilient(
                    instance_id,
                    resource_type,
                )
            except Exception as e:
                # Expected if the resource type has no storage config, or
                # (rarely) if the API isn't available in this region.
                self.logger.debug(
                    f"No {resource_type} storage configuration found for "
                    f"instance {instance_id}: {str(e)}"
                )
                if self.is_resource_not_found(e):
                    continue
                raise

            storage_configs = response.get("StorageConfigs", [])
            for storage_config in storage_configs:
                if storage_config.get("StorageType") == "S3":
                    try:
                        integration = self._analyze_s3_storage_config(instance_id, storage_config)
                        s3_integrations.append(integration)
                        self.logger.debug(
                            f"Analyzed S3 integration ({resource_type}): "
                            f"{storage_config.get('S3Config', {}).get('BucketName', 'Unknown')}"
                        )
                    except Exception as e:
                        self.logger.error(f"Failed to analyze S3 storage config: {str(e)}")
                        raise

        return s3_integrations

    def _analyze_s3_storage_config(
        self, instance_id: str, storage_config: Dict[str, Any]
    ) -> Integration:
        """
        Analyze an S3 storage configuration.

        Args:
            instance_id: The Connect instance ID
            storage_config: S3 storage configuration

        Returns:
            Integration: Analyzed S3 integration
        """
        s3_config = storage_config.get("S3Config", {})
        bucket_name = s3_config.get("BucketName", "")
        bucket_prefix = s3_config.get("BucketPrefix", "")

        # Get S3 bucket details
        s3_details = self._get_s3_bucket_details(bucket_name)

        configuration = {
            "bucket_name": bucket_name,
            "bucket_prefix": bucket_prefix,
            "encryption_config": s3_config.get("EncryptionConfig", {}),
            "bucket_region": s3_details.get("region"),
            "bucket_versioning": s3_details.get("versioning"),
            "bucket_encryption": s3_details.get("encryption"),
            "bucket_policy": s3_details.get("policy"),
            "bucket_public_access": s3_details.get("public_access_block"),
        }

        # Create S3 bucket ARN
        resource_arn = f"arn:aws:s3:::{bucket_name}"

        return Integration(
            integration_type="s3",
            resource_arn=resource_arn,
            resource_id=bucket_name,
            configuration=configuration,
        )

    def _get_s3_bucket_details(self, bucket_name: str) -> Dict[str, Any]:
        """
        Get detailed information about an S3 bucket.

        Args:
            bucket_name: The S3 bucket name

        Returns:
            Dict[str, Any]: S3 bucket details
        """
        try:
            details = {"bucket_name": bucket_name}

            # Get bucket location
            try:
                location_response = self.call_api_resilient(
                    self.s3_client,
                    "get_bucket_location",
                    "s3",
                    Bucket=bucket_name,
                )
                details["region"] = location_response.get("LocationConstraint") or "us-east-1"
            except Exception:
                details["region"] = "unknown"

            # Get bucket versioning
            try:
                versioning_response = self.call_api_resilient(
                    self.s3_client,
                    "get_bucket_versioning",
                    "s3",
                    Bucket=bucket_name,
                )
                details["versioning"] = versioning_response.get("Status", "Disabled")
            except Exception:
                details["versioning"] = "unknown"

            # Get bucket encryption
            try:
                encryption_response = self.aws_client_factory.get_s3_bucket_encryption_resilient(
                    bucket_name
                )
                details["encryption"] = encryption_response.get(
                    "ServerSideEncryptionConfiguration", {}
                )
            except Exception:
                details["encryption"] = None

            # Get bucket policy (if accessible)
            try:
                policy_response = self.aws_client_factory.get_s3_bucket_policy_resilient(
                    bucket_name
                )
                details["policy"] = policy_response.get("Policy")
            except Exception:
                details["policy"] = None

            # Get public access block
            try:
                pab_response = self.aws_client_factory.get_s3_public_access_block_resilient(
                    bucket_name
                )
                details["public_access_block"] = pab_response.get(
                    "PublicAccessBlockConfiguration", {}
                )
            except Exception:
                details["public_access_block"] = None

            return details

        except Exception as e:
            self.logger.warning(f"Failed to get S3 bucket details for {bucket_name}: {str(e)}")
            raise

    def get_integration_summary(self, integrations: List[Integration]) -> Dict[str, Any]:
        """
        Generate a summary of integration analysis results.

        Args:
            integrations: List of analyzed integrations

        Returns:
            Dict[str, Any]: Summary of integration analysis
        """
        if not integrations:
            return {"total_integrations": 0}

        integration_types = {}
        for integration in integrations:
            integration_type = integration.integration_type
            integration_types[integration_type] = integration_types.get(integration_type, 0) + 1

        return {
            "total_integrations": len(integrations),
            "integration_types": integration_types,
            "lambda_integrations": integration_types.get("lambda", 0),
            "lex_integrations": integration_types.get("lex", 0),
            "s3_integrations": integration_types.get("s3", 0),
        }
