"""
Base analyzer interface for Amazon Connect component analysis.

Defines the standard interface for analyzing different types of Amazon Connect
components and extracting their configuration data.
"""

import logging
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Dict, Iterator

from ..models import ConnectInstance

if TYPE_CHECKING:
    from ..aws_client_factory import AWSClientFactory


class BaseAnalyzer(ABC):
    """
    Abstract base class for Amazon Connect component analyzers.

    All component analyzers must inherit from this class and implement
    the analyze method. Provides standard interface for component analysis
    and configuration extraction.
    """

    def __init__(self, aws_client_factory: "AWSClientFactory", config: Dict[str, Any] = None):
        """
        Initialize a new component analyzer.

        Args:
            aws_client_factory: AWSClientFactory instance for AWS service clients
            config: Optional configuration dictionary for analyzer behavior
        """
        self.aws_client_factory = aws_client_factory
        self.config = config or {}
        self.logger = logging.getLogger(f"analyzer.{self.__class__.__name__}")

    @abstractmethod
    def analyze(self, instance: ConnectInstance) -> ConnectInstance:
        """
        Analyze Amazon Connect components and populate instance data.

        This method must be implemented by all concrete analyzer classes.
        It should extract configuration data for specific component types
        and populate the appropriate fields in the ConnectInstance object.

        Args:
            instance: ConnectInstance object to populate with component data

        Returns:
            ConnectInstance: Updated instance with analyzed component data

        Raises:
            Exception: Any errors during analysis should be logged and
                      may be re-raised depending on error handling strategy
        """
        pass

    @property
    def connect_client(self):
        """Get the Amazon Connect client."""
        return self.aws_client_factory.get_connect_client()

    @property
    def cloudwatch_client(self):
        """Get the CloudWatch client."""
        return self.aws_client_factory.get_cloudwatch_client()

    @property
    def s3_client(self):
        """Get the S3 client."""
        return self.aws_client_factory.get_s3_client()

    @property
    def lambda_client(self):
        """Get the Lambda client."""
        return self.aws_client_factory.get_client("lambda")

    @property
    def lex_client(self):
        """Get the Lex (V1) client used for get_bot details."""
        return self.aws_client_factory.get_client("lex-models")

    def call_api_resilient(self, client, operation_name: str, service_name: str = None, **kwargs):
        """
        Call AWS API with network resilience.

        Args:
            client: AWS service client
            operation_name: Name of the API operation
            service_name: Name of the AWS service (for rate limiting)
            **kwargs: Arguments to pass to the API operation

        Returns:
            API response
        """
        return self.aws_client_factory.call_api_with_resilience(
            client, operation_name, service_name, **kwargs
        )

    def paginate_api_resilient(
        self,
        client: Any,
        operation_name: str,
        service_name: str,
        **kwargs: Any,
    ) -> Iterator[Dict[str, Any]]:
        """Yield all pages from a token-based API through the resilience layer."""
        request_kwargs = dict(kwargs)

        while True:
            response = self.call_api_resilient(
                client,
                operation_name,
                service_name,
                **request_kwargs,
            )
            yield response

            next_token = response.get("NextToken")
            if not next_token:
                return
            request_kwargs["NextToken"] = next_token

    @staticmethod
    def is_resource_not_found(error: Exception) -> bool:
        """Return whether an AWS error indicates a deleted or missing resource."""
        candidate = getattr(error, "original_error", None) or error
        response = getattr(candidate, "response", {})
        error_code = response.get("Error", {}).get("Code", "")
        message = str(candidate).lower()
        return (
            error_code
            in {
                "ResourceNotFoundException",
                "ResourceNotFound",
                "NoSuchBucket",
                "NoSuchKey",
            }
            or "not found" in message
        )

    def list_connect_instances_resilient(self, **kwargs):
        """List Connect instances with network resilience."""
        return self.aws_client_factory.list_connect_instances_resilient(**kwargs)

    def describe_connect_instance_resilient(self, instance_id: str, **kwargs):
        """Describe Connect instance with network resilience."""
        return self.aws_client_factory.describe_connect_instance_resilient(instance_id, **kwargs)

    def list_contact_flows_resilient(self, instance_id: str, **kwargs):
        """List contact flows with network resilience."""
        return self.aws_client_factory.list_contact_flows_resilient(instance_id, **kwargs)

    def list_queues_resilient(self, instance_id: str, **kwargs):
        """List queues with network resilience."""
        return self.aws_client_factory.list_queues_resilient(instance_id, **kwargs)

    def safe_analyze(self, instance: ConnectInstance) -> ConnectInstance:
        """
        Analyze components with error handling.

        Wraps the analyze method with try/catch to ensure that analyzer
        failures don't crash the entire assessment process. Records the
        failure reason in self.last_error for upstream reporting.
        """
        self.last_error: str | None = None
        try:
            self.logger.debug(f"Starting analysis for instance {instance.instance_id}")
            result = self.analyze(instance)
            self.logger.debug(f"Analysis completed for instance {instance.instance_id}")
            return result
        except Exception as e:
            self.last_error = f"{self.__class__.__name__} failed for {instance.instance_id}: {e}"
            self.logger.error(self.last_error)
            return instance

    def get_component_count(self, instance: ConnectInstance, component_type: str) -> int:
        """
        Get count of a specific component type in the instance.

        Args:
            instance: ConnectInstance to check
            component_type: Type of component to count

        Returns:
            int: Number of components of the specified type
        """
        component_map = {
            "contact_flows": instance.contact_flows,
            "queues": instance.queues,
            "routing_profiles": instance.routing_profiles,
            "users": instance.users,
            "security_profiles": instance.security_profiles,
            "integrations": instance.integrations,
        }

        components = component_map.get(component_type, [])
        return len(components) if components else 0

    def __str__(self) -> str:
        """String representation of the analyzer."""
        return f"{self.__class__.__name__}"

    def __repr__(self) -> str:
        """Detailed string representation of the analyzer."""
        return f"{self.__class__.__name__}(aws_client_factory={self.aws_client_factory})"
