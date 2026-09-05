"""
Connect Instance Analyzer for Amazon Connect Assessment Tool.

This module provides functionality to discover and analyze Amazon Connect instances
across an AWS account, extracting basic instance configuration and metadata.
"""

import logging
from typing import Any, Dict, List

from ..models import ConnectInstance
from .base import BaseAnalyzer


class ConnectInstanceAnalyzer(BaseAnalyzer):
    """
    Analyzer for discovering and analyzing Amazon Connect instances.

    Discovers all Connect instances in the target AWS account and extracts
    their basic configuration information including instance settings,
    service roles, and operational status.
    """

    def __init__(self, aws_client_factory, config: Dict[str, Any] = None):
        """
        Initialize the Connect Instance Analyzer.

        Args:
            aws_client_factory: AWSClientFactory instance for AWS service clients
            config: Optional configuration dictionary for analyzer behavior
        """
        super().__init__(aws_client_factory, config)
        self.logger = logging.getLogger("analyzer.ConnectInstanceAnalyzer")

    def discover_instances(self) -> List[ConnectInstance]:
        """
        Discover all Amazon Connect instances in the AWS account.

        Returns:
            List[ConnectInstance]: List of discovered Connect instances

        Raises:
            Exception: If instance discovery fails
        """
        instances = []

        try:
            self.logger.info("Starting Connect instance discovery")

            # List all Connect instances
            for page in self.paginate_api_resilient(
                self.connect_client,
                "list_instances",
                "connect",
            ):
                instance_summaries = page.get("InstanceSummaryList", [])

                for instance_summary in instance_summaries:
                    try:
                        instance = self._create_instance_from_summary(instance_summary)
                        instances.append(instance)
                        self.logger.info(
                            f"Discovered Connect instance: {instance.instance_id} "
                            f"({instance.instance_alias or 'No alias'})"
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Failed to process instance {instance_summary.get('Id', 'unknown')}: {str(e)}"
                        )
                        raise

            self.logger.info(f"Discovered {len(instances)} Connect instances")
            return instances

        except Exception as e:
            error_msg = f"Failed to discover Connect instances: {str(e)}"
            self.logger.error(error_msg)
            raise Exception(error_msg) from e

    def _create_instance_from_summary(self, instance_summary: Dict[str, Any]) -> ConnectInstance:
        """
        Create a ConnectInstance object from instance summary data.

        Args:
            instance_summary: Instance summary from list_instances API

        Returns:
            ConnectInstance: Basic instance object with summary data
        """
        instance_id = instance_summary["Id"]
        instance_arn = instance_summary["Arn"]
        instance_alias = instance_summary.get("InstanceAlias")
        service_role = instance_summary.get("ServiceRole")
        status = instance_summary.get("InstanceStatus")

        # Get detailed instance information
        detailed_info = self._get_instance_details(instance_id)

        return ConnectInstance(
            instance_id=instance_id,
            instance_arn=instance_arn,
            instance_alias=instance_alias,
            service_role=service_role,
            status=status,
            identity_management_type=detailed_info.get(
                "identity_management_type", "CONNECT_MANAGED"
            ),
            inbound_calls_enabled=detailed_info.get("inbound_calls_enabled", False),
            outbound_calls_enabled=detailed_info.get("outbound_calls_enabled", False),
        )

    def _get_instance_details(self, instance_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a Connect instance.

        Args:
            instance_id: The Connect instance ID

        Returns:
            Dict[str, Any]: Detailed instance information
        """
        try:
            response = self.describe_connect_instance_resilient(instance_id)
            instance_details = response.get("Instance", {})

            return {
                "identity_management_type": instance_details.get(
                    "IdentityManagementType", "CONNECT_MANAGED"
                ),
                "inbound_calls_enabled": instance_details.get("InboundCallsEnabled", False),
                "outbound_calls_enabled": instance_details.get("OutboundCallsEnabled", False),
            }

        except Exception as e:
            self.logger.warning(f"Failed to get detailed info for instance {instance_id}: {str(e)}")
            raise

    def analyze(self, instance: ConnectInstance) -> ConnectInstance:
        """
        Analyze a Connect instance and populate additional metadata.

        This method enriches the instance object with additional configuration
        details that may not be available during initial discovery.

        Args:
            instance: ConnectInstance object to analyze

        Returns:
            ConnectInstance: Updated instance with additional analysis data
        """
        try:
            self.logger.debug(f"Analyzing instance {instance.instance_id}")

            # Refresh instance details to ensure we have the latest information
            detailed_info = self._get_instance_details(instance.instance_id)

            # Update instance with any additional details
            instance.identity_management_type = detailed_info.get(
                "identity_management_type", instance.identity_management_type
            )
            instance.inbound_calls_enabled = detailed_info.get(
                "inbound_calls_enabled", instance.inbound_calls_enabled
            )
            instance.outbound_calls_enabled = detailed_info.get(
                "outbound_calls_enabled", instance.outbound_calls_enabled
            )

            self.logger.debug(f"Instance analysis completed for {instance.instance_id}")
            return instance

        except Exception as e:
            self.logger.error(f"Failed to analyze instance {instance.instance_id}: {str(e)}")
            raise

    def get_instance_summary(self, instance: ConnectInstance) -> Dict[str, Any]:
        """
        Generate a summary of instance configuration.

        Args:
            instance: ConnectInstance to summarize

        Returns:
            Dict[str, Any]: Summary information about the instance
        """
        return {
            "instance_id": instance.instance_id,
            "instance_alias": instance.instance_alias,
            "identity_management_type": instance.identity_management_type,
            "inbound_calls_enabled": instance.inbound_calls_enabled,
            "outbound_calls_enabled": instance.outbound_calls_enabled,
            "status": instance.status,
            "service_role": instance.service_role,
            "component_counts": {
                "contact_flows": len(instance.contact_flows),
                "queues": len(instance.queues),
                "routing_profiles": len(instance.routing_profiles),
                "users": len(instance.users),
                "security_profiles": len(instance.security_profiles),
                "integrations": len(instance.integrations),
            },
        }
