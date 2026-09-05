"""
Queue Analyzer for Amazon Connect Assessment Tool.

This module provides functionality to analyze Amazon Connect queues and routing profiles,
extracting configuration details, capacity settings, and routing logic.
"""

import logging
from typing import Any, Dict, List

from ..models import ConnectInstance, Queue, RoutingProfile
from .base import BaseAnalyzer


class QueueAnalyzer(BaseAnalyzer):
    """
    Analyzer for Amazon Connect queues and routing profiles.

    Analyzes queue configurations including capacity settings, routing profiles,
    agent assignments, and hours of operation within Connect instances.
    """

    def __init__(self, aws_client_factory, config: Dict[str, Any] = None):
        """
        Initialize the Queue Analyzer.

        Args:
            aws_client_factory: AWSClientFactory instance for AWS service clients
            config: Optional configuration dictionary for analyzer behavior
        """
        super().__init__(aws_client_factory, config)
        self.logger = logging.getLogger("analyzer.QueueAnalyzer")

    def analyze(self, instance: ConnectInstance) -> ConnectInstance:
        """
        Analyze queues and routing profiles for a Connect instance.

        Args:
            instance: ConnectInstance object to populate with queue and routing data

        Returns:
            ConnectInstance: Updated instance with queue and routing analysis data
        """
        try:
            self.logger.debug(
                f"Analyzing queues and routing profiles for instance {instance.instance_id}"
            )

            # Initialize orphaned queue tracking
            self._orphaned_queues = []

            # Analyze queues
            queues = self._discover_queues(instance.instance_id)
            instance.queues = queues

            # Analyze routing profiles
            routing_profiles = self._discover_routing_profiles(instance.instance_id)
            instance.routing_profiles = routing_profiles

            # Report orphaned queue references if any were found
            if hasattr(self, "_orphaned_queues") and self._orphaned_queues:
                orphaned_count = len(self._orphaned_queues)
                self.logger.info(
                    f"Found {orphaned_count} orphaned queue reference(s) in instance {instance.instance_id}. "
                    f"These queues are referenced in configurations but no longer exist. "
                    f"Consider cleaning up routing profiles and other configurations."
                )
                self.logger.debug(
                    f"Orphaned queue IDs: {', '.join(self._orphaned_queues[:5])}"
                    + (f" and {orphaned_count - 5} more..." if orphaned_count > 5 else "")
                )

            self.logger.info(
                f"Analyzed {len(queues)} queues and {len(routing_profiles)} routing profiles "
                f"for instance {instance.instance_id}"
            )
            return instance

        except Exception as e:
            self.logger.error(
                f"Failed to analyze queues and routing profiles for instance {instance.instance_id}: {str(e)}"
            )
            raise

    def _discover_queues(self, instance_id: str) -> List[Queue]:
        """
        Discover and analyze all queues in a Connect instance.

        Args:
            instance_id: The Connect instance ID

        Returns:
            List[Queue]: List of analyzed queues
        """
        queues = []

        try:
            # List all queues
            for page in self.paginate_api_resilient(
                self.connect_client,
                "list_queues",
                "connect",
                InstanceId=instance_id,
            ):
                queue_summaries = page.get("QueueSummaryList", [])

                for queue_summary in queue_summaries:
                    try:
                        queue = self._analyze_queue(instance_id, queue_summary)
                        queues.append(queue)
                        self.logger.debug(f"Analyzed queue: {queue.name}")
                    except Exception as e:
                        self.logger.error(
                            f"Failed to analyze queue {queue_summary.get('Id', 'unknown')}: {str(e)}"
                        )
                        self.logger.debug(
                            f"Queue summary keys for failed queue: {sorted(queue_summary.keys())}"
                        )
                        if not self.is_resource_not_found(e):
                            raise

            return queues

        except Exception as e:
            self.logger.error(f"Failed to discover queues: {str(e)}")
            raise

    def _analyze_queue(self, instance_id: str, queue_summary: Dict[str, Any]) -> Queue:
        """
        Analyze a single queue and extract detailed configuration.

        Args:
            instance_id: The Connect instance ID
            queue_summary: Queue summary from list_queues API

        Returns:
            Queue: Analyzed queue object
        """
        queue_id = queue_summary["Id"]
        queue_arn = queue_summary["Arn"]

        # Handle different possible field names for queue name
        queue_name = queue_summary.get("Name") or queue_summary.get("QueueName") or "Unknown"
        queue_description = queue_summary.get("Description")

        # Get detailed queue information
        queue_details = self._get_queue_details(instance_id, queue_id)

        return Queue(
            id=queue_id,
            arn=queue_arn,
            name=queue_name,
            description=queue_description,
            status=queue_details.get("status"),
            max_contacts=queue_details.get("max_contacts"),
            outbound_caller_config=queue_details.get("outbound_caller_config"),
        )

    def _get_queue_details(self, instance_id: str, queue_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a queue.

        Args:
            instance_id: The Connect instance ID
            queue_id: The queue ID

        Returns:
            Dict[str, Any]: Detailed queue information
        """
        try:
            response = self.call_api_resilient(
                self.connect_client,
                "describe_queue",
                "connect",
                InstanceId=instance_id,
                QueueId=queue_id,
            )

            queue_details = response.get("Queue", {})

            return {
                "status": queue_details.get("Status"),
                "max_contacts": queue_details.get("MaxContacts"),
                "outbound_caller_config": queue_details.get("OutboundCallerConfig"),
                "hours_of_operation_id": queue_details.get("HoursOfOperationId"),
            }

        except Exception as e:
            error_message = str(e)

            # Handle specific AWS errors more gracefully
            if self.is_resource_not_found(e):
                self.logger.debug(f"Queue {queue_id} no longer exists (may have been deleted)")
                # Track orphaned queue references for reporting
                if not hasattr(self, "_orphaned_queues"):
                    self._orphaned_queues = []
                self._orphaned_queues.append(queue_id)
                return {}
            else:
                self.logger.warning(f"Failed to get queue details for {queue_id}: {error_message}")
                raise

    def _discover_routing_profiles(self, instance_id: str) -> List[RoutingProfile]:
        """
        Discover and analyze all routing profiles in a Connect instance.

        Args:
            instance_id: The Connect instance ID

        Returns:
            List[RoutingProfile]: List of analyzed routing profiles
        """
        routing_profiles = []

        try:
            # List all routing profiles
            for page in self.paginate_api_resilient(
                self.connect_client,
                "list_routing_profiles",
                "connect",
                InstanceId=instance_id,
            ):
                profile_summaries = page.get("RoutingProfileSummaryList", [])

                for profile_summary in profile_summaries:
                    try:
                        routing_profile = self._analyze_routing_profile(
                            instance_id, profile_summary
                        )
                        routing_profiles.append(routing_profile)
                        self.logger.debug(f"Analyzed routing profile: {routing_profile.name}")
                    except Exception as e:
                        self.logger.error(
                            f"Failed to analyze routing profile {profile_summary.get('Id', 'unknown')}: {str(e)}"
                        )
                        if not self.is_resource_not_found(e):
                            raise

            return routing_profiles

        except Exception as e:
            self.logger.error(f"Failed to discover routing profiles: {str(e)}")
            raise

    def _analyze_routing_profile(
        self, instance_id: str, profile_summary: Dict[str, Any]
    ) -> RoutingProfile:
        """
        Analyze a single routing profile and extract detailed configuration.

        Args:
            instance_id: The Connect instance ID
            profile_summary: Routing profile summary from list_routing_profiles API

        Returns:
            RoutingProfile: Analyzed routing profile object
        """
        profile_id = profile_summary["Id"]
        profile_arn = profile_summary["Arn"]
        profile_name = profile_summary["Name"]

        # Get detailed routing profile information
        profile_details = self._get_routing_profile_details(instance_id, profile_id)

        return RoutingProfile(
            id=profile_id,
            arn=profile_arn,
            name=profile_name,
            description=profile_details.get("description"),
            default_outbound_queue_id=profile_details.get("default_outbound_queue_id"),
            queue_configs=profile_details.get("queue_configs", []),
        )

    def _get_routing_profile_details(self, instance_id: str, profile_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a routing profile.

        Args:
            instance_id: The Connect instance ID
            profile_id: The routing profile ID

        Returns:
            Dict[str, Any]: Detailed routing profile information
        """
        try:
            response = self.call_api_resilient(
                self.connect_client,
                "describe_routing_profile",
                "connect",
                InstanceId=instance_id,
                RoutingProfileId=profile_id,
            )

            profile_details = response.get("RoutingProfile", {})

            # Check for orphaned queue references in routing profile
            queue_configs = profile_details.get("QueueConfigs", [])
            for queue_config in queue_configs:
                queue_reference = queue_config.get("QueueReference", {})
                queue_id = queue_reference.get("QueueId")
                if (
                    queue_id
                    and hasattr(self, "_orphaned_queues")
                    and queue_id in self._orphaned_queues
                ):
                    self.logger.debug(
                        f"Routing profile {profile_id} references orphaned queue {queue_id}"
                    )

            return {
                "description": profile_details.get("Description"),
                "default_outbound_queue_id": profile_details.get("DefaultOutboundQueueId"),
                "queue_configs": queue_configs,
                "media_concurrencies": profile_details.get("MediaConcurrencies", []),
            }

        except Exception as e:
            error_message = str(e)

            # Handle specific AWS errors more gracefully
            if self.is_resource_not_found(e):
                self.logger.debug(
                    f"Routing profile {profile_id} no longer exists (may have been deleted)"
                )
                return {}
            else:
                self.logger.warning(
                    f"Failed to get routing profile details for {profile_id}: {error_message}"
                )
                raise

    def get_queue_summary(self, queues: List[Queue]) -> Dict[str, Any]:
        """
        Generate a summary of queue analysis results.

        Args:
            queues: List of analyzed queues

        Returns:
            Dict[str, Any]: Summary of queue analysis
        """
        if not queues:
            return {"total_queues": 0}

        queue_statuses = {}
        queues_with_max_contacts = 0
        queues_with_outbound_config = 0

        for queue in queues:
            # Count queue statuses
            if queue.status:
                queue_statuses[queue.status] = queue_statuses.get(queue.status, 0) + 1

            # Count queues with max contacts configured
            if queue.max_contacts is not None:
                queues_with_max_contacts += 1

            # Count queues with outbound caller configuration
            if queue.outbound_caller_config:
                queues_with_outbound_config += 1

        return {
            "total_queues": len(queues),
            "queue_statuses": queue_statuses,
            "queues_with_max_contacts": queues_with_max_contacts,
            "queues_with_outbound_config": queues_with_outbound_config,
            "max_contacts_percentage": (
                (queues_with_max_contacts / len(queues)) * 100 if queues else 0
            ),
            "outbound_config_percentage": (
                (queues_with_outbound_config / len(queues)) * 100 if queues else 0
            ),
        }

    def get_routing_profile_summary(self, routing_profiles: List[RoutingProfile]) -> Dict[str, Any]:
        """
        Generate a summary of routing profile analysis results.

        Args:
            routing_profiles: List of analyzed routing profiles

        Returns:
            Dict[str, Any]: Summary of routing profile analysis
        """
        if not routing_profiles:
            return {"total_routing_profiles": 0}

        profiles_with_default_queue = 0
        total_queue_configs = 0

        for profile in routing_profiles:
            # Count profiles with default outbound queue
            if profile.default_outbound_queue_id:
                profiles_with_default_queue += 1

            # Count total queue configurations
            total_queue_configs += len(profile.queue_configs)

        avg_queue_configs = total_queue_configs / len(routing_profiles) if routing_profiles else 0

        return {
            "total_routing_profiles": len(routing_profiles),
            "profiles_with_default_queue": profiles_with_default_queue,
            "total_queue_configs": total_queue_configs,
            "average_queue_configs_per_profile": round(avg_queue_configs, 2),
            "default_queue_percentage": (
                (profiles_with_default_queue / len(routing_profiles)) * 100
                if routing_profiles
                else 0
            ),
        }

    def get_orphaned_queue_summary(self) -> Dict[str, Any]:
        """
        Generate a summary of orphaned queue references found during analysis.

        Returns:
            Dict[str, Any]: Summary of orphaned queue analysis
        """
        if not hasattr(self, "_orphaned_queues") or not self._orphaned_queues:
            return {
                "orphaned_queue_count": 0,
                "has_orphaned_queues": False,
                "orphaned_queue_ids": [],
            }

        return {
            "orphaned_queue_count": len(self._orphaned_queues),
            "has_orphaned_queues": True,
            "orphaned_queue_ids": self._orphaned_queues,
            "cleanup_recommendation": (
                "Consider reviewing routing profiles and other configurations "
                "to remove references to deleted queues."
            ),
        }
