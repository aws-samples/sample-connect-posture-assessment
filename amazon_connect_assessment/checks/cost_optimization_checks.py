"""
Cost Optimization checks for Amazon Connect Assessment Tool.

This module implements checks for the Cost Optimization pillar of the AWS Well-Architected
Framework, focusing on unused resources, oversized configurations, and inefficient
resource allocation for Amazon Connect deployments.

AWS Well-Architected Framework Reference:
https://docs.aws.amazon.com/wellarchitected/latest/cost-optimization-pillar/welcome.html
"""

from ..models import CheckStatus, Finding, Pillar, Severity
from .base import BaseCheck, CheckContext


class UnusedResourcesCheck(BaseCheck):
    """
    Check for unused resources that may be incurring unnecessary costs.

    AWS Well-Architected Framework: Cost Optimization Pillar - Design Principle 1
    "Implement cloud financial management"

    Reference: https://docs.aws.amazon.com/connect/latest/adminguide/monitoring-cloudwatch.html
    """

    def __init__(self):
        super().__init__(
            check_id="cost-unused-001",
            name="Unused Resources Check",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.LOW,
            description=(
                "Flags configuration clutter — security profiles, routing "
                "profiles, or queues with no users assigned. This is an "
                "operational-hygiene observation, not a cost-savings "
                "estimate: Amazon Connect does not charge per queue, "
                "routing profile, or security profile, so removing these "
                "will not reduce your bill. It's worth doing anyway because "
                "unused configuration is confusing to administer and can "
                "hide a setup mistake (e.g. a queue nobody ever finished "
                "wiring up)."
            ),
            remediation_template="Clean up unused configuration for operational clarity: 1) Review and remove inactive users who haven't logged in recently, 2) Remove unused queues that aren't receiving calls, 3) Consolidate redundant routing profiles, 4) Archive unused contact flows, 5) Review and remove unnecessary integrations. Note: none of this reduces your Amazon Connect bill directly (there is no per-resource charge for these) — it reduces administrative overhead and the chance of misconfiguration.",
        )

    def execute(self, context: CheckContext) -> Finding:
        """
        Execute unused resources check.

        Args:
            context: CheckContext containing instance data and AWS clients

        Returns:
            Finding: Result of the unused resources check
        """
        instance = context.instance

        try:
            evidence = {
                "instance_id": instance.instance_id,
                "total_users": len(instance.users),
                "total_queues": len(instance.queues),
                "total_routing_profiles": len(instance.routing_profiles),
                "total_contact_flows": len(instance.contact_flows),
                "total_security_profiles": len(instance.security_profiles),
            }

            unused_resources = []
            # Renamed from "cost_savings_opportunities": Amazon Connect does
            # not charge per security profile, routing profile, or queue, so
            # cleaning these up does not reduce spend. This is administrative
            # hygiene guidance, not a cost lever.
            cleanup_recommendations = []

            # Check for excessive number of security profiles
            if len(instance.security_profiles) > len(instance.users) + 2:
                unused_resources.append(
                    f"Potentially excessive security profiles ({len(instance.security_profiles)} profiles for {len(instance.users)} users)"
                )
                cleanup_recommendations.append("Review and consolidate security profiles")

            # Check for users without routing profiles (potentially inactive)
            users_without_routing = [user for user in instance.users if not user.routing_profile_id]

            if users_without_routing:
                evidence["users_without_routing_profiles"] = len(users_without_routing)
                unused_resources.append(
                    f"{len(users_without_routing)} users without routing profiles (potentially inactive)"
                )
                cleanup_recommendations.append(
                    "Review users without routing profiles for deactivation"
                )

            # Check for routing profiles without associated users
            user_routing_profile_ids = {
                user.routing_profile_id for user in instance.users if user.routing_profile_id
            }

            unused_routing_profiles = [
                rp for rp in instance.routing_profiles if rp.id not in user_routing_profile_ids
            ]

            if unused_routing_profiles:
                evidence["unused_routing_profiles"] = len(unused_routing_profiles)
                unused_resources.append(
                    f"{len(unused_routing_profiles)} routing profiles not assigned to any users"
                )
                cleanup_recommendations.append("Remove unused routing profiles")

            # Check for queues without routing profile associations
            # This is a simplified check - in practice, we'd need to analyze routing profile configurations
            if len(instance.queues) > len(instance.routing_profiles) * 2:
                unused_resources.append(
                    f"High queue-to-routing-profile ratio ({len(instance.queues)} queues, {len(instance.routing_profiles)} routing profiles)"
                )
                cleanup_recommendations.append(
                    "Review queue utilization and consolidate if possible"
                )

            # Check for minimal usage patterns (MVP implementation)
            if len(instance.users) == 0 and len(instance.queues) > 0:
                unused_resources.append(
                    "Queues configured but no users - potential unused resources"
                )
                cleanup_recommendations.append("Remove unused queues or add users")

            if len(instance.contact_flows) == 0 and (
                len(instance.queues) > 0 or len(instance.users) > 0
            ):
                unused_resources.append(
                    "Users/queues configured but no contact flows - incomplete setup may indicate unused resources"
                )
                cleanup_recommendations.append("Complete setup or remove unused components")

            evidence["unused_resources_identified"] = len(unused_resources)
            evidence["cleanup_recommendations"] = cleanup_recommendations

            if unused_resources:
                return self.create_finding(
                    status=CheckStatus.FAIL,
                    resource_id=instance.instance_id,
                    resource_type="ConnectInstance",
                    description=(
                        f"Connect instance {instance.display_name} has "
                        f"unused configuration: {'; '.join(unused_resources)}.\n\n"
                        "**Operational note, not a cost-savings estimate.** "
                        "Amazon Connect doesn't charge per security profile, "
                        "routing profile, or queue — cleaning these up won't "
                        "lower your bill. It's worth reviewing anyway because "
                        "unused configuration adds administrative overhead "
                        "and can be a symptom of an incomplete setup."
                    ),
                    evidence=evidence,
                )

            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=f"Connect instance {instance.display_name} shows no obvious unused configuration.",
                evidence=evidence,
            )

        except Exception as e:
            self.logger.error(f"Error executing unused resources check: {str(e)}")
            return self.create_finding(
                status=CheckStatus.ERROR,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=f"Failed to execute unused resources check: {str(e)}",
                evidence={"error": str(e)},
            )


class OversizedConfigurationCheck(BaseCheck):
    """
    Check for oversized configurations that may be incurring unnecessary costs.

    AWS Well-Architected Framework: Cost Optimization Pillar - Design Principle 2
    "Adopt a consumption model"

    Reference: https://aws.amazon.com/connect/pricing/
    """

    def __init__(self):
        super().__init__(
            check_id="cost-oversized-001",
            name="Oversized Configuration Check",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.LOW,
            description=(
                "Flags ratios of security profiles, routing profiles, and "
                "queues to users that suggest over-provisioned "
                "configuration. Amazon Connect does not charge per "
                "security profile, routing profile, or queue, so this is "
                "an administrative-clarity observation rather than a "
                "cost-savings estimate — worth a look for maintainability, "
                "not because it's adding to your bill."
            ),
            remediation_template="Right-size your Connect configuration for administrative clarity: 1) Consolidate security profiles with overlapping permissions, 2) Consolidate routing profiles with similar configurations, 3) Review queue necessity relative to routing profiles, 4) Review whether all users are necessary given the queue count. None of this reduces your Amazon Connect bill directly (there is no per-resource charge for these) — it reduces administrative overhead.",
        )

    def execute(self, context: CheckContext) -> Finding:
        """
        Execute oversized configuration check.

        Args:
            context: CheckContext containing instance data and AWS clients

        Returns:
            Finding: Result of the oversized configuration check
        """
        instance = context.instance

        try:
            evidence = {
                "instance_id": instance.instance_id,
                "users_count": len(instance.users),
                "queues_count": len(instance.queues),
                "routing_profiles_count": len(instance.routing_profiles),
                "contact_flows_count": len(instance.contact_flows),
                "security_profiles_count": len(instance.security_profiles),
            }

            oversizing_issues = []
            optimization_recommendations = []

            # Check for excessive security profiles relative to users
            if len(instance.users) > 0:
                security_profile_ratio = len(instance.security_profiles) / len(instance.users)
                evidence["security_profile_to_user_ratio"] = security_profile_ratio

                if security_profile_ratio > 0.5:  # More than 1 security profile per 2 users
                    oversizing_issues.append(
                        f"High security profile to user ratio ({security_profile_ratio:.2f})"
                    )
                    optimization_recommendations.append(
                        "Consolidate security profiles with similar permissions"
                    )

            # Check for excessive routing profiles
            if len(instance.users) > 0:
                routing_profile_ratio = len(instance.routing_profiles) / len(instance.users)
                evidence["routing_profile_to_user_ratio"] = routing_profile_ratio

                if routing_profile_ratio > 0.3:  # More than 1 routing profile per 3 users
                    oversizing_issues.append(
                        f"High routing profile to user ratio ({routing_profile_ratio:.2f})"
                    )
                    optimization_recommendations.append(
                        "Consolidate routing profiles with similar configurations"
                    )

            # Check for excessive queues relative to routing profiles
            if len(instance.routing_profiles) > 0:
                queue_to_routing_ratio = len(instance.queues) / len(instance.routing_profiles)
                evidence["queue_to_routing_profile_ratio"] = queue_to_routing_ratio

                if queue_to_routing_ratio > 3:  # More than 3 queues per routing profile
                    oversizing_issues.append(
                        f"High queue to routing profile ratio ({queue_to_routing_ratio:.2f})"
                    )
                    optimization_recommendations.append(
                        "Review queue necessity and consolidate where possible"
                    )

            # NOTE: a prior version of this check flagged "high number of
            # contact flows relative to other components" (flows >
            # users + queues + routing profiles) as an oversizing issue.
            # That heuristic had no defensible basis and was removed after
            # review: Amazon Connect does not charge per contact flow, so
            # there is no cost angle, and AWS's own best-practice guidance
            # explicitly recommends *more, smaller* modular flows combined
            # into an end-to-end experience rather than a few large ones —
            # https://docs.aws.amazon.com/connect/latest/adminguide/bp-contact-flows.html.
            # A high flow count relative to users/queues is the expected
            # shape for an instance following that guidance, not a defect.
            # Total component count is still surfaced in evidence below for
            # context, without treating flow count itself as a problem.
            evidence["total_components_for_reference"] = (
                len(instance.users) + len(instance.queues) + len(instance.routing_profiles)
            )

            # Check for minimal configurations that might indicate over-provisioning
            if len(instance.users) > 10 and len(instance.queues) == 1:
                oversizing_issues.append(
                    "Many users configured with only one queue - may indicate over-provisioning"
                )
                optimization_recommendations.append(
                    "Review if all users are necessary or if additional queues are needed"
                )

            evidence["oversizing_issues_count"] = len(oversizing_issues)
            evidence["optimization_recommendations"] = optimization_recommendations

            if oversizing_issues:
                return self.create_finding(
                    status=CheckStatus.FAIL,
                    resource_id=instance.instance_id,
                    resource_type="ConnectInstance",
                    description=(
                        f"Connect instance {instance.display_name} has "
                        f"configuration ratios worth a look: {'; '.join(oversizing_issues)}.\n\n"
                        "**Operational note, not a cost-savings estimate.** "
                        "Amazon Connect doesn't charge per security profile, "
                        "routing profile, or queue, so this doesn't affect "
                        "your bill directly. It's flagged for administrative "
                        "clarity — a high ratio can make the instance harder "
                        "to maintain or be a sign of leftover configuration "
                        "from an earlier setup."
                    ),
                    evidence=evidence,
                )

            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=f"Connect instance {instance.display_name} shows no unusual configuration ratios.",
                evidence=evidence,
            )

        except Exception as e:
            self.logger.error(f"Error executing oversized configuration check: {str(e)}")
            return self.create_finding(
                status=CheckStatus.ERROR,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=f"Failed to execute oversized configuration check: {str(e)}",
                evidence={"error": str(e)},
            )


class InefficientResourceAllocationCheck(BaseCheck):
    """
    Check for inefficient resource allocation patterns.

    AWS Well-Architected Framework: Cost Optimization Pillar - Design Principle 3
    "Measure overall efficiency"

    Reference: https://docs.aws.amazon.com/connect/latest/adminguide/optimization.html
    """

    def __init__(self):
        super().__init__(
            check_id="cost-inefficient-001",
            name="Inefficient Resource Allocation Check",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.MEDIUM,
            description="Identifies inefficient resource allocation patterns including unbalanced queue distributions, suboptimal routing configurations, and resource allocation mismatches",
            remediation_template="Optimize resource allocation: 1) Balance queue distributions across routing profiles, 2) Ensure users have appropriate routing profile assignments, 3) Review contact flow efficiency and eliminate redundant steps, 4) Optimize integration usage to reduce API calls, 5) Implement proper resource tagging for cost tracking and allocation.",
        )

    def execute(self, context: CheckContext) -> Finding:
        """
        Execute inefficient resource allocation check.

        Args:
            context: CheckContext containing instance data and AWS clients

        Returns:
            Finding: Result of the inefficient resource allocation check
        """
        instance = context.instance

        try:
            evidence = {
                "instance_id": instance.instance_id,
                "total_components": len(instance.users)
                + len(instance.queues)
                + len(instance.routing_profiles)
                + len(instance.contact_flows),
            }

            inefficiency_issues = []
            optimization_recommendations = []

            # Check for unbalanced user-to-queue ratios
            if len(instance.users) > 0 and len(instance.queues) > 0:
                user_queue_ratio = len(instance.users) / len(instance.queues)
                evidence["user_to_queue_ratio"] = user_queue_ratio

                if user_queue_ratio > 10:  # More than 10 users per queue
                    inefficiency_issues.append(
                        f"High user-to-queue ratio ({user_queue_ratio:.1f}) may cause bottlenecks"
                    )
                    optimization_recommendations.append(
                        "Consider adding more queues to distribute load"
                    )
                elif user_queue_ratio < 0.5:  # Less than 1 user per 2 queues
                    inefficiency_issues.append(
                        f"Low user-to-queue ratio ({user_queue_ratio:.1f}) may indicate over-provisioning"
                    )
                    optimization_recommendations.append(
                        "Consider consolidating queues or adding more users"
                    )

            # Check for users without proper routing profile assignments
            users_with_routing = [user for user in instance.users if user.routing_profile_id]
            if len(instance.users) > 0:
                routing_assignment_ratio = len(users_with_routing) / len(instance.users)
                evidence["users_with_routing_assignment_ratio"] = routing_assignment_ratio

                if routing_assignment_ratio < 1.0:
                    unassigned_users = len(instance.users) - len(users_with_routing)
                    inefficiency_issues.append(
                        f"{unassigned_users} users without routing profile assignments"
                    )
                    optimization_recommendations.append(
                        "Assign routing profiles to all active users"
                    )

            # Check for routing profiles without users
            if len(instance.routing_profiles) > 0:
                user_routing_ids = {
                    user.routing_profile_id for user in instance.users if user.routing_profile_id
                }
                unused_routing_profiles = [
                    rp for rp in instance.routing_profiles if rp.id not in user_routing_ids
                ]

                if unused_routing_profiles:
                    evidence["unused_routing_profiles_count"] = len(unused_routing_profiles)
                    inefficiency_issues.append(
                        f"{len(unused_routing_profiles)} routing profiles not assigned to users"
                    )
                    optimization_recommendations.append(
                        "Remove unused routing profiles or assign them to users"
                    )

            # Check for integration efficiency
            if len(instance.integrations) > 0:
                evidence["integrations_count"] = len(instance.integrations)

                # Group integrations by type
                integration_types = {}
                for integration in instance.integrations:
                    integration_type = integration.integration_type
                    integration_types[integration_type] = (
                        integration_types.get(integration_type, 0) + 1
                    )

                evidence["integration_types"] = integration_types

                # Check for excessive integrations of the same type
                for integration_type, count in integration_types.items():
                    if count > 3:  # More than 3 integrations of the same type
                        inefficiency_issues.append(
                            f"Multiple {integration_type} integrations ({count}) may be inefficient"
                        )
                        optimization_recommendations.append(
                            f"Review and consolidate {integration_type} integrations"
                        )

            # Check for component balance
            total_components = (
                len(instance.users) + len(instance.queues) + len(instance.routing_profiles)
            )
            if total_components > 0:
                if len(instance.contact_flows) == 0:
                    inefficiency_issues.append(
                        "Components configured but no contact flows - incomplete setup"
                    )
                    optimization_recommendations.append(
                        "Create contact flows to utilize configured components"
                    )
                elif len(instance.contact_flows) > total_components * 2:
                    inefficiency_issues.append(
                        "Excessive contact flows relative to other components"
                    )
                    optimization_recommendations.append("Review and consolidate contact flows")

            evidence["inefficiency_issues_count"] = len(inefficiency_issues)
            evidence["optimization_recommendations"] = optimization_recommendations

            if inefficiency_issues:
                return self.create_finding(
                    status=CheckStatus.FAIL,
                    resource_id=instance.instance_id,
                    resource_type="ConnectInstance",
                    description=f"Connect instance {instance.display_name} has inefficient resource allocation: {'; '.join(inefficiency_issues)}",
                    evidence=evidence,
                )

            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=f"Connect instance {instance.display_name} shows efficient resource allocation with no obvious inefficiencies identified.",
                evidence=evidence,
            )

        except Exception as e:
            self.logger.error(f"Error executing inefficient resource allocation check: {str(e)}")
            return self.create_finding(
                status=CheckStatus.ERROR,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=f"Failed to execute inefficient resource allocation check: {str(e)}",
                evidence={"error": str(e)},
            )
