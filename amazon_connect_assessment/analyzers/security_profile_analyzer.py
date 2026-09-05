"""
Security Profile Analyzer for Amazon Connect Assessment Tool.

This module provides functionality to analyze Amazon Connect security profiles,
extracting permission configurations, access controls, and security settings.
"""

import logging
from typing import Any, Dict, List

from ..models import ConnectInstance, SecurityProfile
from .base import BaseAnalyzer


class SecurityProfileAnalyzer(BaseAnalyzer):
    """
    Analyzer for Amazon Connect security profiles.

    Analyzes security profile configurations including permissions, access controls,
    and security settings to identify potential security risks and compliance issues.
    """

    def __init__(self, aws_client_factory, config: Dict[str, Any] = None):
        """
        Initialize the Security Profile Analyzer.

        Args:
            aws_client_factory: AWSClientFactory instance for AWS service clients
            config: Optional configuration dictionary for analyzer behavior
        """
        super().__init__(aws_client_factory, config)
        self.logger = logging.getLogger("analyzer.SecurityProfileAnalyzer")

    def analyze(self, instance: ConnectInstance) -> ConnectInstance:
        """
        Analyze security profiles for a Connect instance.

        Args:
            instance: ConnectInstance object to populate with security profile data

        Returns:
            ConnectInstance: Updated instance with security profile analysis data
        """
        try:
            self.logger.debug(f"Analyzing security profiles for instance {instance.instance_id}")

            security_profiles = self._discover_security_profiles(instance.instance_id)
            instance.security_profiles = security_profiles

            self.logger.info(
                f"Analyzed {len(security_profiles)} security profiles for instance {instance.instance_id}"
            )
            return instance

        except Exception as e:
            self.logger.error(
                f"Failed to analyze security profiles for instance {instance.instance_id}: {str(e)}"
            )
            raise

    def _discover_security_profiles(self, instance_id: str) -> List[SecurityProfile]:
        """
        Discover and analyze all security profiles in a Connect instance.

        Args:
            instance_id: The Connect instance ID

        Returns:
            List[SecurityProfile]: List of analyzed security profiles
        """
        security_profiles = []

        try:
            # List all security profiles
            for page in self.paginate_api_resilient(
                self.connect_client,
                "list_security_profiles",
                "connect",
                InstanceId=instance_id,
            ):
                profile_summaries = page.get("SecurityProfileSummaryList", [])

                for profile_summary in profile_summaries:
                    try:
                        security_profile = self._analyze_security_profile(
                            instance_id, profile_summary
                        )
                        security_profiles.append(security_profile)
                        self.logger.debug(
                            f"Analyzed security profile: {security_profile.security_profile_name}"
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Failed to analyze security profile {profile_summary.get('Id', 'unknown')}: {str(e)}"
                        )
                        self.logger.debug(
                            "Security profile summary keys for failed profile: "
                            f"{sorted(profile_summary.keys())}"
                        )
                        if not self.is_resource_not_found(e):
                            raise

            return security_profiles

        except Exception as e:
            self.logger.error(f"Failed to discover security profiles: {str(e)}")
            raise

    def _analyze_security_profile(
        self, instance_id: str, profile_summary: Dict[str, Any]
    ) -> SecurityProfile:
        """
        Analyze a single security profile and extract detailed configuration.

        Args:
            instance_id: The Connect instance ID
            profile_summary: Security profile summary from list_security_profiles API

        Returns:
            SecurityProfile: Analyzed security profile object
        """
        profile_id = profile_summary["Id"]
        profile_arn = profile_summary["Arn"]

        # The API returns 'Name' field, not 'SecurityProfileName'
        profile_name = (
            profile_summary.get("Name") or profile_summary.get("SecurityProfileName") or "Unknown"
        )

        # Get detailed security profile information
        profile_details = self._get_security_profile_details(instance_id, profile_id)

        return SecurityProfile(
            id=profile_id,
            arn=profile_arn,
            security_profile_name=profile_name,
            description=profile_details.get("description"),
            permissions=profile_details.get("permissions", []),
        )

    def _get_security_profile_details(self, instance_id: str, profile_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a security profile.

        Args:
            instance_id: The Connect instance ID
            profile_id: The security profile ID

        Returns:
            Dict[str, Any]: Detailed security profile information
        """
        try:
            response = self.call_api_resilient(
                self.connect_client,
                "describe_security_profile",
                "connect",
                InstanceId=instance_id,
                SecurityProfileId=profile_id,
            )

            profile_details = response.get("SecurityProfile", {})

            # Extract permissions from the security profile
            permissions = self._extract_permissions(profile_details)

            return {
                "description": profile_details.get("Description"),
                "permissions": permissions,
                "organization_resource_id": profile_details.get("OrganizationResourceId"),
                "allowed_access_control_tags": profile_details.get("AllowedAccessControlTags", {}),
                "tag_restricted_resources": profile_details.get("TagRestrictedResources", []),
            }

        except Exception as e:
            self.logger.warning(
                f"Failed to get security profile details for {profile_id}: {str(e)}"
            )
            raise

    def _extract_permissions(self, profile_details: Dict[str, Any]) -> List[str]:
        """
        Extract and categorize permissions from security profile details.

        Args:
            profile_details: Security profile details from describe_security_profile API

        Returns:
            List[str]: List of permissions granted by this security profile
        """
        permissions = []

        # Extract permissions from different sections
        if "Permissions" in profile_details:
            permissions.extend(profile_details["Permissions"])

        # Extract allowed access control tags as permissions
        allowed_tags = profile_details.get("AllowedAccessControlTags", {})
        for tag_key, tag_values in allowed_tags.items():
            permissions.append(f"tag:{tag_key}:{','.join(tag_values)}")

        # Extract tag-restricted resources
        tag_restricted = profile_details.get("TagRestrictedResources", [])
        for resource in tag_restricted:
            permissions.append(f"tag_restricted:{resource}")

        return permissions

    def analyze_security_risks(self, security_profiles: List[SecurityProfile]) -> Dict[str, Any]:
        """
        Analyze security profiles for potential security risks and compliance issues.

        Args:
            security_profiles: List of security profiles to analyze

        Returns:
            Dict[str, Any]: Security risk analysis results
        """
        if not security_profiles:
            return {"total_profiles": 0, "risks": []}

        risks = []
        high_privilege_profiles = []
        profiles_without_description = []
        overly_permissive_profiles = []

        for profile in security_profiles:
            # Check for profiles without descriptions
            if not profile.description or profile.description.strip() == "":
                profiles_without_description.append(profile.security_profile_name)

            # Check for overly permissive profiles (many permissions)
            if len(profile.permissions) > 20:  # Configurable threshold
                overly_permissive_profiles.append(
                    {
                        "name": profile.security_profile_name,
                        "permission_count": len(profile.permissions),
                    }
                )

            # Check for high-privilege permissions
            high_privilege_keywords = [
                "admin",
                "administrator",
                "manage",
                "delete",
                "create",
                "modify",
                "full",
                "all",
                "*",
            ]

            has_high_privilege = any(
                any(keyword in perm.lower() for keyword in high_privilege_keywords)
                for perm in profile.permissions
            )

            if has_high_privilege:
                high_privilege_profiles.append(profile.security_profile_name)

        # Generate risk findings
        if profiles_without_description:
            risks.append(
                {
                    "type": "missing_descriptions",
                    "severity": "medium",
                    "description": "Security profiles without descriptions make it difficult to understand their purpose",
                    "affected_profiles": profiles_without_description,
                    "count": len(profiles_without_description),
                }
            )

        if overly_permissive_profiles:
            risks.append(
                {
                    "type": "overly_permissive",
                    "severity": "high",
                    "description": "Security profiles with excessive permissions may violate principle of least privilege",
                    "affected_profiles": overly_permissive_profiles,
                    "count": len(overly_permissive_profiles),
                }
            )

        if high_privilege_profiles:
            risks.append(
                {
                    "type": "high_privilege",
                    "severity": "high",
                    "description": "Security profiles with high-privilege permissions require careful review",
                    "affected_profiles": high_privilege_profiles,
                    "count": len(high_privilege_profiles),
                }
            )

        return {
            "total_profiles": len(security_profiles),
            "risks": risks,
            "risk_count": len(risks),
            "profiles_at_risk": len(
                set(
                    profiles_without_description
                    + [p["name"] for p in overly_permissive_profiles]
                    + high_privilege_profiles
                )
            ),
        }

    def get_security_profile_summary(
        self, security_profiles: List[SecurityProfile]
    ) -> Dict[str, Any]:
        """
        Generate a summary of security profile analysis results.

        Args:
            security_profiles: List of analyzed security profiles

        Returns:
            Dict[str, Any]: Summary of security profile analysis
        """
        if not security_profiles:
            return {"total_security_profiles": 0}

        total_permissions = sum(len(profile.permissions) for profile in security_profiles)
        avg_permissions = total_permissions / len(security_profiles) if security_profiles else 0

        profiles_with_description = sum(
            1
            for profile in security_profiles
            if profile.description and profile.description.strip()
        )

        # Analyze permission distribution
        permission_counts = [len(profile.permissions) for profile in security_profiles]
        min_permissions = min(permission_counts) if permission_counts else 0
        max_permissions = max(permission_counts) if permission_counts else 0

        return {
            "total_security_profiles": len(security_profiles),
            "total_permissions": total_permissions,
            "average_permissions_per_profile": round(avg_permissions, 2),
            "min_permissions": min_permissions,
            "max_permissions": max_permissions,
            "profiles_with_description": profiles_with_description,
            "description_percentage": (
                (profiles_with_description / len(security_profiles)) * 100
                if security_profiles
                else 0
            ),
        }
