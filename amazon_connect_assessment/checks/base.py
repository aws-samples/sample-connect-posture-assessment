"""
Base check interface and context for Amazon Connect assessments.

Defines the standard interface that all assessment checks must implement,
along with the context object that provides access to assessment data.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from ..models import (
    CheckStatus,
    ConnectInstance,
    Finding,
    Pillar,
    Remediation,
    Severity,
)

if TYPE_CHECKING:
    from ..aws_client_factory import AWSClientFactory


@dataclass
class CheckContext:
    """
    Context object providing assessment data to checks.

    Contains all the necessary data and configuration that checks need
    to perform their evaluations, including Connect instance data and
    assessment configuration.
    """

    instance: ConnectInstance
    aws_client_factory: "AWSClientFactory"
    config: Dict[str, Any]
    logger: logging.Logger


class BaseCheck(ABC):
    """
    Abstract base class for all Amazon Connect assessment checks.

    All assessment checks must inherit from this class and implement
    the execute method. Provides standard interface for check metadata,
    execution, and remediation guidance.
    """

    def __init__(
        self,
        check_id: str,
        name: str,
        pillar: Pillar,
        severity: Severity,
        description: str = "",
        remediation_template: str = "",
    ):
        """
        Initialize a new assessment check.

        Args:
            check_id: Unique identifier for this check
            name: Human-readable name for this check
            pillar: AWS Well-Architected Framework pillar
            severity: Severity level for findings from this check
            description: Detailed description of what this check validates
            remediation_template: Template for remediation guidance
        """
        self.check_id = check_id
        self.name = name
        self.pillar = pillar
        self.severity = severity
        self.description = description
        self.remediation_template = remediation_template
        self.logger = logging.getLogger(f"check.{check_id}")

    @abstractmethod
    def execute(self, context: CheckContext) -> Finding:
        """
        Execute the assessment check against the provided context.

        This method must be implemented by all concrete check classes.
        It should perform the actual assessment logic and return a Finding
        with the results.

        Args:
            context: CheckContext containing instance data and configuration

        Returns:
            Finding: Result of the check execution

        Raises:
            Exception: Any errors during check execution should be caught
                      and converted to a Finding with ERROR status
        """
        pass

    def get_remediation_guidance(self, evidence: Dict[str, Any] = None) -> str:
        """
        Generate remediation guidance for this check.

        Can be overridden by specific checks to provide dynamic guidance
        based on the evidence collected during check execution.

        Args:
            evidence: Optional evidence data from check execution

        Returns:
            str: Remediation guidance text
        """
        return self.remediation_template

    def create_finding(
        self,
        status: CheckStatus,
        resource_id: str,
        resource_type: str,
        description: str = None,
        evidence: Dict[str, Any] = None,
        structured_remediation: Optional[Remediation] = None,
        remediation: str = None,
        severity: Optional[Severity] = None,
    ) -> Finding:
        """
        Helper method to create a Finding object for this check.

        Args:
            status: Result status of the check
            resource_id: ID of the resource being checked
            resource_type: Type of the resource being checked
            description: Optional custom description
            evidence: Optional evidence data
            structured_remediation: Optional structured, evidence-specific
                remediation (Requirement 42). When provided, the flat
                ``remediation`` string is derived from it.
            remediation: Optional explicit flat remediation string. Ignored
                when ``structured_remediation`` is provided.
            severity: Optional per-finding severity override. Defaults to
                the check's declared severity. Use this when a single
                check has multiple failure modes with different
                severities (e.g. a HIGH failure for wildcard values and
                a LOW observation for the "not-configured" case).

        Returns:
            Finding: Configured Finding object
        """
        if structured_remediation is not None:
            remediation_text = self._flatten_remediation(structured_remediation)
        elif remediation is not None:
            remediation_text = remediation
        else:
            remediation_text = self.get_remediation_guidance(evidence)

        return Finding(
            check_id=self.check_id,
            check_name=self.name,
            pillar=self.pillar,
            severity=severity if severity is not None else self.severity,
            status=status,
            resource_id=resource_id,
            resource_type=resource_type,
            description=description or self.description,
            remediation=remediation_text,
            evidence=evidence or {},
            structured_remediation=structured_remediation,
        )

    @staticmethod
    def _flatten_remediation(remediation: Remediation) -> str:
        """
        Render a ``Remediation`` into the legacy flat string so existing report
        rendering and JSON/CSV exports remain backward compatible.
        """
        lines: List[str] = [remediation.summary]
        for step in sorted(remediation.steps, key=lambda s: s.order):
            line = f"{step.order}. {step.instruction}"
            if step.console_path:
                line += f"\n   Console: {step.console_path}"
            if step.command:
                line += f"\n   $ {step.command}"
            lines.append(line)
        if remediation.target_resources:
            lines.append("Targets: " + ", ".join(remediation.target_resources))
        if remediation.applies_if:
            lines.append(f"Applies if relevant: {remediation.applies_if}")
        if remediation.references:
            for ref in remediation.references:
                lines.append(f"Reference: {ref.title} - {ref.url}")
        return "\n".join(lines)

    def skipped_for_access_denied(
        self,
        context: "CheckContext",
        required_permission: str,
        resource_id: str = None,
        resource_type: str = "ConnectInstance",
    ) -> Finding:
        """
        Build a standardized SKIPPED finding for insufficient permissions.

        Centralizes the graceful-degradation behavior required across all
        API-backed checks: a denied AWS call yields SKIPPED (never ERROR/FAIL),
        with the missing permission recorded for the operator to grant.
        """
        return self.create_finding(
            status=CheckStatus.SKIPPED,
            resource_id=resource_id or context.instance.instance_id,
            resource_type=resource_type,
            description=(
                f"Skipped: insufficient permissions. This check requires "
                f"'{required_permission}'. Grant it and re-run to evaluate."
            ),
            evidence={"required_permission": required_permission},
        )

    def not_applicable(
        self,
        context: "CheckContext",
        reason: str,
        resource_id: str = None,
        resource_type: str = "ConnectInstance",
        evidence: Dict[str, Any] = None,
        structured_remediation: Optional[Remediation] = None,
    ) -> Finding:
        """
        Build a standardized NOT_APPLICABLE finding.

        Use when the check ran to completion and determined it does not apply
        to this instance (e.g., an ACGR sub-check when no traffic distribution
        group is configured). Distinct from SKIPPED, which means the check
        could not be evaluated at all (usually due to IAM AccessDenied).

        The report excludes NOT_APPLICABLE findings from the pass-rate
        denominator and renders them with a neutral badge, so they do not
        clutter the reader's attention.

        ``structured_remediation`` is optional for checks whose subject does
        not apply by default but that still need conditional guidance. Set the
        remediation's ``applies_if`` so readers can distinguish that guidance
        from a generally required action.
        """
        merged_evidence = {"reason": reason}
        if evidence:
            merged_evidence.update(evidence)
        return self.create_finding(
            status=CheckStatus.NOT_APPLICABLE,
            resource_id=resource_id or context.instance.instance_id,
            resource_type=resource_type,
            description=f"Not applicable: {reason}",
            evidence=merged_evidence,
            structured_remediation=structured_remediation,
        )

    def safe_execute(self, context: CheckContext) -> Finding:
        """
        Execute the check with error handling.

        Wraps the execute method with try/catch to ensure that check
        failures don't crash the entire assessment process.

        Args:
            context: CheckContext for check execution

        Returns:
            Finding: Result of check execution or error finding
        """
        try:
            self.logger.debug(f"Executing check {self.check_id}")
            result = self.execute(context)
            self.logger.debug(f"Check {self.check_id} completed with status {result.status}")
            return result
        except Exception as e:
            self.logger.error(f"Check {self.check_id} failed with error: {str(e)}")
            return self.create_finding(
                status=CheckStatus.ERROR,
                resource_id=context.instance.instance_id,
                resource_type="ConnectInstance",
                description=f"Check execution failed: {str(e)}",
                evidence={"error": str(e), "error_type": type(e).__name__},
            )

    def __str__(self) -> str:
        """String representation of the check."""
        return f"{self.check_id}: {self.name} ({self.pillar.value}, {self.severity.value})"

    def __repr__(self) -> str:
        """Detailed string representation of the check."""
        return (
            f"BaseCheck(check_id='{self.check_id}', name='{self.name}', "
            f"pillar={self.pillar}, severity={self.severity})"
        )
