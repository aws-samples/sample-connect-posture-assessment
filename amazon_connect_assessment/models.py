"""
Core data models for the Amazon Connect Assessment Tool.

This module defines the primary data structures used throughout the assessment
process, including assessment results, findings, and Connect instance representations.
"""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional


class Pillar(Enum):
    """AWS Well-Architected Framework pillars for assessment categorization."""

    RESILIENCE = "resilience"
    SECURITY = "security"
    COST_OPTIMIZATION = "cost_optimization"
    OPERATIONAL_EXCELLENCE = "operational_excellence"
    PERFORMANCE_EFFICIENCY = "performance_efficiency"


class Severity(Enum):
    """Severity levels for assessment findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class CheckStatus(Enum):
    """Status values for check execution results.

    ``NOT_APPLICABLE`` is distinct from ``SKIPPED``:
      * ``SKIPPED``        — we could not evaluate (IAM AccessDenied, API missing).
      * ``NOT_APPLICABLE`` — evaluation ran and determined the check does not
        apply to this instance (for example, an ACGR audit sub-check when no
        traffic distribution group is configured). N/A findings are excluded
        from the pass-rate denominator and shown distinctly in the report.
    """

    PASS = "pass"  # nosec B105 - enum status value, not a credential
    FAIL = "fail"
    ERROR = "error"
    SKIPPED = "skipped"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class RemediationStep:
    """A single concrete, prescriptive remediation action."""

    order: int
    instruction: str  # Resource-specific, prescriptive text
    command: Optional[str] = None  # Exact CLI/API command, if applicable
    console_path: Optional[str] = None  # e.g., "Connect console -> Routing -> Queues"


@dataclass
class RemediationReference:
    """A documentation or API reference supporting a remediation."""

    title: str
    url: str


@dataclass
class Remediation:
    """
    Structured, evidence-specific remediation for a finding (Requirement 42).

    Unlike the legacy flat ``remediation`` string, this names the exact flagged
    resource(s), gives ordered prescriptive steps, marks user-supplied
    placeholders, and carries an "applies if relevant" qualifier so users can
    dismiss contextual recommendations that do not fit their requirements.
    """

    summary: str
    steps: List[RemediationStep] = field(default_factory=list)
    target_resources: List[str] = field(default_factory=list)
    references: List[RemediationReference] = field(default_factory=list)
    applies_if: Optional[str] = None
    placeholders: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """
    Represents the result of a single check execution.

    Contains all information about a specific assessment finding including
    the check details, result status, and remediation guidance.
    """

    check_id: str
    check_name: str
    pillar: Pillar
    severity: Severity
    status: CheckStatus
    resource_id: str
    resource_type: str
    description: str
    remediation: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    # Optional structured, evidence-specific remediation (Requirement 42).
    # The flat ``remediation`` string above is auto-derived from this when set,
    # so existing report rendering and exports remain backward compatible.
    structured_remediation: Optional["Remediation"] = None


@dataclass
class ContactFlow:
    """Represents an Amazon Connect contact flow configuration."""

    id: str
    arn: str
    name: str
    type: str
    state: str
    description: Optional[str] = None
    content: Optional[Dict[str, Any]] = None


@dataclass
class Queue:
    """Represents an Amazon Connect queue configuration."""

    id: str
    arn: str
    name: str
    description: Optional[str] = None
    status: Optional[str] = None
    max_contacts: Optional[int] = None
    outbound_caller_config: Optional[Dict[str, Any]] = None


@dataclass
class RoutingProfile:
    """Represents an Amazon Connect routing profile configuration."""

    id: str
    arn: str
    name: str
    description: Optional[str] = None
    default_outbound_queue_id: Optional[str] = None
    queue_configs: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class User:
    """Represents an Amazon Connect user configuration."""

    id: str
    arn: str
    username: str
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    email: Optional[str] = None
    phone_config: Optional[Dict[str, Any]] = None
    security_profile_ids: List[str] = field(default_factory=list)
    routing_profile_id: Optional[str] = None


@dataclass
class SecurityProfile:
    """Represents an Amazon Connect security profile configuration."""

    id: str
    arn: str
    security_profile_name: str
    description: Optional[str] = None
    permissions: List[str] = field(default_factory=list)


@dataclass
class Integration:
    """Represents an Amazon Connect integration (Lambda, Lex, S3, etc.)."""

    integration_type: str
    resource_arn: str
    resource_id: str
    configuration: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ConnectInstance:
    """
    Represents a complete Amazon Connect instance with all its components.

    This is the primary data structure for holding all Connect configuration
    data that will be analyzed during the assessment process.
    """

    instance_id: str
    instance_arn: str
    identity_management_type: str
    inbound_calls_enabled: bool
    outbound_calls_enabled: bool
    instance_alias: Optional[str] = None
    service_role: Optional[str] = None
    status: Optional[str] = None
    contact_flows: List[ContactFlow] = field(default_factory=list)
    queues: List[Queue] = field(default_factory=list)
    routing_profiles: List[RoutingProfile] = field(default_factory=list)
    users: List[User] = field(default_factory=list)
    security_profiles: List[SecurityProfile] = field(default_factory=list)
    integrations: List[Integration] = field(default_factory=list)

    @property
    def display_name(self) -> str:
        """
        Human-friendly identifier for use in finding descriptions.

        Returns the instance alias (the name the user chose when creating the
        instance) with the UUID in parentheses for disambiguation — falling
        back to just the UUID when no alias is set. Use this in every
        user-facing string; keep ``instance_id`` for machine-readable fields
        like ``Finding.resource_id`` and evidence dicts.
        """
        if self.instance_alias:
            return f"'{self.instance_alias}' ({self.instance_id})"
        return self.instance_id


@dataclass
class AssessmentSummary:
    """Summary statistics for an assessment execution.

    ``not_applicable_checks`` counts findings that ran to completion but
    determined the check did not apply (see :class:`CheckStatus`). It is
    kept separate from ``skipped_checks`` (which means "we could not
    evaluate") and is excluded from the pass-rate denominator downstream.
    Defaulted so existing callers that predate the field keep working.
    """

    total_checks: int
    passed_checks: int
    failed_checks: int
    error_checks: int
    skipped_checks: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    not_applicable_checks: int = 0
    # ``total_checks`` remains the backward-compatible total number of
    # check-like results in ``findings``. These fields make the two sources
    # explicit: registry checks and Caller Journey findings.
    registered_checks: Optional[int] = None
    journey_findings: int = 0


@dataclass
class AssessmentMetadata:
    """Metadata information for an assessment execution."""

    tool_version: str
    execution_time_seconds: float
    aws_account_id: str
    aws_region: str
    execution_environment: str
    python_version: str


@dataclass
class AssessmentResult:
    """
    Complete result of an Amazon Connect assessment execution.

    Contains all findings, metadata, and summary information from
    a complete assessment run across one or more Connect instances.

    ``journey_map_entries`` powers the Caller Journey Map section of the
    HTML report. It's a **phone-number-driven** view: one entry per
    (instance, DID/toll-free) pair with a flow association (resolved
    via ``connect:ListFlowAssociations`` — see
    ``AssessmentEngine._compute_journey_map`` for why
    ``ListPhoneNumbersV2``'s ``TargetArn`` cannot be used for this).
    Shape per entry::

        {
            "instance_id":            "...",
            "instance_display_name":  "sushant-cc",
            "phone_number":           "+18005551234",
            "phone_type":             "DID" | "TOLL_FREE" | ...,
            "phone_country_code":     "US",
            "phone_description":      "" | "...",
            "flow_id":                "...",
            "flow_name":              "Main IVR",
            "flow_type":              "CONTACT_FLOW",
            "mermaid_diagram":        "flowchart LR\\n  ...",
            "fallback_html":          "<div class=\\"journey-fallback\\">...",
        }

    Rationale for phone-first framing: only flows a real inbound number
    terminates on are worth surfacing as "customer experience" — the
    rest are subflows, test flows, or AWS-provided templates that no
    caller ever enters directly.
    """

    assessment_id: str
    timestamp: datetime
    account_id: str
    region: str
    instances: List[ConnectInstance]
    findings: List[Finding]
    summary: AssessmentSummary
    metadata: AssessmentMetadata
    execution_errors: List[str] = field(default_factory=list)
    journey_map_entries: List[Dict[str, Any]] = field(default_factory=list)
    # ``journey_map_status`` explains why the Caller Journey Map section
    # is empty when it is. Never populated when ``journey_map_entries``
    # is non-empty. Shape: ``{"reason": <slug>, "message":
    # <plain-English>, "hint": <what to change to see the map>}``.
    # Defaults to None so the report can distinguish "not run" (None)
    # from "ran and produced nothing" (dict with reason).
    journey_map_status: Optional[Dict[str, str]] = None


# ---------------------------------------------------------------------------
# Contact Flow graph models (Phase 1 — Contact Flow Parser)
#
# These structures represent a parsed Amazon Connect contact flow as a directed
# graph so that checks can analyze error handling, loops, authentication,
# personalization, transfers, self-service containment, and complexity.
# ---------------------------------------------------------------------------


@dataclass
class FlowTransition:
    """An edge in the contact flow graph (a transition between two actions)."""

    source_action_id: str
    target_action_id: str
    condition: Optional[str] = None  # Branch condition label, if any
    transition_type: str = "default"  # "default" | "error" | "condition"


@dataclass
class FlowAction:
    """A single action (node) within a contact flow graph."""

    action_id: str
    action_type: str  # e.g., "InvokeLambdaFunction", "TransferToQueue"
    parameters: Dict[str, Any] = field(default_factory=dict)
    transitions: List[FlowTransition] = field(default_factory=list)
    error_transitions: List[FlowTransition] = field(default_factory=list)
    # Read-only resource details resolved during assessment for reader-facing
    # projections. Kept separate from parameters/raw_json so parsing and
    # round-trip fidelity remain unchanged.
    resource_details: Dict[str, Any] = field(default_factory=dict)
    # Preserve the original action JSON verbatim for round-trip fidelity.
    raw_json: Dict[str, Any] = field(default_factory=dict)

    @property
    def all_transitions(self) -> List[FlowTransition]:
        """All outgoing transitions including error branches."""
        return self.transitions + self.error_transitions


@dataclass
class ContactFlowGraph:
    """Directed graph representation of a parsed contact flow."""

    flow_id: str
    flow_name: str
    flow_type: str
    actions: Dict[str, FlowAction] = field(default_factory=dict)
    entry_point_id: str = ""
    version: str = "2019-10-30"
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def action_count(self) -> int:
        return len(self.actions)

    @property
    def transition_count(self) -> int:
        return sum(len(a.all_transitions) for a in self.actions.values())


@dataclass
class CycleInfo:
    """Information about a detected cycle in a contact flow."""

    cycle_actions: List[str]  # Ordered action IDs forming the cycle
    has_bounded_exit: bool  # Whether the cycle has a bounded exit condition
    exit_condition_type: Optional[str] = None  # "loop_count" | "timeout" | "condition"


@dataclass
class FlowPattern:
    """A behavioral pattern detected within a contact flow."""

    pattern_type: str  # "authentication" | "personalization" | "transfer" | "self_service"
    action_ids: List[str] = field(default_factory=list)
    confidence: float = 1.0  # 0.0 - 1.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class FlowStructuralMetrics:
    """Descriptive structural metrics for a contact flow.

    These values support architecture review; they are not an AWS compliance
    score and are not compared with invented pass/fail thresholds.
    """

    total_actions: int
    reachable_actions: int
    longest_route_transitions: int
    route_analysis_capped: bool
    integration_points: int
    cycle_count: int
    paths_enumerated: int
    path_enumeration_capped: bool
    module_invocations: int
