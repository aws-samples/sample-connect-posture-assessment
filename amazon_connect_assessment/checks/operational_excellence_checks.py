"""
Operational Excellence checks (Phase 6 / Task 13).

- ops-logging-001     : Contact flow logging enabled (Req 17.1-17.2)
- ops-early-media-001 : Early media for outbound calls (Req 17.3)
- ops-auto-resolve-001: Auto-resolve best-effort tasks (Req 17.4)

``ops-logging-001`` evaluates the instance-wide ``CONTACTFLOW_LOGS``
attribute. Amazon Connect does not expose a per-flow logging toggle, so
``journey-scope-001`` separately evaluates whether individual flows are
active or dormant using phone-number associations and traffic topology.
"""

from ..models import (
    CheckStatus,
    Pillar,
    Remediation,
    RemediationStep,
    Severity,
)
from .base import BaseCheck, CheckContext


class ContactFlowLoggingCheck(BaseCheck):
    """Verify contact flow logging is enabled (Req 17.1-17.2)."""

    def __init__(self):
        super().__init__(
            check_id="ops-logging-001",
            name="Contact Flow Logging",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            severity=Severity.HIGH,
            description=(
                "Checks the instance-wide contact flow logging switch "
                "(connect:DescribeInstanceAttribute, CONTACTFLOW_LOGS). "
                "This is an instance-level setting, not a per-flow control; "
                "see `journey-scope-001` for which flows are active or dormant."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.call_api_with_resilience(
                factory.get_connect_client(),
                "describe_instance_attribute",
                "connect",
                InstanceId=instance.instance_id,
                AttributeType="CONTACTFLOW_LOGS",
            )
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:DescribeInstanceAttribute")
            raise

        enabled = resp.get("Attribute", {}).get("Value", "false").lower() == "true"
        evidence = {"contact_flow_logs_enabled": enabled}

        if not enabled:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"**Contact flow logging is off for instance "
                    f"{instance.display_name}.** This is an instance-wide "
                    "switch; Amazon Connect has no per-flow equivalent.\n\n"
                    "Without it, branch choices, Lambda results, and transfer "
                    "failures do not produce the structured flow log needed to "
                    "reconstruct what happened on a reported contact.\n\n"
                    "This check cannot determine whether an individual flow is "
                    "active, published, or associated with live traffic. See "
                    "`journey-scope-001` for that separate topology-based scope."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Enable contact flow logging.",
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Enable contact flow logging in the instance "
                                "settings. Logs go to a CloudWatch Log Group "
                                "named /aws/connect/<instance-alias>."
                            ),
                            console_path=(
                                "Connect console -> Instance -> Contact flow -> Enable logging"
                            ),
                        ),
                    ],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Contact flow logging is enabled for instance {instance.display_name}. "
                "The instance-wide setting applies uniformly to its flows and "
                "provides CloudWatch log records for flow actions."
            ),
            evidence=evidence,
        )


class EarlyMediaCheck(BaseCheck):
    """Check early media for outbound calls (Req 17.3)."""

    def __init__(self):
        super().__init__(
            check_id="ops-early-media-001",
            name="Early Media for Outbound Calls",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            severity=Severity.LOW,
            description=(
                "Checks whether early media audio is enabled for outbound "
                "calls (improves agent experience by hearing ringing/busy)."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.call_api_with_resilience(
                factory.get_connect_client(),
                "describe_instance_attribute",
                "connect",
                InstanceId=instance.instance_id,
                AttributeType="EARLY_MEDIA",
            )
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:DescribeInstanceAttribute")
            raise

        enabled = resp.get("Attribute", {}).get("Value", "false").lower() == "true"
        evidence = {"early_media_enabled": enabled}

        if not enabled:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description="Early media is disabled for outbound calls.",
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Enable early media for outbound calls.",
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Enable early media in the instance telephony "
                                "settings so agents hear ringing/busy tones."
                            ),
                            console_path="Connect console -> Telephony",
                        ),
                    ],
                    applies_if="outbound calling is used.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description="Early media is enabled.",
            evidence=evidence,
        )


class AutoResolveTasksCheck(BaseCheck):
    """Report on the AUTO_RESOLVE_BEST_VOICES instance attribute (SSML fallback)."""

    def __init__(self):
        super().__init__(
            check_id="ops-auto-resolve-001",
            # NOTE: the check id retains its historical slug so external
            # references (dashboards, allowlists) keep working, but the
            # name/description are corrected. The old name "Auto-Resolve
            # Best-Effort Tasks" was wrong on two counts: (1) the attribute
            # queried is `AUTO_RESOLVE_BEST_VOICES`, which is about SSML
            # <voice> tag locale fallback for text-to-speech, and (2) it
            # has nothing to do with the Task channel in Amazon Connect.
            name="SSML Voice Locale Fallback (AUTO_RESOLVE_BEST_VOICES)",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            severity=Severity.LOW,
            description=(
                "Reports whether the `AUTO_RESOLVE_BEST_VOICES` instance "
                "attribute is enabled. When on, Amazon Connect automatically "
                "substitutes an equivalent Amazon Polly voice from the same "
                "locale if a flow's SSML `<voice>` tag names a voice that "
                "is unavailable — a resilience feature for TTS prompts."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.call_api_with_resilience(
                factory.get_connect_client(),
                "describe_instance_attribute",
                "connect",
                InstanceId=instance.instance_id,
                AttributeType="AUTO_RESOLVE_BEST_VOICES",
            )
        except Exception:
            # This attribute may not exist on all instances; treat as unconfigured.
            resp = {"Attribute": {"Value": "false"}}

        enabled = resp.get("Attribute", {}).get("Value", "false").lower() == "true"

        if enabled:
            description = (
                f"Connect instance {instance.display_name} has "
                "`AUTO_RESOLVE_BEST_VOICES` **enabled**. If any of your "
                'contact flows use SSML `<voice name="...">` tags and the '
                "named voice becomes unavailable (retired, region-limited, "
                "language mismatch), Connect will automatically substitute "
                "another voice from the same locale rather than failing the "
                "prompt. No action needed — this is a resilience feature."
            )
        else:
            description = (
                f"Connect instance {instance.display_name} has "
                "`AUTO_RESOLVE_BEST_VOICES` **disabled**. If a flow uses "
                'SSML `<voice name="...">` tags and the named voice '
                "becomes unavailable, the prompt may fall through to error "
                "handling instead of speaking. Only relevant if you use "
                "SSML voice overrides in your flows; the default TTS path "
                "(no `<voice>` tag) is unaffected."
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=description,
            evidence={"auto_resolve_best_voices_enabled": enabled},
        )


def register_operational_excellence_checks(registry) -> None:
    """Register all operational excellence checks."""
    registry.register_check(ContactFlowLoggingCheck())
    registry.register_check(EarlyMediaCheck())
    registry.register_check(AutoResolveTasksCheck())
