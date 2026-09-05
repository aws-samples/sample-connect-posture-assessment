"""
Tests for contact flow behavior checks (Phase 5 / Task 11).

Focused on AuthenticationPatternCheck's reviewer-driven changes: excluding
AWS's default "Sample ..." flows from the count, downgraded severity, and
the "this is optional" framing. Other checks in this module
(PersonalizationAnalysisCheck, ErrorHandlingCompletenessCheck,
LoopDetectionCheck) are exercised indirectly elsewhere and are not
otherwise touched by this change.
"""

from amazon_connect_assessment.checks.contact_flow_behavior_checks import (
    AuthenticationPatternCheck,
)
from amazon_connect_assessment.models import CheckStatus, ContactFlow, Severity
from tests.conftest import build_action, build_contact_flow


def _instance_with_flows(instance, flows):
    """Attach multiple (name, flow_json) pairs as distinct ContactFlow objects."""
    instance.contact_flows = [
        ContactFlow(
            id=f"f{i}",
            arn=f"arn:...:flow/f{i}",
            name=name,
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=flow_json,
        )
        for i, (name, flow_json) in enumerate(flows)
    ]
    return instance


class TestAuthenticationPatternCheck:
    def test_severity_is_low_not_medium(self):
        # Reviewer feedback: authentication is optional and depends on
        # business requirements, not a universal defect — downgraded
        # from MEDIUM.
        assert AuthenticationPatternCheck().severity == Severity.LOW

    def test_unauthenticated_queue_transfer_fails(
        self, make_check_context, sample_connect_instance
    ):
        flow = build_contact_flow([build_action("a1", "TransferToQueue", {"QueueId": "q1"})])
        inst = _instance_with_flows(sample_connect_instance, [("My Support Flow", flow)])
        finding = AuthenticationPatternCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL
        assert "optional" in finding.description.lower()

    def test_authenticated_queue_transfer_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "GetParticipantInput",
                    {"Text": "Enter your PIN"},
                    next_action="a2",
                ),
                build_action("a2", "TransferToQueue", {"QueueId": "q1"}),
            ]
        )
        inst = _instance_with_flows(sample_connect_instance, [("My Support Flow", flow)])
        finding = AuthenticationPatternCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS

    def test_sample_flows_excluded_from_unprotected_count(
        self, make_check_context, sample_connect_instance
    ):
        # AWS's default sample flows route to queues to demonstrate the
        # pattern, not because a real account operation is exposed —
        # flagging them would just report on AWS's own demo content.
        sample_flow = build_contact_flow(
            [build_action("s1", "TransferToQueue", {"QueueId": "q-sample"})]
        )
        customer_flow = build_contact_flow(
            [
                build_action(
                    "c1",
                    "GetParticipantInput",
                    {"Text": "Enter your account PIN"},
                    next_action="c2",
                ),
                build_action("c2", "TransferToQueue", {"QueueId": "q-real"}),
            ]
        )
        inst = _instance_with_flows(
            sample_connect_instance,
            [
                ("Sample queued callback flow", sample_flow),
                ("My Account Support Flow", customer_flow),
            ],
        )
        finding = AuthenticationPatternCheck().execute(make_check_context(instance=inst))
        # The sample flow is unauthenticated but excluded; the only
        # customer flow analyzed is authenticated, so this passes.
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["flows_analyzed"] == 1
        assert finding.evidence["sample_flows_excluded"] == 1

    def test_sample_flow_alone_is_not_applicable_for_unprotected_count(
        self, make_check_context, sample_connect_instance
    ):
        sample_flow = build_contact_flow(
            [build_action("s1", "TransferToQueue", {"QueueId": "q-sample"})]
        )
        inst = _instance_with_flows(sample_connect_instance, [("Sample AB test", sample_flow)])
        finding = AuthenticationPatternCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["flows_analyzed"] == 0
        assert finding.evidence["sample_flows_excluded"] == 1
