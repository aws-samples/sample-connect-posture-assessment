"""
Tests for IVRToAgentDataContinuityCheck (cost-data-continuity-001).

Focused on the reviewer-driven description rewrite -- the original was a
single terse line the reviewer said lacked context. Trigger logic itself
(3+ inputs collected, fewer than 2 persisted as attributes, before a
queue transfer) is unchanged and covered here for completeness.
"""

from amazon_connect_assessment.checks.cost_containment_checks import (
    IVRToAgentDataContinuityCheck,
)
from amazon_connect_assessment.models import CheckStatus, ContactFlow
from tests.conftest import build_action, build_contact_flow


def _instance_with_flow(instance, flow_json, name="TestFlow"):
    instance.contact_flows = [
        ContactFlow(
            id="f1",
            arn="arn:...:flow/f1",
            name=name,
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=flow_json,
        )
    ]
    return instance


class TestIVRToAgentDataContinuityCheck:
    def test_many_inputs_few_attributes_before_queue_fails(
        self, make_check_context, sample_connect_instance
    ):
        flow = build_contact_flow(
            [
                build_action(
                    "a1", "GetParticipantInput", {"Text": "Account number?"}, next_action="a2"
                ),
                build_action(
                    "a2", "GetUserInput", {"Text": "Reason for calling?"}, next_action="a3"
                ),
                build_action(
                    "a3", "GetParticipantInput", {"Text": "Callback number?"}, next_action="a4"
                ),
                build_action("a4", "TransferToQueue", {"QueueId": "q1"}),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = IVRToAgentDataContinuityCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL
        # Reviewer feedback: the original description was a single terse
        # line. It must now explain what "input collection" and
        # "persisting" mean in this context, and the cost angle.
        assert "screen pop" in finding.description.lower()
        assert "TestFlow" in finding.description

    def test_inputs_persisted_as_attributes_passes(
        self, make_check_context, sample_connect_instance
    ):
        flow = build_contact_flow(
            [
                build_action(
                    "a1", "GetParticipantInput", {"Text": "Account number?"}, next_action="a2"
                ),
                build_action(
                    "a2",
                    "SetContactAttributes",
                    {"Attributes": {"AccountNumber": "$.StoredCustomerInput"}},
                    next_action="a3",
                ),
                build_action(
                    "a3", "GetUserInput", {"Text": "Reason for calling?"}, next_action="a4"
                ),
                build_action(
                    "a4",
                    "UpdateContactAttributes",
                    {"Attributes": {"Reason": "$.StoredCustomerInput"}},
                    next_action="a5",
                ),
                build_action(
                    "a5", "GetParticipantInput", {"Text": "Callback number?"}, next_action="a6"
                ),
                build_action("a6", "TransferToQueue", {"QueueId": "q1"}),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = IVRToAgentDataContinuityCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS

    def test_no_queue_transfer_passes(self, make_check_context, sample_connect_instance):
        # Fewer than 3 inputs collected, or no queue transfer at all --
        # either way, the check only fires for the specific IVR-then-agent
        # shape.
        flow = build_contact_flow(
            [build_action("a1", "GetParticipantInput", {"Text": "Account number?"})]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = IVRToAgentDataContinuityCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS
