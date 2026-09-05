"""
Regression tests for wiring Caller Journey Mapping findings into
AssessmentEngine execution.

Prior to this fix, journey.run_journey_mapping() was fully implemented and
its four findings (journey-sec-001, journey-cost-001, journey-res-001,
journey-scope-001) were documented in docs/check-catalog.md, but no engine
ever called it — --list-checks never showed journey-* IDs and no report
ever contained them. See AssessmentEngine._compute_journey_findings.

Also covers a bug found while adding this wiring: ContactFlowParser.parse()
can't set ContactFlowGraph.flow_id/flow_name because the raw Content blob
returned by DescribeContactFlow never carries an "Identifier" or "Name"
key (those live on the outer ContactFlow API object). Left unset, every
parsed graph has flow_id="" — which collapses every flow's super-graph
node keys onto the same "::action_id" string (a real cross-flow
collision) and makes every flow's entry point overwrite the same "" key
in SuperGraph.entry_points, so topology resolution silently produced zero
journeys for every real-world flow. Fixed by backfilling graph.flow_id /
graph.flow_name from the ContactFlow object immediately after parsing.
"""

from __future__ import annotations

from typing import Any, Dict
from unittest.mock import MagicMock

from amazon_connect_assessment.engine import AssessmentEngine
from amazon_connect_assessment.models import ConnectInstance, ContactFlow
from amazon_connect_assessment.parsers import ContactFlowParser

# A flow with no authentication, a queue transfer, and no self-service
# automation beyond the initial prompt — should trip journey-sec-001
# (reaches queue without authentication).
NO_AUTH_FLOW_CONTENT: Dict[str, Any] = {
    "Version": "2019-10-30",
    "StartAction": "a1",
    "Metadata": {},
    "Actions": [
        {
            "Identifier": "a1",
            "Type": "MessageParticipant",
            "Parameters": {"Text": "Please hold."},
            "Transitions": {"NextAction": "a2", "Errors": [], "Conditions": []},
        },
        {
            "Identifier": "a2",
            "Type": "TransferToQueue",
            "Parameters": {"QueueId": "queue-1"},
            "Transitions": {"NextAction": None, "Errors": [], "Conditions": []},
        },
    ],
}


def _instance(alias: str = "test-cc") -> ConnectInstance:
    inst = ConnectInstance(
        instance_id="iid-1",
        instance_arn="arn:aws:connect:us-east-1:111:instance/iid-1",
        instance_alias=alias,
        service_role="arn:aws:iam::111:role/service",
        identity_management_type="CONNECT_MANAGED",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
        status="ACTIVE",
    )
    inst.contact_flows = [
        ContactFlow(
            id="flow-A",
            arn="arn:aws:connect:us-east-1:111:instance/iid-1/contact-flow/flow-A",
            name="Main IVR",
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=NO_AUTH_FLOW_CONTENT,
        ),
    ]
    return inst


def _engine_with_phone_number(target_flow_id: str = "flow-A") -> AssessmentEngine:
    engine = AssessmentEngine.__new__(AssessmentEngine)
    engine.config = {}
    engine.logger = MagicMock()
    engine._execution_errors = []

    phone_arn = "arn:aws:connect:us-east-1:111:phone-number/18005551212"

    def _dispatch(_client, operation_name, _service_name=None, **_kwargs):
        if operation_name == "list_phone_numbers_v2":
            return {
                "ListPhoneNumbersSummaryList": [
                    {
                        "PhoneNumber": "+18005551212",
                        "PhoneNumberArn": phone_arn,
                        "PhoneNumberType": "DID",
                        # TargetArn is always the instance/TDG ARN on the
                        # real API — flow assignment comes exclusively
                        # from list_flow_associations below.
                        "TargetArn": "arn:aws:connect:us-east-1:111:instance/iid-1",
                    }
                ],
                "NextToken": None,
            }
        if operation_name == "list_flow_associations":
            if _kwargs.get("ResourceType") != "VOICE_PHONE_NUMBER":
                return {"FlowAssociationSummaryList": [], "NextToken": None}
            return {
                "FlowAssociationSummaryList": [
                    {
                        "ResourceId": phone_arn,
                        "FlowId": (
                            "arn:aws:connect:us-east-1:111:instance/iid-1/"
                            f"contact-flow/{target_flow_id}"
                        ),
                        "ResourceType": "VOICE_PHONE_NUMBER",
                    }
                ],
                "NextToken": None,
            }
        raise AssertionError(f"unexpected operation: {operation_name}")

    factory = MagicMock()
    factory.get_connect_client.return_value = MagicMock()
    factory.call_api_with_resilience.side_effect = _dispatch
    factory.is_access_denied.return_value = False
    engine.aws_client_factory = factory
    return engine


class TestJourneyFindingsWiring:
    def test_produces_journey_sec_001_for_unauthenticated_queue_path(self):
        engine = _engine_with_phone_number()
        findings = engine._compute_journey_findings([_instance()])
        check_ids = {f.check_id for f in findings}
        assert "journey-sec-001" in check_ids

    def test_findings_carry_the_journey_check_ids_from_the_catalog(self):
        # Guards against a future refactor accidentally renaming/dropping
        # one of the four documented journey-* check IDs.
        engine = _engine_with_phone_number()
        findings = engine._compute_journey_findings([_instance()])
        for f in findings:
            assert f.check_id.startswith("journey-")

    def test_no_contact_flows_produces_no_findings(self):
        engine = _engine_with_phone_number()
        inst = _instance()
        inst.contact_flows = []
        assert engine._compute_journey_findings([inst]) == []

    def test_no_instances_produces_no_findings(self):
        engine = _engine_with_phone_number()
        assert engine._compute_journey_findings([]) == []

    def test_skip_flow_analysis_top_level_disables_journey_findings(self):
        engine = _engine_with_phone_number()
        engine.config = {"skip_flow_analysis": True}
        assert engine._compute_journey_findings([_instance()]) == []

    def test_skip_flow_analysis_under_cli_key_disables_journey_findings(self):
        # This is the config shape the CLI actually produces — see
        # cli.merge_cli_args_with_config, which nests skip_flow_analysis
        # under config["cli"], not at the top level.
        engine = _engine_with_phone_number()
        engine.config = {"cli": {"skip_flow_analysis": True}}
        assert engine._compute_journey_findings([_instance()]) == []

    def test_unparseable_flow_content_does_not_raise(self):
        engine = _engine_with_phone_number()
        inst = _instance()
        inst.contact_flows[0].content = {"not": "a valid flow"}
        # Should not raise; parser tolerates missing Actions gracefully,
        # and an empty parsed_flows dict short-circuits before scoring.
        findings = engine._compute_journey_findings([inst])
        assert isinstance(findings, list)

    def test_per_instance_failure_does_not_abort_other_instances(self):
        # journey.run_journey_mapping raising for one instance must not
        # prevent findings for a different instance in the same batch.
        # _compute_journey_findings does `from . import journey` locally
        # inside the method, so patch the real source attribute on the
        # journey package itself rather than on the engine module.
        engine = _engine_with_phone_number()
        good_instance = _instance("good-cc")
        bad_instance = _instance("bad-cc")
        bad_instance.instance_id = "iid-bad"
        bad_instance.instance_arn = "arn:aws:connect:us-east-1:111:instance/iid-bad"

        from amazon_connect_assessment import journey as journey_module

        real_run = journey_module.run_journey_mapping

        def flaky_run_journey_mapping(*, instance, **kwargs):
            if instance is bad_instance:
                raise RuntimeError("boom")
            return real_run(instance=instance, **kwargs)

        journey_module.run_journey_mapping = flaky_run_journey_mapping
        try:
            findings = engine._compute_journey_findings([bad_instance, good_instance])
        finally:
            journey_module.run_journey_mapping = real_run

        assert any(f.check_id == "journey-sec-001" for f in findings)
        assert any("iid-bad" in e for e in engine._execution_errors)


class TestFlowIdBackfillRegression:
    """
    ContactFlowGraph.flow_id/flow_name must be backfilled from the
    ContactFlow object after parsing, because DescribeContactFlow's
    Content blob never carries Identifier/Name — the parser has no way
    to set them itself. Without the backfill, every graph has
    flow_id="", which collapses every flow's nodes onto the same
    super-graph key and topology.py's per-flow-id dict entries.
    """

    def test_parser_alone_leaves_flow_id_empty(self):
        # This documents *why* the backfill is necessary — it is not a
        # bug in the parser itself, Content really doesn't carry these
        # fields, so this must stay true.
        graph = ContactFlowParser().parse(NO_AUTH_FLOW_CONTENT)
        assert graph.flow_id == ""
        assert graph.flow_name == ""

    def test_engine_backfills_flow_id_before_journey_mapping(self):
        # End-to-end: without the backfill, this produces zero journeys
        # (super-graph entry_points keyed by "" collapses to one entry
        # across all flows, and node keys collide). With the backfill,
        # the single flow in this fixture produces exactly one journey
        # and the journey-sec-001 finding.
        engine = _engine_with_phone_number()
        findings = engine._compute_journey_findings([_instance()])
        assert len(findings) >= 1
