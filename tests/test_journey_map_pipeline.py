"""
Tests for the phone-number-driven Caller Journey Map pipeline.

The pipeline must:
  * emit one entry per (instance, DID/toll-free) pair with a
    ``VOICE_PHONE_NUMBER`` flow association (resolved via
    ``ListFlowAssociations``, matched by ``PhoneNumberArn``);
  * skip numbers that have no flow association (queues, agents,
    unassigned);
  * cache each flow's Mermaid + fallback render so a flow shared by many
    numbers pays the render cost once;
  * produce a deterministic order (instance display name, then phone
    number);
  * populate ``journey_map_status`` with a specific reason slug when it
    ends up empty.

These are the guarantees the two-dropdown UI relies on. If any of them
break silently, the report goes back to showing empty boxes.

Regression note: an earlier version of this pipeline resolved a
number's flow by checking ``ListPhoneNumbersV2``'s ``TargetArn`` for a
``/contact-flow/`` substring. AWS documents ``TargetArn`` as the
instance/traffic-distribution-group ARN a number is claimed to, not the
flow it's assigned to in the console — that check never matched a
single real-world number, so the map (and its empty-state message)
were wrong for every account, even ones with correctly-configured
numbers. The fixtures below deliberately set ``TargetArn`` to the
instance ARN on every phone number (as the real API always does) and
resolve flow assignment exclusively through the separate
``ListFlowAssociations`` mock, so a regression back to the old
``TargetArn`` check would make every "happy path" test in this file
fail.
"""

from __future__ import annotations

from typing import Any, Dict, List
from unittest.mock import MagicMock

from amazon_connect_assessment.engine import (
    AssessmentEngine,
    _AccessDeniedListingFlowAssociations,
    _AccessDeniedListingPhoneNumbers,
)
from amazon_connect_assessment.models import ConnectInstance, ContactFlow

# ---------------------------------------------------------------------------
# Fixtures + factory helpers
# ---------------------------------------------------------------------------


FLOW_IVR_CONTENT: Dict[str, Any] = {
    "Version": "2019-10-30",
    "StartAction": "a1",
    "Metadata": {},
    "Actions": [
        {
            "Identifier": "a1",
            "Type": "MessageParticipant",
            "Parameters": {"Text": "Welcome to Acme."},
            "Transitions": {"NextAction": "a2", "Errors": [], "Conditions": []},
        },
        {
            "Identifier": "a2",
            "Type": "TransferToQueue",
            "Parameters": {"QueueId": "$.Attributes.MainQueue"},
            "Transitions": {"NextAction": None, "Errors": [], "Conditions": []},
        },
    ],
}

FLOW_SALES_CONTENT: Dict[str, Any] = {
    "Version": "2019-10-30",
    "StartAction": "s1",
    "Metadata": {},
    "Actions": [
        {
            "Identifier": "s1",
            "Type": "MessageParticipant",
            "Parameters": {"Text": "Sales line."},
            "Transitions": {"NextAction": None, "Errors": [], "Conditions": []},
        },
    ],
}

FLOW_AI_CONTENT: Dict[str, Any] = {
    "Version": "2019-10-30",
    "StartAction": "setup",
    "Metadata": {},
    "Actions": [
        {
            "Identifier": "setup",
            "Type": "CreateWisdomSession",
            "Parameters": {
                "WisdomAssistantArn": (
                    "arn:aws:wisdom:us-east-1:111:assistant/71291fb2-5952-451f-b3f8-d32699f148bd"
                )
            },
            "Transitions": {"NextAction": "update", "Errors": [], "Conditions": []},
        },
        {
            "Identifier": "update",
            "Type": "UpdateContactData",
            "Parameters": {},
            "Transitions": {"NextAction": "ai", "Errors": [], "Conditions": []},
        },
        {
            "Identifier": "ai",
            "Type": "ConnectParticipantWithLexBot",
            "Parameters": {
                "Text": "How can I help you today?",
                "LexV2Bot": {
                    "AliasArn": ("arn:aws:lex:us-east-1:111:bot-alias/ALGAULUNIR/TSTALIASID")
                },
            },
            "Transitions": {"NextAction": None, "Errors": [], "Conditions": []},
        },
    ],
}

EMPTY_FLOW_CONTENT: Dict[str, Any] = {
    "Version": "2019-10-30",
    "StartAction": "",
    "Metadata": {},
    "Actions": [],
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
            id="flow-ivr",
            arn="arn:aws:connect:us-east-1:111:instance/iid-1/contact-flow/flow-ivr",
            name="Main IVR",
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=FLOW_IVR_CONTENT,
        ),
        ContactFlow(
            id="flow-sales",
            arn="arn:aws:connect:us-east-1:111:instance/iid-1/contact-flow/flow-sales",
            name="Sales IVR",
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=FLOW_SALES_CONTENT,
        ),
        ContactFlow(
            id="flow-ai",
            arn="arn:aws:connect:us-east-1:111:instance/iid-1/contact-flow/flow-ai",
            name="AI Support",
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=FLOW_AI_CONTENT,
        ),
        ContactFlow(
            id="flow-empty",
            arn="arn:aws:connect:us-east-1:111:instance/iid-1/contact-flow/flow-empty",
            name="Empty default",
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=EMPTY_FLOW_CONTENT,
        ),
    ]
    return inst


def _engine(
    list_response: Any = None,
    flow_associations: Any = None,
    access_denied: bool = False,
    flow_associations_access_denied: bool = False,
) -> AssessmentEngine:
    """
    Build a shell engine with a mocked AWS client factory.

    ``call_api_with_resilience`` is dispatched by operation name so a
    single mock factory can answer both ``list_phone_numbers_v2`` and
    ``list_flow_associations`` calls with independent fixtures (and
    independent access-denied behavior, since the pipeline now makes
    two separate API calls that fail open/closed independently).
    """
    e = AssessmentEngine.__new__(AssessmentEngine)
    e.config = {}
    e.logger = MagicMock()
    factory = MagicMock()
    factory.get_connect_client.return_value = MagicMock()

    list_resp = list_response or {"ListPhoneNumbersSummaryList": [], "NextToken": None}
    flow_resp = flow_associations or {"FlowAssociationSummaryList": [], "NextToken": None}
    empty_flow_resp = {"FlowAssociationSummaryList": [], "NextToken": None}

    def _dispatch(_client, operation_name, _service_name=None, **kwargs):
        if operation_name == "list_phone_numbers_v2":
            if access_denied:
                raise RuntimeError("denied: list_phone_numbers_v2")
            return list_resp
        if operation_name == "list_flow_associations":
            if flow_associations_access_denied:
                raise RuntimeError("denied: list_flow_associations")
            # The engine queries VOICE_PHONE_NUMBER, SMS_PHONE_NUMBER, and
            # WHATSAPP_MESSAGING_PHONE_NUMBER and merges results. Only the
            # VOICE_PHONE_NUMBER call returns the fixture data; the other
            # two return empty so tests can assert on a single fixture
            # without needing to know about every resource type.
            if kwargs.get("ResourceType") == "VOICE_PHONE_NUMBER":
                return flow_resp
            return empty_flow_resp
        raise AssertionError(f"unexpected operation: {operation_name}")

    factory.call_api_with_resilience.side_effect = _dispatch

    def _is_access_denied(exc: Exception) -> bool:
        msg = str(exc)
        if access_denied and "list_phone_numbers_v2" in msg:
            return True
        if flow_associations_access_denied and "list_flow_associations" in msg:
            return True
        return False

    factory.is_access_denied.side_effect = _is_access_denied
    e.aws_client_factory = factory
    return e


def _phone(
    number: str,
    ptype: str = "DID",
    country: str = "US",
    description: str = "",
) -> Dict[str, Any]:
    """
    Build a ``ListPhoneNumbersSummaryList`` entry.

    ``TargetArn`` is always the instance ARN, matching real API
    behavior — flow assignment is conveyed separately via
    :func:`_flow_association`, never via this field.
    """
    number_id = number.lstrip("+")
    return {
        "PhoneNumberId": number_id,
        "PhoneNumberArn": f"arn:aws:connect:us-east-1:111:phone-number/{number_id}",
        "PhoneNumber": number,
        "PhoneNumberType": ptype,
        "PhoneNumberCountryCode": country,
        "PhoneNumberDescription": description,
        "TargetArn": "arn:aws:connect:us-east-1:111:instance/iid-1",
    }


def _flow_association(phone: Dict[str, Any], flow_id: str) -> Dict[str, Any]:
    """Build a ``FlowAssociationSummaryList`` entry binding a phone to a flow."""
    return {
        "ResourceId": phone["PhoneNumberArn"],
        "FlowId": f"arn:aws:connect:us-east-1:111:instance/iid-1/contact-flow/{flow_id}",
        "ResourceType": "VOICE_PHONE_NUMBER",
    }


# ---------------------------------------------------------------------------
# Happy paths
# ---------------------------------------------------------------------------


class TestPhoneToFlowMapping:
    def test_flow_bound_numbers_produce_entries(self):
        p1 = _phone("+18005551212", description="Main")
        p2 = _phone("+18885550000", ptype="TOLL_FREE")
        engine = _engine(
            list_response={
                "ListPhoneNumbersSummaryList": [p1, p2],
                "NextToken": None,
            },
            flow_associations={
                "FlowAssociationSummaryList": [
                    _flow_association(p1, "flow-ivr"),
                    _flow_association(p2, "flow-sales"),
                ],
                "NextToken": None,
            },
        )
        entries, status = engine._compute_journey_map([_instance()])
        assert status is None
        assert len(entries) == 2
        numbers = {e["phone_number"] for e in entries}
        assert numbers == {"+18005551212", "+18885550000"}
        # Rich diagram content should carry actual prompt text.
        ivr_entry = next(e for e in entries if e["flow_id"] == "flow-ivr")
        assert "Welcome to Acme" in ivr_entry["diagram_html"]
        assert "jm-canvas" in ivr_entry["diagram_html"]

    def test_ai_resource_names_are_resolved_before_rendering(self):
        phone = _phone("+18005550123", description="AI support")
        engine = _engine(
            list_response={
                "ListPhoneNumbersSummaryList": [phone],
                "NextToken": None,
            },
            flow_associations={
                "FlowAssociationSummaryList": [_flow_association(phone, "flow-ai")],
                "NextToken": None,
            },
        )
        factory = engine.aws_client_factory
        factory.describe_lex_v2_bot_resilient.return_value = {
            "botId": "ALGAULUNIR",
            "botName": "RTHelpDeskBot",
        }
        factory.describe_lex_v2_bot_alias_resilient.return_value = {
            "botAliasId": "TSTALIASID",
            "botAliasName": "TestBotAlias",
        }
        factory.get_qconnect_assistant_resilient.return_value = {
            "assistant": {
                "assistantId": "71291fb2-5952-451f-b3f8-d32699f148bd",
                "name": "AnyCompany",
                "type": "AGENT",
            }
        }

        entries, status = engine._compute_journey_map([_instance()])
        model = entries[0]["diagram_model"]
        ai_node = next(node for node in model["nodes"].values() if node["ai"])
        setup_node = next(node for node in model["nodes"].values() if node["scope"])

        assert status is None
        assert ai_node["ai"] == {
            "technology": "Amazon Lex",
            "identity": "RTHelpDeskBot",
            "subtype": "V2 bot",
            "alias": "TestBotAlias",
        }
        assert setup_node["scope"] == [
            "Starts an Amazon Q in Connect session with AnyCompany (assistant type: Agent).",
            "Updates contact data used by subsequent flow and routing steps.",
        ]
        factory.describe_lex_v2_bot_resilient.assert_called_once_with("ALGAULUNIR")
        factory.describe_lex_v2_bot_alias_resilient.assert_called_once_with(
            "ALGAULUNIR", "TSTALIASID"
        )
        factory.get_qconnect_assistant_resilient.assert_called_once_with(
            "71291fb2-5952-451f-b3f8-d32699f148bd"
        )

    def test_queue_name_is_resolved_and_inherited_by_transfer_block(self):
        phone = _phone("+18005550125", description="Queue support")
        engine = _engine(
            list_response={"ListPhoneNumbersSummaryList": [phone], "NextToken": None},
            flow_associations={
                "FlowAssociationSummaryList": [_flow_association(phone, "flow-ivr")],
                "NextToken": None,
            },
        )
        instance = _instance()
        queue_id = "57083a00-bd7d-4e1d-ac63-510d7f835a84"
        instance.contact_flows[0].content = {
            "Version": "2019-10-30",
            "StartAction": "select",
            "Metadata": {},
            "Actions": [
                {
                    "Identifier": "select",
                    "Type": "UpdateContactTargetQueue",
                    "Parameters": {
                        "QueueId": (
                            "arn:aws:connect:us-east-1:111:instance/iid-1/queue/" + queue_id
                        )
                    },
                    "Transitions": {
                        "NextAction": "transfer",
                        "Errors": [],
                        "Conditions": [],
                    },
                },
                {
                    "Identifier": "transfer",
                    "Type": "TransferContactToQueue",
                    "Parameters": {},
                    "Transitions": {"Errors": [], "Conditions": []},
                },
            ],
        }
        engine.aws_client_factory.describe_queue_resilient.return_value = {
            "Queue": {"Name": "BasicQueue"}
        }

        entries, status = engine._compute_journey_map([instance])
        transfer = next(
            node
            for node in entries[0]["diagram_model"]["nodes"].values()
            if node["category"] == "waits"
        )

        assert status is None
        assert transfer["scope"] == [
            "Transfers the caller to BasicQueue to wait for an available agent."
        ]
        engine.aws_client_factory.describe_queue_resilient.assert_called_once_with(
            "iid-1", queue_id
        )

    def test_ai_resource_lookup_failure_falls_back_without_hiding_diagram(self):
        phone = _phone("+18005550124")
        engine = _engine(
            list_response={"ListPhoneNumbersSummaryList": [phone], "NextToken": None},
            flow_associations={
                "FlowAssociationSummaryList": [_flow_association(phone, "flow-ai")],
                "NextToken": None,
            },
        )
        factory = engine.aws_client_factory
        factory.describe_lex_v2_bot_resilient.side_effect = RuntimeError("denied")
        factory.describe_lex_v2_bot_alias_resilient.side_effect = RuntimeError("denied")
        factory.get_qconnect_assistant_resilient.side_effect = RuntimeError("denied")

        entries, status = engine._compute_journey_map([_instance()])
        model = entries[0]["diagram_model"]
        ai_node = next(node for node in model["nodes"].values() if node["ai"])

        assert status is None
        assert entries[0]["diagram_html"]
        assert ai_node["ai"] == {
            "technology": "Amazon Lex",
            "identity": "Configured Lex V2 bot",
            "subtype": "V2 bot",
        }
        assert "ALGAULUNIR" not in entries[0]["diagram_html"]
        assert "TSTALIASID" not in entries[0]["diagram_html"]
        setup_node = next(
            node for node in model["nodes"].values() if node["title"].startswith("System setup")
        )
        assert "71291fb2-5952-451f-b3f8-d32699f148bd" not in str(setup_node["scope"])
        assert "configured assistant" in setup_node["scope"][0]

    def test_numbers_without_flow_association_are_excluded(self):
        p1 = _phone("+18005551212")
        p2 = _phone("+18005559999")  # No flow association — points at a queue.
        engine = _engine(
            list_response={
                "ListPhoneNumbersSummaryList": [p1, p2],
                "NextToken": None,
            },
            flow_associations={
                "FlowAssociationSummaryList": [_flow_association(p1, "flow-ivr")],
                "NextToken": None,
            },
        )
        entries, status = engine._compute_journey_map([_instance()])
        assert status is None
        assert len(entries) == 1
        assert entries[0]["phone_number"] == "+18005551212"

    def test_entries_are_sorted_deterministically(self):
        # Same instance, three phone numbers — the JSON island ordering
        # feeds a stable dropdown, so this can't drift.
        p1 = _phone("+18885550000")
        p2 = _phone("+18005551212")
        p3 = _phone("+18005550001")
        engine = _engine(
            list_response={
                "ListPhoneNumbersSummaryList": [p1, p2, p3],
                "NextToken": None,
            },
            flow_associations={
                "FlowAssociationSummaryList": [
                    _flow_association(p1, "flow-sales"),
                    _flow_association(p2, "flow-ivr"),
                    _flow_association(p3, "flow-ivr"),
                ],
                "NextToken": None,
            },
        )
        entries, _ = engine._compute_journey_map([_instance()])
        assert [e["phone_number"] for e in entries] == [
            "+18005550001",
            "+18005551212",
            "+18885550000",
        ]

    def test_shared_flow_renders_once_per_instance(self):
        # Two numbers point at the same flow — we should still produce
        # two entries (one per number) but the diagram/fallback strings
        # come from a single render pass. Simplest check: identical
        # strings for entries that reference the same flow_id.
        p1 = _phone("+18005551212")
        p2 = _phone("+18005551213")
        engine = _engine(
            list_response={
                "ListPhoneNumbersSummaryList": [p1, p2],
                "NextToken": None,
            },
            flow_associations={
                "FlowAssociationSummaryList": [
                    _flow_association(p1, "flow-ivr"),
                    _flow_association(p2, "flow-ivr"),
                ],
                "NextToken": None,
            },
        )
        entries, _ = engine._compute_journey_map([_instance()])
        assert len(entries) == 2
        assert entries[0]["diagram_html"] == entries[1]["diagram_html"]
        assert entries[0]["exports"] == entries[1]["exports"]

    def test_empty_flow_content_is_skipped(self):
        p1 = _phone("+18005551212")
        engine = _engine(
            list_response={
                "ListPhoneNumbersSummaryList": [p1],
                "NextToken": None,
            },
            flow_associations={
                "FlowAssociationSummaryList": [_flow_association(p1, "flow-empty")],
                "NextToken": None,
            },
        )
        entries, status = engine._compute_journey_map([_instance()])
        # No renderable diagram for the only bound number — treat as
        # empty and produce a diagnostic status.
        assert entries == []
        assert status is not None
        assert status["reason"] == "no_renderable_flows"

    def test_entry_shape_carries_expected_fields(self):
        p1 = _phone("+18005551212", description="Main line")
        engine = _engine(
            list_response={
                "ListPhoneNumbersSummaryList": [p1],
                "NextToken": None,
            },
            flow_associations={
                "FlowAssociationSummaryList": [_flow_association(p1, "flow-ivr")],
                "NextToken": None,
            },
        )
        entries, _ = engine._compute_journey_map([_instance()])
        e = entries[0]
        expected_keys = {
            "instance_id",
            "instance_display_name",
            "phone_number",
            "phone_type",
            "phone_country_code",
            "phone_description",
            "flow_id",
            "flow_name",
            "flow_type",
            "diagram_html",
            "diagram_model",
            "exports",
        }
        assert expected_keys <= set(e.keys())
        assert e["phone_description"] == "Main line"
        assert e["flow_name"] == "Main IVR"
        assert e["exports"]["schema_version"] == 1
        assert set(e["exports"]["formats"]) == {"svg", "drawio"}


# ---------------------------------------------------------------------------
# Empty-state diagnostics
# ---------------------------------------------------------------------------


class TestEmptyStateDiagnostics:
    def test_skip_flow_analysis_config(self):
        engine = _engine()
        engine.config = {"skip_flow_analysis": True}
        entries, status = engine._compute_journey_map([_instance()])
        assert entries == []
        assert status["reason"] == "skipped_by_config"

    def test_skip_flow_analysis_under_cli_key_also_works(self):
        # Regression test: the CLI stores this flag under
        # config["cli"]["skip_flow_analysis"] (see
        # cli.merge_cli_args_with_config), not at the top level.
        # _compute_journey_map originally only checked the top-level key,
        # so --skip-flow-analysis never actually disabled the Journey
        # Map's ListPhoneNumbersV2 + flow-render API calls for a real CLI
        # invocation.
        engine = _engine()
        engine.config = {"cli": {"skip_flow_analysis": True}}
        entries, status = engine._compute_journey_map([_instance()])
        assert entries == []
        assert status["reason"] == "skipped_by_config"

    def test_no_instances(self):
        engine = _engine()
        entries, status = engine._compute_journey_map([])
        assert entries == []
        assert status["reason"] == "no_instances"

    def test_list_phone_numbers_denied(self):
        engine = _engine(access_denied=True)
        entries, status = engine._compute_journey_map([_instance()])
        assert entries == []
        assert status["reason"] == "list_phone_numbers_denied"
        assert "ListPhoneNumbersV2" in status["hint"]

    def test_list_flow_associations_denied(self):
        # A role can have ListPhoneNumbersV2 but not ListFlowAssociations
        # — the empty-state hint must name the specific missing
        # permission, not a generic "phone numbers" message.
        engine = _engine(
            list_response={
                "ListPhoneNumbersSummaryList": [_phone("+18005551212")],
                "NextToken": None,
            },
            flow_associations_access_denied=True,
        )
        entries, status = engine._compute_journey_map([_instance()])
        assert entries == []
        assert status["reason"] == "list_phone_numbers_denied"
        assert "ListFlowAssociations" in status["hint"]

    def test_no_numbers_claimed_on_instance(self):
        engine = _engine(list_response={"ListPhoneNumbersSummaryList": [], "NextToken": None})
        entries, status = engine._compute_journey_map([_instance()])
        assert entries == []
        assert status["reason"] == "no_phone_numbers_claimed"

    def test_numbers_without_any_flow_association(self):
        # Numbers exist but none have a VOICE_PHONE_NUMBER flow
        # association — the real-world shape of "every number points
        # at a queue/agent/unassigned" that motivated this pipeline.
        engine = _engine(
            list_response={
                "ListPhoneNumbersSummaryList": [
                    _phone("+18005551212"),
                    _phone("+18005551213"),
                ],
                "NextToken": None,
            },
            flow_associations={"FlowAssociationSummaryList": [], "NextToken": None},
        )
        entries, status = engine._compute_journey_map([_instance()])
        assert entries == []
        assert status["reason"] == "numbers_do_not_target_flows"


# ---------------------------------------------------------------------------
# Robustness / helpers
# ---------------------------------------------------------------------------


class TestListPhoneNumbersHelper:
    def test_access_denied_raises_sentinel(self):
        engine = _engine(access_denied=True)
        try:
            engine._list_phone_numbers_for_instance(_instance())
        except _AccessDeniedListingPhoneNumbers:
            pass  # expected
        else:
            raise AssertionError("expected _AccessDeniedListingPhoneNumbers")

    def test_pagination_is_followed(self):
        # Simulate two pages so we know the loop actually follows
        # NextToken (a common bug in first drafts).
        pages: List[Dict[str, Any]] = [
            {
                "ListPhoneNumbersSummaryList": [_phone("+18005550001")],
                "NextToken": "cursor-1",
            },
            {
                "ListPhoneNumbersSummaryList": [_phone("+18005550002")],
                "NextToken": None,
            },
        ]
        engine = _engine()
        engine.aws_client_factory.call_api_with_resilience.side_effect = pages
        result = engine._list_phone_numbers_for_instance(_instance())
        assert [n["PhoneNumber"] for n in result] == [
            "+18005550001",
            "+18005550002",
        ]


class TestListFlowAssociationsHelper:
    def test_access_denied_raises_sentinel(self):
        engine = _engine(flow_associations_access_denied=True)
        try:
            engine._list_flow_associations_for_instance(_instance())
        except _AccessDeniedListingFlowAssociations:
            pass  # expected
        else:
            raise AssertionError("expected _AccessDeniedListingFlowAssociations")

    def test_pagination_is_followed(self):
        # Simulate two pages for the VOICE_PHONE_NUMBER resource type so
        # we know the loop actually follows NextToken (a common bug in
        # first drafts). Other resource types return a single empty page.
        p1 = _phone("+18005550001")
        p2 = _phone("+18005550002")
        voice_pages: List[Dict[str, Any]] = [
            {
                "FlowAssociationSummaryList": [_flow_association(p1, "flow-ivr")],
                "NextToken": "cursor-1",
            },
            {
                "FlowAssociationSummaryList": [_flow_association(p2, "flow-sales")],
                "NextToken": None,
            },
        ]
        empty_page = {"FlowAssociationSummaryList": [], "NextToken": None}

        def _dispatch(_client, operation_name, _service_name=None, **kwargs):
            assert operation_name == "list_flow_associations"
            if kwargs.get("ResourceType") == "VOICE_PHONE_NUMBER":
                if not kwargs.get("NextToken"):
                    return voice_pages[0]
                return voice_pages[1]
            return empty_page

        engine = _engine()
        engine.aws_client_factory.call_api_with_resilience.side_effect = _dispatch
        result = engine._list_flow_associations_for_instance(_instance())
        assert result == {
            p1["PhoneNumberArn"]: "flow-ivr",
            p2["PhoneNumberArn"]: "flow-sales",
        }

    def test_flow_id_is_extracted_from_full_flow_arn(self):
        # FlowId in the real API response is a full contact-flow ARN,
        # not a bare ID — the trailing segment must be extracted.
        phone = _phone("+18005551212")
        engine = _engine(
            flow_associations={
                "FlowAssociationSummaryList": [_flow_association(phone, "flow-ivr")],
                "NextToken": None,
            }
        )
        result = engine._list_flow_associations_for_instance(_instance())
        assert result[phone["PhoneNumberArn"]] == "flow-ivr"
