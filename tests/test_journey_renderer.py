"""Tests for caller-focused journey rendering and portable exports.

The renderer must project raw actions into a readable caller journey, preserve
inspectable system-work groups, use deterministic left-to-right lanes and
orthogonal connectors, cap unreasonably large flows, emit editable draw.io XML,
and keep all flow-derived content inert in HTML and XML artifacts.
"""

# ElementTree only parses strings generated in-process by the renderer under test.
from xml.etree import ElementTree as ET  # nosec B405

from amazon_connect_assessment.journey.renderer import (
    _HARD_CAP,
    _compute_layout,
    flow_to_diagram_artifacts,
    flow_to_diagram_html,
    flow_to_diagram_payload,
    flow_to_drawio_export,
    flow_to_svg_export,
)
from amazon_connect_assessment.models import (
    ContactFlowGraph,
    FlowAction,
    FlowTransition,
)


def _parse_generated_xml(xml_text: str) -> ET.Element:
    """Parse XML emitted by the renderer, never external or customer input."""
    # This helper never accepts external or customer-provided XML.
    return ET.fromstring(xml_text)  # nosec B314


def _action(action_id: str, action_type: str, **kwargs) -> FlowAction:
    return FlowAction(
        action_id=action_id,
        action_type=action_type,
        parameters=kwargs.get("parameters", {}),
        resource_details=kwargs.get("resource_details", {}),
    )


def _graph(actions, entry_id: str = "a0", name: str = "Test Flow") -> ContactFlowGraph:
    return ContactFlowGraph(
        flow_id="test-flow",
        flow_name=name,
        flow_type="CONTACT_FLOW",
        actions={a.action_id: a for a in actions},
        entry_point_id=entry_id,
    )


# ---------------------------------------------------------------------------
# Basic structural output
# ---------------------------------------------------------------------------


class TestStructuralOutput:
    def test_emits_canvas_container(self):
        actions = [_action("a0", "MessageParticipant")]
        actions[0].transitions = [FlowTransition("a0", "a1")]
        actions.append(_action("a1", "DisconnectParticipant"))
        result = flow_to_diagram_html(_graph(actions))
        assert '<div class="jm-canvas"' in result

    def test_canvas_carries_explicit_pixel_dimensions(self):
        # The whole point of server-rendering is that layout is fully
        # decided before the browser sees it — the canvas must carry
        # its own width/height rather than relying on content flow.
        actions = [_action("a0", "DisconnectParticipant")]
        result = flow_to_diagram_html(_graph(actions))
        assert "width:" in result and "px" in result
        assert "height:" in result

    def test_includes_connectors_svg(self):
        actions = [
            _action("a0", "MessageParticipant"),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].transitions = [FlowTransition("a0", "a1")]
        result = flow_to_diagram_html(_graph(actions))
        assert '<svg class="jm-connectors"' in result

    def test_entry_point_gets_entry_class(self):
        actions = [_action("a0", "MessageParticipant")]
        actions[0].transitions = [FlowTransition("a0", "a1")]
        actions.append(_action("a1", "DisconnectParticipant"))
        result = flow_to_diagram_html(_graph(actions, entry_id="a0"))
        assert "jm-node-entry" in result

    def test_nodes_are_absolutely_positioned(self):
        actions = [_action("a0", "DisconnectParticipant")]
        result = flow_to_diagram_html(_graph(actions))
        assert 'class="jm-node' in result
        assert "left:" in result and "top:" in result


# ---------------------------------------------------------------------------
# Hover tooltips — explain node/edge content instead of leaving bare,
# unexplained text (e.g. "NoMatchingError") on hover.
# ---------------------------------------------------------------------------


class TestTooltips:
    def test_node_tooltip_omits_raw_action_type(self):
        actions = [_action("a0", "InvokeLambdaFunction")]
        result = flow_to_diagram_html(_graph(actions))
        assert "Action type:" not in result
        assert "InvokeLambdaFunction" not in result
        assert "Invisible to the caller" in result

    def test_node_tooltip_explains_category(self):
        actions = [_action("a0", "TransferToQueue")]
        result = flow_to_diagram_html(_graph(actions))
        assert "placed on hold, queued, or offered a callback" in result

    def test_node_tooltip_carries_full_text_when_truncated(self):
        long_text = "x" * 200
        actions = [_action("a0", "MessageParticipant", parameters={"Text": long_text})]
        result = flow_to_diagram_html(_graph(actions))
        assert f"Full text: Plays: &quot;{long_text}&quot;" in result

    def test_node_tooltip_omits_full_text_when_not_truncated(self):
        actions = [_action("a0", "DisconnectParticipant")]
        result = flow_to_diagram_html(_graph(actions))
        assert "Full text:" not in result

    def test_known_error_branch_gets_specific_explanation(self):
        actions = [
            _action("a0", "InvokeLambdaFunction"),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].error_transitions = [
            FlowTransition("a0", "a1", condition="NoMatchingError", transition_type="error"),
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "configured catch-all route" in result
        assert "does not mean an error was observed" in result

    def test_known_condition_branch_gets_specific_explanation(self):
        actions = [
            _action("a0", "TransferToQueue"),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].transitions = [
            FlowTransition("a0", "a1", condition="QueueAtCapacity", transition_type="condition"),
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "maximum contacts-in-queue limit" in result

    def test_unknown_branch_name_still_gets_a_generic_explanation(self):
        actions = [
            _action("a0", "GetUserInput"),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].transitions = [
            FlowTransition("a0", "a1", condition="SomeCustomLabel", transition_type="condition"),
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "the exact label the flow" in result

    def test_edge_label_tooltip_is_html_escaped(self):
        actions = [
            _action("a0", "GetUserInput"),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].transitions = [
            FlowTransition(
                "a0", "a1", condition='"><script>alert(1)</script>', transition_type="condition"
            ),
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "<script>" not in result


# ---------------------------------------------------------------------------
# Straight-line-only connector routing
# ---------------------------------------------------------------------------


class TestOrthogonalRouting:
    def test_forward_edge_path_uses_only_h_and_v_commands(self):
        # This is the core guarantee: no diagonal segment is ever
        # possible because the path grammar only emits M/H/V.
        actions = [
            _action("a0", "MessageParticipant"),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].transitions = [FlowTransition("a0", "a1")]
        result = flow_to_diagram_html(_graph(actions))
        import re

        paths = re.findall(r'<path[^>]*\sd="([^"]+)"', result)
        assert paths, "expected at least one SVG path"
        for d in paths:
            # Only M/H/V/L/Z tokens are allowed; L only appears in the
            # tiny 3-point arrowhead triangles, never in a connector's
            # main path, and even those triangle vertices are computed
            # from purely horizontal/vertical offsets off the tip.
            tokens = set(re.findall(r"[A-Za-z]", d))
            assert tokens <= {"M", "H", "V", "L", "Z"}, f"unexpected path command in {d}"

    def test_branching_edges_have_distinct_bend_points(self):
        actions = [
            _action("a0", "GetUserInput"),
            _action("a1", "DisconnectParticipant"),
            _action("a2", "TransferToQueue"),
        ]
        actions[0].transitions = [
            FlowTransition("a0", "a1", condition="1", transition_type="condition"),
            FlowTransition("a0", "a2", condition="2", transition_type="condition"),
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert result.count("jm-connector") >= 2

    def test_crowded_branch_labels_are_stacked_apart(self):
        # A node with several closely-anchored branches (a
        # multi-condition GetUserInput here) places its edge labels
        # within a few pixels of each other on the y axis -- tighter
        # than a rendered pill's own height, which produced genuinely
        # overlapping text before _stack_edge_labels existed. Every
        # label sharing (essentially) the same x must end up spaced at
        # least _EDGE_LABEL_MIN_GAP apart.
        from amazon_connect_assessment.journey.renderer import _EDGE_LABEL_MIN_GAP

        actions = [
            _action("a0", "GetUserInput"),
            _action("a1", "DisconnectParticipant"),
            _action("a2", "TransferToQueue"),
            _action("a3", "MessageParticipant"),
            _action("a4", "Wait"),
        ]
        actions[0].transitions = [
            FlowTransition("a0", "a1", condition="1", transition_type="condition"),
            FlowTransition("a0", "a2", condition="2", transition_type="condition"),
            FlowTransition("a0", "a3", condition="3", transition_type="condition"),
            FlowTransition("a0", "a4", condition="4", transition_type="condition"),
        ]
        result = flow_to_diagram_html(_graph(actions))
        import re

        tops = [
            float(m.group(1))
            for m in re.finditer(
                r'class="jm-edge-label[^"]*" style="left:[\d.]+px;top:([\d.]+)px;"', result
            )
        ]
        assert len(tops) == 4
        tops.sort()
        for earlier, later in zip(tops, tops[1:]):
            assert later - earlier >= _EDGE_LABEL_MIN_GAP

    def test_labels_at_different_x_are_left_alone(self):
        # Two labels that don't share a column (different layers, so
        # different mid_x) must not be nudged relative to each other
        # even if their y values happen to be close.
        actions = [
            _action("a0", "GetUserInput"),
            _action("a1", "DisconnectParticipant"),
            _action("a2", "TransferToQueue"),
        ]
        actions[0].transitions = [
            FlowTransition("a0", "a1", condition="1", transition_type="condition"),
        ]
        actions[1].transitions = [
            FlowTransition("a1", "a2", condition="2", transition_type="condition"),
        ]
        result = flow_to_diagram_html(_graph(actions))
        import re

        placements = [
            (float(m.group(1)), float(m.group(2)))
            for m in re.finditer(
                r'class="jm-edge-label[^"]*" style="left:([\d.]+)px;top:([\d.]+)px;"', result
            )
        ]
        assert len(placements) == 2
        xs = {x for x, _y in placements}
        assert len(xs) == 2  # different columns -- independent placement

    def test_back_edge_routed_below_via_lane(self):
        # A transition pointing back to an earlier (or same) layer is a
        # "back edge" — routed in a dedicated lane below the lowest row
        # rather than drawn straight through the middle of the diagram.
        actions = [
            _action("a0", "GetUserInput"),
            _action("a1", "MessageParticipant"),
        ]
        actions[0].transitions = [FlowTransition("a0", "a1")]
        actions[1].transitions = [FlowTransition("a1", "a0")]  # loop back
        result = flow_to_diagram_html(_graph(actions))
        assert "jm-connector-back" in result


# ---------------------------------------------------------------------------
# Category mapping (generic labels — no rich parameters)
# ---------------------------------------------------------------------------


class TestCategoryMapping:
    def test_message_participant_is_speaks(self):
        actions = [_action("a0", "MessageParticipant")]
        assert "jm-node-speaks" in flow_to_diagram_html(_graph(actions))

    def test_get_user_input_is_chooses(self):
        actions = [_action("a0", "GetUserInput")]
        result = flow_to_diagram_html(_graph(actions))
        assert "jm-node-chooses" in result
        assert "Asks caller to choose" in result

    def test_transfer_to_queue_is_waits(self):
        actions = [_action("a0", "TransferToQueue")]
        result = flow_to_diagram_html(_graph(actions))
        assert "jm-node-waits" in result
        assert "Waits for an agent" in result

    def test_disconnect_is_terminal(self):
        actions = [_action("a0", "DisconnectParticipant")]
        result = flow_to_diagram_html(_graph(actions))
        assert "jm-node-terminal" in result
        assert "Call ends" in result

    def test_unknown_action_falls_to_processing_without_exposing_raw_type(self):
        actions = [_action("a0", "SomeInternalFrobnicator")]
        result = flow_to_diagram_html(_graph(actions))
        assert "jm-node-processing" in result
        assert "Internal contact processing" in result
        assert "SomeInternalFrobnicator" not in result
        assert "detailed configuration is not yet interpreted" in result

    def test_lambda_gets_customer_facing_processing_label(self):
        actions = [_action("a0", "InvokeLambdaFunction")]
        result = flow_to_diagram_html(_graph(actions))
        assert "jm-node-processing" in result
        assert "Looks up data" in result


# ---------------------------------------------------------------------------
# Rich labels — parameters drive the visible node text
# ---------------------------------------------------------------------------


class TestRichLabels:
    def test_message_participant_surfaces_prompt_text(self):
        actions = [
            _action(
                "a0",
                "MessageParticipant",
                parameters={"Text": "Welcome to Acme Support. Please hold."},
            )
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "Welcome to Acme Support" in result

    def test_get_participant_input_surfaces_prompt_text(self):
        actions = [
            _action(
                "a0",
                "GetParticipantInput",
                parameters={"Text": "Press 1 for sales, 2 for support."},
            )
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "Press 1 for sales" in result

    def test_invoke_lambda_extracts_function_name_from_arn(self):
        actions = [
            _action(
                "a0",
                "InvokeLambdaFunction",
                parameters={
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:lookup-customer"
                },
            )
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "lookup-customer" in result

    def test_invoke_lambda_arn_with_qualifier_strips_qualifier(self):
        actions = [
            _action(
                "a0",
                "InvokeLambdaFunction",
                parameters={
                    "FunctionArn": "arn:aws:lambda:us-east-1:123456789012:function:lookup-customer:PROD"
                },
            )
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "lookup-customer" in result
        assert "PROD" not in result

    def test_lex_bot_surfaces_bot_name(self):
        actions = [
            _action(
                "a0",
                "ConnectParticipantWithLexBot",
                parameters={"BotName": "CustomerServiceBot"},
            )
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "CustomerServiceBot" in result

    def test_lex_v2_prompt_keeps_conversation_text_and_ai_identity(self):
        actions = [
            _action(
                "a0",
                "ConnectParticipantWithLexBot",
                parameters={
                    "Text": "How can I help you today?",
                    "LexV2Bot": {
                        "AliasArn": (
                            "arn:aws:lex:us-east-1:123456789012:bot-alias/ALGAULUNIR/TSTALIASID"
                        )
                    },
                },
                resource_details={
                    "ai": {
                        "technology": "Amazon Lex",
                        "identity": "RTHelpDeskBot",
                        "subtype": "V2 bot",
                        "alias": "TestBotAlias",
                    }
                },
            )
        ]

        html_result, model = flow_to_diagram_payload(_graph(actions))
        node = next(iter(model["nodes"].values()))

        assert node["title"] == 'AI conversation: "How can I help you today?"'
        assert node["ai"] == {
            "technology": "Amazon Lex",
            "identity": "RTHelpDeskBot",
            "subtype": "V2 bot",
            "alias": "TestBotAlias",
        }
        assert "AI agent: RTHelpDeskBot" in html_result
        assert "Amazon Lex · V2 bot · Alias: TestBotAlias" in html_result
        assert "ConnectParticipantWithLexBot" not in html_result
        assert "ALGAULUNIR" not in html_result
        assert "TSTALIASID" not in html_result

    def test_lex_v1_shape_is_identified_without_resource_lookup(self):
        actions = [
            _action(
                "a0",
                "ConnectToLexBot",
                parameters={"BotName": "LegacySupportBot", "BotAlias": "Production"},
            )
        ]

        _html, model = flow_to_diagram_payload(_graph(actions))
        ai = next(iter(model["nodes"].values()))["ai"]

        assert ai == {
            "technology": "Amazon Lex",
            "identity": "LegacySupportBot",
            "subtype": "V1 bot",
            "alias": "Production",
        }

    def test_transfer_to_queue_hides_dynamic_reference(self):
        actions = [
            _action(
                "a0",
                "TransferToQueue",
                parameters={"QueueId": "$.Attributes.RoutingQueue"},
            )
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "Queue selected from contact data" in result
        assert "$.Attributes.RoutingQueue" not in result

    def test_static_prompt_describes_effective_tts_configuration(self):
        actions = [
            _action(
                "voice",
                "UpdateContactTextToSpeechVoice",
                parameters={
                    "TextToSpeechVoice": "Matthew",
                    "TextToSpeechEngine": "Generative",
                },
            ),
            _action(
                "message",
                "MessageParticipant",
                parameters={"Text": "Welcome to Acme support."},
            ),
        ]
        actions[0].transitions = [FlowTransition("voice", "message")]

        html_result, model = flow_to_diagram_payload(_graph(actions, entry_id="voice"))
        message = next(node for node in model["nodes"].values() if node["category"] == "speaks")

        assert message["scope"] == [
            "Plays a prompt to the caller using inline static text.",
            "Synthesizes the prompt with Amazon Polly using Matthew and the Generative engine.",
            'Prompt: "Welcome to Acme support."',
        ]
        assert message["is_group"] is False
        assert "What this block does:" in html_result

    def test_queue_transfer_inherits_resolved_selected_queue(self):
        actions = [
            _action(
                "select",
                "UpdateContactTargetQueue",
                parameters={"QueueId": "queue-id"},
                resource_details={"queue": {"identity": "BasicQueue", "selection": "configured"}},
            ),
            _action("transfer", "TransferContactToQueue"),
        ]
        actions[0].transitions = [FlowTransition("select", "transfer")]

        _html, model = flow_to_diagram_payload(_graph(actions, entry_id="select"))
        transfer = next(node for node in model["nodes"].values() if node["category"] == "waits")

        assert transfer["scope"] == [
            "Transfers the caller to BasicQueue to wait for an available agent."
        ]

    def test_every_visible_block_has_reader_focused_scope(self):
        actions = [
            _action("message", "MessageParticipant", parameters={"Text": "Hello"}),
            _action("input", "GetParticipantInput"),
            _action("lookup", "InvokeLambdaFunction"),
            _action("check", "CheckContactAttributes"),
            _action("wait", "Wait", parameters={"WaitTimeSeconds": "10"}),
            _action("end", "DisconnectParticipant"),
            _action("unknown", "FutureConnectAction"),
        ]

        _html, model = flow_to_diagram_payload(_graph(actions, entry_id="message"))

        assert all(node["scope"] for node in model["nodes"].values())
        assert all("FutureConnectAction" not in node["title"] for node in model["nodes"].values())

    def test_branching_block_scope_explains_where_outcomes_continue(self):
        actions = [
            _action("ai", "ConnectParticipantWithLexBot", parameters={"BotName": "SupportBot"}),
            _action("queue", "UpdateContactTargetQueue"),
            _action("done", "MessageParticipant", parameters={"Text": "Goodbye"}),
        ]
        actions[0].transitions = [
            FlowTransition(
                "ai",
                "queue",
                condition="{'Operator': 'Equals', 'Operands': ['Escalate']}",
                transition_type="condition",
            ),
            FlowTransition(
                "ai",
                "done",
                condition="{'Operator': 'Equals', 'Operands': ['Complete']}",
                transition_type="condition",
            ),
        ]

        _html, model = flow_to_diagram_payload(_graph(actions, entry_id="ai"))
        ai_node = next(node for node in model["nodes"].values() if node["ai"])

        assert any("Routes Escalate to specialist" in item for item in ai_node["scope"])
        assert any("Routes Resolved" in item for item in ai_node["scope"])

    def test_transfer_external_masks_phone_number(self):
        actions = [
            _action(
                "a0",
                "TransferParticipantToThirdParty",
                parameters={"Endpoint": {"Address": "+18005551212"}},
            )
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "1212" in result
        assert "8005551212" not in result

    def test_long_prompt_text_is_truncated(self):
        long_text = "This is an unusually verbose prompt " * 10
        actions = [_action("a0", "MessageParticipant", parameters={"Text": long_text})]
        result = flow_to_diagram_html(_graph(actions))
        assert long_text not in result


# ---------------------------------------------------------------------------
# Transitions / edge labels
# ---------------------------------------------------------------------------


class TestTransitions:
    def test_condition_transition_carries_label(self):
        actions = [
            _action("a0", "GetUserInput"),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].transitions = [
            FlowTransition("a0", "a1", condition="1", transition_type="condition"),
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "jm-edge-label" in result
        assert ">1<" in result

    def test_error_transition_styled_distinctly(self):
        actions = [
            _action("a0", "InvokeLambdaFunction"),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].error_transitions = [
            FlowTransition("a0", "a1", transition_type="error"),
        ]
        result = flow_to_diagram_html(_graph(actions))
        assert "jm-connector-error" in result

    def test_journey_primary_connector_emits_matching_arrowhead_class(self):
        # Arrange
        actions = [
            _action("a0", "MessageParticipant"),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].transitions = [FlowTransition("a0", "a1")]

        # Act
        result = flow_to_diagram_html(_graph(actions))

        # Assert
        assert "jm-connector-primary-head" in result

    def test_long_edge_labels_are_truncated_in_html_and_retained_in_model(self):
        raw_label = "a" * 100
        actions = [
            _action("a0", "GetUserInput"),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].transitions = [
            FlowTransition(
                "a0",
                "a1",
                condition=raw_label,
                transition_type="condition",
            ),
        ]
        result, model = flow_to_diagram_payload(_graph(actions))
        # The visible pill is truncated and native hover text stays reader-facing.
        import re

        pill_text = re.search(r'class="jm-edge-label[^"]*"[^>]*>([^<]*)</button>', result).group(1)
        assert raw_label not in result
        assert "…" in pill_text
        # The inspector still exposes the complete value on explicit selection.
        assert raw_label in {
            outcome["raw_label"] for edge in model["edges"].values() for outcome in edge["outcomes"]
        }


# ---------------------------------------------------------------------------
# Caller-focused projection and system-work grouping
# ---------------------------------------------------------------------------


class TestProjection:
    def test_small_flow_shows_processing_nodes(self):
        actions = [
            _action("a0", "MessageParticipant"),
            _action("a1", "SetContactAttributes"),
            _action("a2", "DisconnectParticipant"),
        ]
        actions[0].transitions = [FlowTransition("a0", "a1")]
        actions[1].transitions = [FlowTransition("a1", "a2")]
        result = flow_to_diagram_html(_graph(actions))
        assert "Sets attributes" in result

    def test_large_flow_groups_consecutive_processing_nodes(self):
        # Arrange: a caller-facing start, a long invisible setup run,
        # and a caller-facing end.
        processing_count = 51
        actions = [_action("a0", "MessageParticipant")]
        actions.extend(
            _action(f"a{i}", "SetContactAttributes") for i in range(1, processing_count + 1)
        )
        actions.append(_action(f"a{processing_count + 1}", "DisconnectParticipant"))
        for i in range(len(actions) - 1):
            actions[i].transitions = [
                FlowTransition(actions[i].action_id, actions[i + 1].action_id)
            ]

        # Act
        result = flow_to_diagram_html(_graph(actions))

        # Assert
        assert "Sets attributes" not in result
        assert f"System work · {processing_count} internal actions" in result
        assert (
            f"{processing_count} internal action(s) consolidated into 1 inspectable system-work step(s)"
            in result
        )

    def test_grouped_setup_exposes_seven_reader_focused_effects(self):
        actions = [
            _action("enable-logging", "UpdateFlowLoggingBehavior"),
            _action(
                "customer-lookup",
                "InvokeLambdaFunction",
                parameters={
                    "LambdaFunctionARN": (
                        "arn:aws:lambda:us-east-1:123456789012:"
                        "function:rt-helpdesk-prod-vip-phone-lookup"
                    )
                },
            ),
            _action(
                "set-customer-attrs",
                "UpdateContactAttributes",
                parameters={
                    "Attributes": {
                        "isVip": "$.External.isVip",
                        "contactName": "$.External.contactName",
                        "institutionName": "$.External.institutionName",
                    }
                },
            ),
            _action(
                "create-wisdom-session",
                "CreateWisdomSession",
                parameters={
                    "WisdomAssistantArn": (
                        "arn:aws:wisdom:us-east-1:123456789012:assistant/assistant-id"
                    )
                },
                resource_details={
                    "q_connect_assistant": {
                        "technology": "Amazon Q in Connect",
                        "identity": "AnyCompany",
                        "subtype": "Agent",
                    }
                },
            ),
            _action("update-contact-data", "UpdateContactData"),
            _action("set-voice", "UpdateContactTextToSpeechVoice"),
            _action("set-recording", "UpdateContactRecordingBehavior"),
            _action(
                "ai-agent",
                "ConnectParticipantWithLexBot",
                parameters={"Text": "How can I help?", "BotName": "SupportBot"},
            ),
        ]
        for source, target in zip(actions, actions[1:]):
            source.transitions = [FlowTransition(source.action_id, target.action_id)]

        html_result, model = flow_to_diagram_payload(_graph(actions, entry_id="enable-logging"))
        setup = next(
            node for node in model["nodes"].values() if node["title"].startswith("System setup")
        )

        assert setup["scope"] == [
            "Enables flow logging for subsequent actions.",
            ("Invokes rt-helpdesk-prod-vip-phone-lookup to retrieve or process contact data."),
            (
                "Copies isVip, contactName, institutionName from the Lambda response "
                "into contact attributes."
            ),
            "Starts an Amazon Q in Connect session with AnyCompany (assistant type: Agent).",
            "Updates contact data used by subsequent flow and routing steps.",
            "Sets the Amazon Polly voice used by subsequent prompts and Lex interactions.",
            "Configures which participants are captured in contact recordings.",
        ]
        assert setup["is_group"] is True
        assert "What this setup does:" in html_result
        assert "• Enables flow logging for subsequent actions." in html_result
        assert "CreateWisdomSession" not in html_result
        assert "UpdateContactRecordingBehavior" not in html_result
        assert "assistant-id" not in html_result

    def test_projection_internal_no_matching_error_routes_preserve_distinct_provenance(self):
        # Arrange
        actions = [
            _action("setup", "UpdateFlowLoggingBehavior"),
            _action("lookup", "InvokeLambdaFunction"),
            _action("attributes", "SetContactAttributes"),
            _action("end", "DisconnectParticipant"),
        ]
        actions[0].transitions = [FlowTransition("setup", "lookup")]
        actions[0].error_transitions = [
            FlowTransition(
                "setup", "attributes", condition="NoMatchingError", transition_type="error"
            ),
            FlowTransition(
                "setup", "attributes", condition="NoMatchingError", transition_type="error"
            ),
        ]
        actions[1].transitions = [FlowTransition("lookup", "attributes")]
        actions[1].error_transitions = [
            FlowTransition(
                "lookup", "attributes", condition="NoMatchingError", transition_type="error"
            )
        ]
        actions[2].transitions = [FlowTransition("attributes", "end")]

        # Act
        html_result, model = flow_to_diagram_payload(_graph(actions, entry_id="setup"))
        group = next(node for node in model["nodes"].values() if len(node["actions"]) == 3)
        routes = group["absorbed_outcomes"]

        # Assert
        assert len(routes) == 2
        assert {(route["source_action_id"], route["target_action_id"]) for route in routes} == {
            ("setup", "attributes"),
            ("lookup", "attributes"),
        }
        assert {route["source_action_type"] for route in routes} == {
            "UpdateFlowLoggingBehavior",
            "InvokeLambdaFunction",
        }
        assert {route["source_action_label"] for route in routes} == {
            "Update Flow Logging Behavior",
            "Looks up data",
        }
        assert {route["target_action_type"] for route in routes} == {"SetContactAttributes"}
        assert {route["target_action_label"] for route in routes} == {"Sets attributes"}
        assert all(route["raw_label"] == "NoMatchingError" for route in routes)
        assert all(route["route_type"] == "exception" for route in routes)
        assert all(route["transition_type"] == "error" for route in routes)
        assert all(route["label"] == "Catch-all error route" for route in routes)
        assert all("does not mean an error was observed" in route["meaning"] for route in routes)
        assert "Technical error" not in str(routes)
        assert "encountered" not in str(routes)
        assert ">Includes main-route steps</span>" in html_result

    def test_projection_single_primary_node_keeps_unambiguous_main_route_badge(self):
        # Arrange
        graph = _graph([_action("a0", "DisconnectParticipant")])

        # Act
        html_result = flow_to_diagram_html(graph)

        # Assert
        assert ">Main route</span>" in html_result
        assert "Includes main-route steps" not in html_result

    def test_hard_cap_returns_placeholder(self):
        huge = _HARD_CAP + 5
        actions = [_action(f"a{i}", "MessageParticipant") for i in range(huge)]
        result = flow_to_diagram_html(_graph(actions, name="Enormous Flow"))
        assert "Enormous Flow" in result
        assert "too complex" in result
        assert "jm-placeholder" in result


# ---------------------------------------------------------------------------
# Robustness
# ---------------------------------------------------------------------------


class TestRobustness:
    def test_empty_flow_returns_readable_placeholder(self):
        empty = ContactFlowGraph(
            flow_id="empty",
            flow_name="Empty Flow",
            flow_type="CONTACT_FLOW",
            actions={},
            entry_point_id="",
        )
        result = flow_to_diagram_html(empty)
        assert "jm-placeholder" in result
        assert "Empty Flow" in result

    def test_unknown_action_type_is_not_rendered_as_markup_or_text(self):
        actions = [_action("a0", '<script>alert("xss")</script>')]
        result = flow_to_diagram_html(_graph(actions))
        assert "<script>" not in result
        assert "&lt;script&gt;" not in result
        assert "Internal contact processing" in result

    def test_missing_entry_point_still_renders(self):
        actions = [_action("a0", "DisconnectParticipant")]
        graph = _graph(actions, entry_id="does-not-exist")
        result = flow_to_diagram_html(graph)
        assert '<div class="jm-canvas"' in result
        assert "jm-node-entry" not in result

    def test_never_raises_on_broken_input(self):
        broken = ContactFlowGraph(
            flow_id="broken",
            flow_name="Broken Flow",
            flow_type="CONTACT_FLOW",
            actions=None,  # type: ignore[arg-type]
            entry_point_id="",
        )
        result = flow_to_diagram_html(broken)
        assert "Broken Flow" in result

    def test_disconnected_fragment_still_renders(self):
        # A node with no path from the entry point (dead code, or a
        # flow with multiple disconnected components) must still
        # appear rather than silently vanishing from the diagram.
        actions = [
            _action("a0", "MessageParticipant"),
            _action("a1", "DisconnectParticipant"),
            _action("orphan", "TransferToQueue"),
        ]
        actions[0].transitions = [FlowTransition("a0", "a1")]
        result = flow_to_diagram_html(_graph(actions))
        assert "Waits for an agent" in result


# ---------------------------------------------------------------------------
# Caller-focused projection regression coverage
# ---------------------------------------------------------------------------


def _caller_focused_graph() -> ContactFlowGraph:
    """Build a compact analogue of the RT Help Desk flow."""
    actions = [
        _action("setup-logging", "UpdateFlowLoggingBehavior"),
        _action(
            "setup-lookup",
            "InvokeLambdaFunction",
            parameters={
                "LambdaFunctionARN": (
                    "arn:aws:lambda:us-east-1:123456789012:function:customer-lookup:PROD"
                )
            },
        ),
        _action(
            "ai",
            "ConnectParticipantWithLexBot",
            parameters={
                "Text": "Hello, how can I help you today?",
                "LexV2Bot": {
                    "AliasArn": (
                        "arn:aws:lex:us-east-1:123456789012:bot-alias/ALGAULUNIR/TSTALIASID"
                    )
                },
            },
            resource_details={
                "ai": {
                    "technology": "Amazon Lex",
                    "identity": "RTHelpDeskBot",
                    "subtype": "V2 bot",
                    "alias": "TestBotAlias",
                }
            },
        ),
        _action("goodbye", "MessageParticipant", parameters={"Text": "Thank you for calling."}),
        _action("queue-setup", "UpdateContactTargetQueue"),
        _action(
            "transfer-message",
            "MessageParticipant",
            parameters={"Text": "Let me connect you with a support specialist."},
        ),
        _action("queue", "TransferToQueue"),
        _action(
            "technical-message",
            "MessageParticipant",
            parameters={"Text": "We are experiencing a technical issue."},
        ),
        _action("end", "DisconnectParticipant"),
    ]
    by_id = {action.action_id: action for action in actions}
    by_id["setup-logging"].transitions = [FlowTransition("setup-logging", "setup-lookup")]
    by_id["setup-lookup"].transitions = [FlowTransition("setup-lookup", "ai")]
    by_id["setup-lookup"].error_transitions = [
        FlowTransition(
            "setup-lookup",
            "ai",
            condition="NoMatchingError",
            transition_type="error",
        )
    ]
    by_id["ai"].transitions = [
        FlowTransition("ai", "goodbye"),
        FlowTransition(
            "ai",
            "goodbye",
            condition="{'Operator': 'Equals', 'Operands': ['Complete']}",
            transition_type="condition",
        ),
        FlowTransition(
            "ai",
            "queue-setup",
            condition="{'Operator': 'Equals', 'Operands': ['Escalate']}",
            transition_type="condition",
        ),
    ]
    by_id["ai"].error_transitions = [
        FlowTransition(
            "ai",
            "goodbye",
            condition="NoMatchingCondition",
            transition_type="error",
        ),
        FlowTransition(
            "ai",
            "technical-message",
            condition="NoMatchingError",
            transition_type="error",
        ),
    ]
    by_id["goodbye"].transitions = [FlowTransition("goodbye", "end")]
    by_id["queue-setup"].transitions = [FlowTransition("queue-setup", "transfer-message")]
    by_id["transfer-message"].transitions = [FlowTransition("transfer-message", "queue")]
    by_id["queue"].transitions = [FlowTransition("queue", "end")]
    by_id["queue"].error_transitions = [
        FlowTransition(
            "queue",
            "technical-message",
            condition="QueueAtCapacity",
            transition_type="error",
        ),
        FlowTransition(
            "queue",
            "technical-message",
            condition="NoMatchingError",
            transition_type="error",
        ),
    ]
    by_id["technical-message"].transitions = [FlowTransition("technical-message", "end")]
    return _graph(actions, entry_id="setup-logging", name="RT-shaped flow")


class TestCallerFocusedProjection:
    def test_projection_rt_shape_groups_setup_and_preserves_visible_steps(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        _html, model = flow_to_diagram_payload(graph)
        titles = [node["title"] for node in model["nodes"].values()]

        # Assert
        assert "System setup · 2 internal actions" in titles
        assert any("AI conversation" in title for title in titles)
        assert any("Thank you for calling" in title for title in titles)
        assert any("technical issue" in title for title in titles)
        ai_node = next(node for node in model["nodes"].values() if node["ai"])
        assert ai_node["ai"] == {
            "technology": "Amazon Lex",
            "identity": "RTHelpDeskBot",
            "subtype": "V2 bot",
            "alias": "TestBotAlias",
        }
        assert len(model["nodes"]) == 8

    def test_projection_omits_redundant_single_step_and_default_route_summaries(self):
        # Arrange
        graph = _caller_focused_graph()
        default_actions = [
            _action("message", "MessageParticipant", parameters={"Text": "Welcome."}),
            _action("end", "DisconnectParticipant"),
        ]
        default_actions[0].transitions = [FlowTransition("message", "end")]

        # Act
        _html, model = flow_to_diagram_payload(graph)
        _default_html, default_model = flow_to_diagram_payload(_graph(default_actions))
        nodes = list(model["nodes"].values())
        setup = next(node for node in nodes if node["title"].startswith("System setup"))
        spoken_message = next(
            node for node in nodes if node["title"] == 'Plays: "Thank you for calling."'
        )
        default_route = next(iter(default_model["edges"].values()))

        # Assert
        assert setup["summary"] == "Prepares the contact before the caller-facing journey begins."
        assert spoken_message["summary"] == ""
        assert default_route["summary"] == ""

    def test_projection_rt_shape_prefers_resolved_primary_route(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        _html, model = flow_to_diagram_payload(graph)
        primary_titles = [model["nodes"][key]["title"] for key in model["primary_path"]]

        # Assert
        assert primary_titles == [
            "System setup · 2 internal actions",
            'AI conversation: "Hello, how can I help you today?"',
            'Plays: "Thank you for calling."',
            "Call ends",
        ]

    def test_projection_reader_labels_replace_connect_implementation_terms(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        html_result, model = flow_to_diagram_payload(graph)
        edge_titles = [edge["title"] for edge in model["edges"].values()]

        # Assert
        assert "Escalate to specialist" in edge_titles
        assert "Catch-all error route" in edge_titles
        assert "Queue unavailable" in edge_titles
        assert ">Escalate to specialist</button>" in html_result
        assert ">Catch-all error route</button>" in html_result

    def test_projection_keeps_raw_outcomes_in_inspector_model_only(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        html_result, model = flow_to_diagram_payload(graph)
        action_ids = {
            action["id"] for node in model["nodes"].values() for action in node["actions"]
        }
        raw_outcomes = {
            outcome["raw_label"] for edge in model["edges"].values() for outcome in edge["outcomes"]
        }
        structured_predicate = "{'Operator': 'Equals', 'Operands': ['Escalate']}"

        # Assert
        assert "setup-lookup" in action_ids
        assert "NoMatchingError" in raw_outcomes
        assert "QueueAtCapacity" in raw_outcomes
        assert structured_predicate in raw_outcomes
        assert structured_predicate not in html_result

    def test_projection_inspector_model_redacts_lambda_arn(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        _html, model = flow_to_diagram_payload(graph)
        serialized = str(model)

        # Assert
        assert "123456789012" not in serialized
        assert "customer-lookup" in serialized

    def test_projection_html_emits_keyboard_accessible_inspector_controls(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        html_result = flow_to_diagram_html(graph)

        # Assert
        assert 'type="button" class="jm-node' in html_result
        assert 'data-jm-node-key="n0"' in html_result
        assert 'data-jm-edge-key="e0"' in html_result
        assert 'aria-pressed="false"' in html_result


class TestProjectedLayout:
    def test_layout_non_feedback_routes_always_point_right(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        layout = _compute_layout(graph)

        # Assert
        assert not layout.back_edges
        for edge in layout.forward_edges:
            source_x = layout.positions[edge.source][0]
            target_x = layout.positions[edge.target][0]
            assert target_x > source_x

    def test_layout_places_normal_alternates_above_and_exceptions_below_primary(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        layout = _compute_layout(graph)
        by_title = {node.label: key for key, node in layout.visible.items()}
        primary_y = layout.positions[
            by_title['AI conversation: "Hello, how can I help you today?"']
        ][1]
        alternate_y = layout.positions[by_title["Prepare queue transfer"]][1]
        exception_y = layout.positions[by_title['Plays: "We are experiencing a technical issue."']][
            1
        ]

        # Assert
        assert alternate_y < primary_y
        assert exception_y > primary_y

    def test_layout_displayed_node_rectangles_do_not_overlap(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        layout = _compute_layout(graph)
        rectangles = [(x, y, x + 210, y + 72) for x, y in layout.positions.values()]

        # Assert
        for index, first in enumerate(rectangles):
            for second in rectangles[index + 1 :]:
                separated = (
                    first[2] <= second[0]
                    or second[2] <= first[0]
                    or first[3] <= second[1]
                    or second[3] <= first[1]
                )
                assert separated


class TestPortableJourneyExports:
    def test_export_svg_valid_graph_returns_self_contained_svg(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        exported = flow_to_svg_export(graph)

        # Assert
        assert exported is not None
        svg_markup, width, height = exported
        root = _parse_generated_xml(svg_markup)
        assert root.tag == "{http://www.w3.org/2000/svg}svg"
        assert int(root.attrib["width"]) == width
        assert int(root.attrib["height"]) == height
        assert "<script" not in svg_markup.lower()
        assert "foreignObject" not in svg_markup
        assert "http://" not in svg_markup.replace("http://www.w3.org/2000/svg", "")

    def test_export_drawio_valid_graph_returns_editable_native_cells(self):
        # Arrange
        graph = _caller_focused_graph()
        layout = _compute_layout(graph)

        # Act
        drawio_xml = flow_to_drawio_export(graph)

        # Assert
        assert drawio_xml is not None
        root = _parse_generated_xml(drawio_xml)
        assert root.tag == "mxfile"
        assert root.attrib["compressed"] == "false"
        cells = root.findall("./diagram/mxGraphModel/root/mxCell")
        node_cells = [cell for cell in cells if cell.attrib.get("vertex") == "1"]
        edge_cells = [cell for cell in cells if cell.attrib.get("edge") == "1"]
        assert len(node_cells) == len(layout.visible)
        assert len(edge_cells) == len(layout.forward_edges) + len(layout.back_edges)
        assert all("html=0" in cell.attrib["style"] for cell in node_cells + edge_cells)
        assert all(cell.attrib["source"].startswith("node-n") for cell in edge_cells)
        assert all(cell.attrib["target"].startswith("node-n") for cell in edge_cells)

    def test_export_drawio_projected_nodes_preserve_layout_geometry(self):
        # Arrange
        graph = _caller_focused_graph()
        layout = _compute_layout(graph)

        # Act
        drawio_xml = flow_to_drawio_export(graph)
        root = _parse_generated_xml(drawio_xml or "")

        # Assert
        for key, (expected_x, expected_y) in layout.positions.items():
            cell = root.find(f"./diagram/mxGraphModel/root/mxCell[@id='node-{key}']")
            assert cell is not None
            geometry = cell.find("mxGeometry")
            assert geometry is not None
            assert int(geometry.attrib["x"]) == expected_x
            assert int(geometry.attrib["y"]) == expected_y
            assert int(geometry.attrib["width"]) == 210
            assert int(geometry.attrib["height"]) == 72

    def test_export_drawio_omits_raw_connect_metadata(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        drawio_xml = flow_to_drawio_export(graph)

        # Assert
        assert drawio_xml is not None
        assert "setup-lookup" not in drawio_xml
        assert "NoMatchingError" not in drawio_xml
        assert "QueueAtCapacity" not in drawio_xml
        assert "123456789012" not in drawio_xml
        assert "Escalate to specialist" in drawio_xml

    def test_export_artifacts_hostile_text_stays_inert_and_xml_valid(self):
        # Arrange
        hostile = '</SCRIPT><script>alert(1)</script>\x01 & "quoted"'
        actions = [
            _action("a0", "MessageParticipant", parameters={"Text": hostile}),
            _action("a1", "DisconnectParticipant"),
        ]
        actions[0].transitions = [FlowTransition("a0", "a1")]
        graph = _graph(actions)

        # Act
        artifacts = flow_to_diagram_artifacts(graph)

        # Assert
        assert artifacts.svg_markup is not None
        assert artifacts.drawio_xml is not None
        _parse_generated_xml(artifacts.svg_markup)
        _parse_generated_xml(artifacts.drawio_xml)
        assert "\x01" not in artifacts.drawio_xml
        assert "<script" not in artifacts.svg_markup.lower()
        assert "<script" not in artifacts.drawio_xml.lower()

    def test_export_artifacts_valid_graph_returns_versioned_payload(self):
        # Arrange
        graph = _caller_focused_graph()

        # Act
        artifacts = flow_to_diagram_artifacts(graph)
        payload = artifacts.export_payload()

        # Assert
        assert payload["schema_version"] == 1
        assert set(payload["formats"]) == {"svg", "drawio"}
        assert payload["formats"]["svg"]["width"] > 0
        assert payload["formats"]["svg"]["height"] > 0
        assert payload["formats"]["drawio"]["content"].startswith("<mxfile")

    def test_export_empty_graph_returns_no_portable_artifacts(self):
        # Arrange
        graph = _graph([])

        # Act
        artifacts = flow_to_diagram_artifacts(graph)

        # Assert
        assert flow_to_svg_export(graph) is None
        assert flow_to_drawio_export(graph) is None
        assert artifacts.export_payload()["formats"] == {}
