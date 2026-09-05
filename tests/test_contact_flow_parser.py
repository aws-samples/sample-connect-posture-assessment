"""
Tests for the Contact Flow Parser package (Phase 1).

Covers:
- Round-trip fidelity (parse -> serialize -> parse) — Requirement 34.3
- Unknown action type preservation — Requirement 34.4
- Malformed-input robustness (no unhandled exceptions)
- Cycle detection: bounded vs. unbounded — Requirements 4.1-4.2
- Pattern detection (auth / personalization / transfer / self-service)
- Descriptive flow structural metrics — Requirement 33.1
"""

import json

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from amazon_connect_assessment.parsers import (
    ContactFlowParseError,
    ContactFlowParser,
    calculate_flow_metrics,
    detect_cycles,
    detect_patterns,
)
from tests.conftest import build_action, build_contact_flow

# ---------------------------------------------------------------------------
# Hypothesis strategy: generate structurally valid contact flow JSON
# ---------------------------------------------------------------------------

_ACTION_TYPES = st.sampled_from(
    [
        "MessageParticipant",
        "GetParticipantInput",
        "InvokeLambdaFunction",
        "TransferToQueue",
        "TransferContactToPhoneNumber",
        "DisconnectParticipant",
        "CheckContactAttributes",
        "SomeFutureUnknownType",  # exercises unknown-type preservation
    ]
)


@st.composite
def contact_flow_strategy(draw):
    n = draw(st.integers(min_value=1, max_value=8))
    ids = [f"act-{i}" for i in range(n)]
    actions = []
    for i, aid in enumerate(ids):
        # Wire a forward NextAction sometimes; allow back-edges to form cycles.
        target = draw(st.one_of(st.none(), st.sampled_from(ids)))
        errors = None
        if draw(st.booleans()):
            errors = [
                {
                    "NextAction": draw(st.sampled_from(ids)),
                    "ErrorType": "NoMatchingError",
                }
            ]
        actions.append(
            build_action(
                aid,
                draw(_ACTION_TYPES),
                parameters={"k": draw(st.text(max_size=8))},
                next_action=target,
                errors=errors,
            )
        )
    return build_contact_flow(actions, start_action=ids[0])


def _graph_signature(graph):
    """A comparable signature of a graph's structure for round-trip checks."""
    return {
        "flow_id": graph.flow_id,
        "entry": graph.entry_point_id,
        "actions": {
            aid: (
                a.action_type,
                sorted(t.target_action_id for t in a.transitions),
                sorted(t.target_action_id for t in a.error_transitions),
            )
            for aid, a in graph.actions.items()
        },
    }


class TestRoundTrip:
    @settings(max_examples=100)
    @given(flow=contact_flow_strategy())
    def test_parse_serialize_roundtrip(self, flow):
        parser = ContactFlowParser()
        g1 = parser.parse(flow)
        g2 = parser.parse(parser.serialize(g1))
        assert _graph_signature(g1) == _graph_signature(g2)

    def test_unknown_action_type_preserved(self):
        parser = ContactFlowParser()
        flow = build_contact_flow(
            [build_action("a1", "SomeFutureUnknownType", {"custom": "value"}, next_action=None)]
        )
        graph = parser.parse(flow)
        out = parser.serialize(graph)
        assert out["Actions"][0]["Type"] == "SomeFutureUnknownType"
        assert out["Actions"][0]["Parameters"] == {"custom": "value"}


class TestMalformedInput:
    def test_non_dict_raises_parse_error(self):
        parser = ContactFlowParser()
        for bad in ([], "string", 42, None):
            with pytest.raises(ContactFlowParseError):
                parser.parse(bad)

    def test_missing_actions_yields_empty_graph(self):
        parser = ContactFlowParser()
        graph = parser.parse({"Identifier": "f1", "Name": "n"})
        assert graph.action_count == 0

    def test_action_without_identifier_skipped(self):
        parser = ContactFlowParser()
        graph = parser.parse({"Actions": [{"Type": "MessageParticipant"}]})
        assert graph.action_count == 0

    @settings(max_examples=75)
    @given(raw=st.text())
    def test_arbitrary_text_never_crashes_parser(self, raw):
        parser = ContactFlowParser()
        try:
            data = json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return  # not JSON; nothing to parse
        try:
            parser.parse(data)
        except ContactFlowParseError:
            pass  # expected for non-dict JSON


class TestCycleDetection:
    def test_unbounded_cycle_detected(self):
        parser = ContactFlowParser()
        # a1 -> a2 -> a1 with no exit condition.
        flow = build_contact_flow(
            [
                build_action("a1", "MessageParticipant", next_action="a2"),
                build_action("a2", "MessageParticipant", next_action="a1"),
            ]
        )
        cycles = detect_cycles(parser.parse(flow))
        assert len(cycles) >= 1
        assert any(not c.has_bounded_exit for c in cycles)

    def test_bounded_cycle_with_loop_counter(self):
        parser = ContactFlowParser()
        flow = build_contact_flow(
            [
                build_action("a1", "GetParticipantInput", next_action="a2"),
                build_action(
                    "a2",
                    "Compare",
                    {"ComparisonValue": "LoopCount"},
                    next_action="a1",
                    conditions=[{"NextAction": "a3", "Condition": {"max": 3}}],
                ),
                build_action("a3", "DisconnectParticipant"),
            ]
        )
        cycles = detect_cycles(parser.parse(flow))
        assert cycles
        assert all(c.has_bounded_exit for c in cycles)

    def test_acyclic_flow_has_no_cycles(self):
        parser = ContactFlowParser()
        flow = build_contact_flow(
            [
                build_action("a1", "MessageParticipant", next_action="a2"),
                build_action("a2", "DisconnectParticipant"),
            ]
        )
        assert detect_cycles(parser.parse(flow)) == []


class TestPatternDetection:
    def test_authentication_pattern(self):
        parser = ContactFlowParser()
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:authenticate-caller"},
                )
            ]
        )
        patterns = detect_patterns(parser.parse(flow))
        assert any(p.pattern_type == "authentication" for p in patterns)

    def test_transfer_classified(self):
        parser = ContactFlowParser()
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "TransferContactToPhoneNumber",
                    {"PhoneNumber": "+18005551212"},
                )
            ]
        )
        patterns = detect_patterns(parser.parse(flow))
        transfer = [p for p in patterns if p.pattern_type == "transfer"]
        assert transfer and transfer[0].details["transfer_type"] == "phone_number"

    def test_self_service_detected(self):
        parser = ContactFlowParser()
        flow = build_contact_flow([build_action("a1", "ConnectToLexBot", {"BotName": "faq"})])
        patterns = detect_patterns(parser.parse(flow))
        assert any(p.pattern_type == "self_service" for p in patterns)


class TestFlowStructuralMetrics:
    def test_metrics_linear_flow_reports_route_length_without_threshold(self):
        # Arrange
        parser = ContactFlowParser()
        actions = [
            build_action(f"a{i}", "MessageParticipant", next_action=f"a{i + 1}") for i in range(55)
        ]
        actions.append(build_action("a55", "DisconnectParticipant"))

        # Act
        metrics = calculate_flow_metrics(parser.parse(build_contact_flow(actions)))

        # Assert
        assert metrics.total_actions == 56
        assert metrics.reachable_actions == 56
        assert metrics.longest_route_transitions == 55
        assert not hasattr(metrics, "overall_score")
        assert not hasattr(metrics, "exceeds_threshold")

    def test_metrics_flow_with_module_reports_structural_signals(self):
        # Arrange
        parser = ContactFlowParser()
        flow = build_contact_flow(
            [
                build_action("a1", "InvokeFlowModule", next_action="a2"),
                build_action("a2", "DisconnectParticipant"),
                build_action("orphan", "MessageParticipant"),
            ]
        )

        # Act
        metrics = calculate_flow_metrics(parser.parse(flow))

        # Assert
        assert metrics.total_actions == 3
        assert metrics.reachable_actions == 2
        assert metrics.module_invocations == 1
        assert metrics.integration_points == 1
        assert metrics.paths_enumerated == 1
        assert metrics.path_enumeration_capped is False

    @settings(max_examples=50)
    @given(flow=contact_flow_strategy())
    def test_metrics_added_disconnected_action_increases_total_only(self, flow):
        # Arrange
        parser = ContactFlowParser()
        base = calculate_flow_metrics(parser.parse(flow))
        flow_with_orphan = dict(flow)
        flow_with_orphan["Actions"] = list(flow["Actions"]) + [
            build_action("extra-act", "MessageParticipant")
        ]

        # Act
        expanded = calculate_flow_metrics(parser.parse(flow_with_orphan))

        # Assert
        assert expanded.total_actions == base.total_actions + 1
        assert expanded.reachable_actions == base.reachable_actions
