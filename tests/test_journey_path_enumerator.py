"""
Tests for journey.path_enumerator.enumerate_journeys.

Regression coverage for two bugs found in review:

1. Paths that hit max_depth were dropped entirely (`continue` with
   nothing recorded). Any flow deep/branchy enough to need the depth cap
   produced ZERO journeys for that branch — a false negative, since
   security/containment/dead-end checks downstream never saw that path
   at all. Fixed to record a "truncated" terminal path instead of
   silently discarding it.

2. A cross-flow action (TransferToFlow/TransferContactToFlow/
   InvokeFlowModule) with no outgoing super-graph edge was labeled
   terminal_type="disconnect", reason="dead_end" — but no edge exists
   there specifically BECAUSE super_graph.build_super_graph couldn't
   statically resolve a dynamic/attribute-based transfer target, not
   because the caller's journey actually dead-ends. That fabricated a
   real "journey-res-001 Dead-End Caller Path" HIGH finding for what is
   often just normal dynamic routing. Fixed to label these
   "unresolved_transfer" instead of "disconnect"/"dead_end".
"""

from amazon_connect_assessment.journey.models import (
    JourneyNode,
    PhoneNumberEntry,
    SuperGraph,
)
from amazon_connect_assessment.journey.path_enumerator import (
    MAX_PATH_DEPTH,
    enumerate_journeys,
)


def _node(flow_id, action_id, action_type, parameters=None) -> JourneyNode:
    return JourneyNode(
        flow_id=flow_id,
        flow_name=f"flow-{flow_id}",
        action_id=action_id,
        action_type=action_type,
        parameters=parameters or {},
    )


def _phone_entry(number, flow_id):
    return PhoneNumberEntry(
        phone_number=number,
        number_type="DID",
        country_code="US",
        contact_flow_id=flow_id,
    )


class TestDeepPathTruncation:
    def test_path_exceeding_max_depth_is_recorded_not_dropped(self):
        """
        Build a straight-line chain of MessageParticipant nodes longer
        than max_depth, with no terminal action anywhere in the chain.
        Before the fix this produced ZERO journeys. After the fix it
        must produce exactly one journey with terminal_type="truncated".
        """
        graph = SuperGraph()
        chain_length = 10
        for i in range(chain_length):
            key = f"f1::a{i}"
            graph.nodes[key] = _node("f1", f"a{i}", "MessageParticipant")
            if i > 0:
                graph.adjacency.setdefault(f"f1::a{i - 1}", []).append(key)
        graph.entry_points["f1"] = "f1::a0"

        entries = [_phone_entry("+18005551212", "f1")]
        journeys = enumerate_journeys(graph, entries, max_depth=5)

        assert len(journeys) == 1
        assert journeys[0].terminal_type == "truncated"
        assert journeys[0].terminal_details["reason"] == "max_depth_exceeded"
        # Recorded path length should be capped near the depth bound, not
        # the full 10-node chain.
        assert len(journeys[0].nodes) <= 6

    def test_default_max_depth_constant_unchanged(self):
        # Sanity check that the public constant is still 50 — a
        # regression here would silently change behavior across the
        # whole journey mapping pipeline.
        assert MAX_PATH_DEPTH == 50

    def test_short_path_under_depth_limit_is_unaffected(self):
        graph = SuperGraph()
        graph.nodes["f1::a0"] = _node("f1", "a0", "MessageParticipant")
        graph.nodes["f1::a1"] = _node("f1", "a1", "DisconnectParticipant")
        graph.adjacency["f1::a0"] = ["f1::a1"]
        graph.entry_points["f1"] = "f1::a0"

        entries = [_phone_entry("+18005551212", "f1")]
        journeys = enumerate_journeys(graph, entries, max_depth=50)

        assert len(journeys) == 1
        assert journeys[0].terminal_type == "disconnect"
        assert journeys[0].terminal_details.get("reason") != "max_depth_exceeded"


class TestUnresolvedTransferNotMislabeledAsDeadEnd:
    def test_cross_flow_action_with_no_edge_is_unresolved_not_dead_end(self):
        """
        A TransferToFlow node with no outgoing super-graph edge (because
        the target was a dynamic attribute reference super_graph
        couldn't resolve) must be labeled "unresolved_transfer", never
        "disconnect"/"dead_end".
        """
        graph = SuperGraph()
        graph.nodes["f1::a0"] = _node(
            "f1", "a0", "TransferToFlow", parameters={"ContactFlowId": "$.Attributes.NextFlow"}
        )
        # Deliberately no adjacency entry for f1::a0 — this is the
        # "couldn't resolve" case.
        graph.entry_points["f1"] = "f1::a0"

        entries = [_phone_entry("+18005551212", "f1")]
        journeys = enumerate_journeys(graph, entries)

        assert len(journeys) == 1
        assert journeys[0].terminal_type == "unresolved_transfer"
        assert journeys[0].terminal_type != "disconnect"
        assert journeys[0].terminal_details["reason"] == "dynamic_transfer_target"

    def test_transfer_contact_to_flow_also_treated_as_unresolved(self):
        graph = SuperGraph()
        graph.nodes["f1::a0"] = _node("f1", "a0", "TransferContactToFlow")
        graph.entry_points["f1"] = "f1::a0"

        entries = [_phone_entry("+18005551212", "f1")]
        journeys = enumerate_journeys(graph, entries)

        assert journeys[0].terminal_type == "unresolved_transfer"

    def test_invoke_flow_module_also_treated_as_unresolved(self):
        graph = SuperGraph()
        graph.nodes["f1::a0"] = _node("f1", "a0", "InvokeFlowModule")
        graph.entry_points["f1"] = "f1::a0"

        entries = [_phone_entry("+18005551212", "f1")]
        journeys = enumerate_journeys(graph, entries)

        assert journeys[0].terminal_type == "unresolved_transfer"

    def test_genuine_dead_end_is_still_labeled_disconnect(self):
        """
        A non-cross-flow action with no outgoing edge and no recognized
        terminal type IS a real dead end and must keep the
        disconnect/dead_end label — the fix narrows the exception to
        cross-flow actions only, it doesn't remove dead-end detection
        entirely.
        """
        graph = SuperGraph()
        graph.nodes["f1::a0"] = _node("f1", "a0", "SetContactAttributes")
        graph.entry_points["f1"] = "f1::a0"

        entries = [_phone_entry("+18005551212", "f1")]
        journeys = enumerate_journeys(graph, entries)

        assert journeys[0].terminal_type == "disconnect"
        assert journeys[0].terminal_details["reason"] == "dead_end"

    def test_unresolved_transfer_paths_are_excluded_from_dead_end_scoring(self):
        # journey_scorer's dead-end deficiency check filters on
        # terminal_type == "disconnect" AND reason == "dead_end" — an
        # "unresolved_transfer" path must not match that filter.
        from amazon_connect_assessment.journey.journey_scorer import score_journeys

        graph = SuperGraph()
        graph.nodes["f1::a0"] = _node("f1", "a0", "TransferToFlow")
        graph.entry_points["f1"] = "f1::a0"
        entries = [_phone_entry("+18005551212", "f1")]
        journeys = enumerate_journeys(graph, entries)

        scores = score_journeys(journeys, config={})
        j = journeys[0]
        score = scores[j.path_hash]
        assert "⚠️ Dead-end disconnect" not in score.deficiencies
