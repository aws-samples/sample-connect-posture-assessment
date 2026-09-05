"""
Tests for amazon_connect_assessment.parsers.flow_graph.

The route-length traversal is bounded because heavily branching flows that
reconverge can otherwise create a combinatorial number of simple paths. The
metric is explicitly a longest simple route in transitions, not branch nesting.
"""

from amazon_connect_assessment.models import ContactFlowGraph, FlowAction, FlowTransition
from amazon_connect_assessment.parsers.flow_graph import (
    count_paths,
    count_paths_bounded,
    longest_simple_path_analysis,
    longest_simple_path_length,
    reachable_from_entry,
    successors,
)


def _action(action_id: str, next_ids=None) -> FlowAction:
    transitions = [FlowTransition(action_id, nxt) for nxt in (next_ids or [])]
    return FlowAction(
        action_id=action_id, action_type="MessageParticipant", transitions=transitions
    )


def _linear_graph(length: int) -> ContactFlowGraph:
    """Build a straight-line flow a0 -> a1 -> ... -> a{length-1}."""
    actions = {}
    for i in range(length):
        next_ids = [f"a{i + 1}"] if i < length - 1 else []
        actions[f"a{i}"] = _action(f"a{i}", next_ids)
    return ContactFlowGraph(
        flow_id="f1",
        flow_name="linear",
        flow_type="CONTACT_FLOW",
        actions=actions,
        entry_point_id="a0",
    )


def _diamond_graph(width: int, depth: int) -> ContactFlowGraph:
    """
    Build a flow with `depth` layers, each fanning out to `width` branches
    that all reconverge into a single node before the next layer. This is
    the "many branch points that later reconverge" shape that makes the
    seen-set state space explode: with W branches at each of D layers, a
    naive unbounded traversal explores O(W^D) distinct seen-sets even
    though the graph itself has only O(W*D) nodes.
    """
    actions = {}
    entry = "start"
    actions[entry] = _action(entry, [f"L0_B{i}" for i in range(width)])

    for layer in range(depth):
        branch_ids = [f"L{layer}_B{i}" for i in range(width)]
        converge_id = f"C{layer}"
        for b in branch_ids:
            actions[b] = _action(b, [converge_id])
        if layer + 1 < depth:
            next_branches = [f"L{layer + 1}_B{i}" for i in range(width)]
            actions[converge_id] = _action(converge_id, next_branches)
        else:
            actions[converge_id] = _action(converge_id, [])

    return ContactFlowGraph(
        flow_id="f-diamond",
        flow_name="diamond",
        flow_type="CONTACT_FLOW",
        actions=actions,
        entry_point_id=entry,
    )


class TestSuccessors:
    def test_returns_target_ids(self):
        graph = _linear_graph(3)
        assert successors(graph, "a0") == ["a1"]
        assert successors(graph, "a2") == []

    def test_unknown_action_returns_empty(self):
        graph = _linear_graph(3)
        assert successors(graph, "nope") == []


class TestLongestSimplePath:
    def test_route_empty_graph_returns_zero_and_not_capped(self):
        # Arrange
        graph = ContactFlowGraph(
            flow_id="f", flow_name="empty", flow_type="CONTACT_FLOW", actions={}
        )

        # Act
        length, capped = longest_simple_path_analysis(graph)

        # Assert
        assert length == 0
        assert capped is False

    def test_route_linear_flow_reports_transition_count_not_branch_nesting(self):
        # Arrange
        graph = _linear_graph(10)

        # Act
        result = longest_simple_path_length(graph)

        # Assert
        assert result == 9

    def test_route_diamond_shape_returns_without_unbounded_traversal(self):
        # Arrange
        graph = _diamond_graph(width=8, depth=6)

        # Act
        result = longest_simple_path_length(graph)

        # Assert
        assert isinstance(result, int)
        assert result >= 0

    def test_route_tight_state_limit_marks_result_as_capped(self):
        # Arrange
        graph = _diamond_graph(width=6, depth=5)

        # Act
        bounded, capped = longest_simple_path_analysis(graph, max_states=10)
        complete, complete_capped = longest_simple_path_analysis(graph, max_states=1_000_000)

        # Assert
        assert capped is True
        assert complete_capped is False
        assert 0 <= bounded <= complete

    def test_route_missing_entry_falls_back_to_first_action(self):
        # Arrange
        graph = _linear_graph(3)
        graph.entry_point_id = "does-not-exist"

        # Act
        result = longest_simple_path_length(graph)

        # Assert
        assert isinstance(result, int)


class TestCountPaths:
    def test_paths_linear_flow_has_one_path(self):
        # Arrange
        graph = _linear_graph(5)

        # Act
        result = count_paths(graph)

        # Assert
        assert result == 1

    def test_paths_cap_reports_lower_bound_and_capped_state(self):
        # Arrange
        graph = _diamond_graph(width=4, depth=3)

        # Act
        count, capped = count_paths_bounded(graph, max_paths=5)

        # Assert
        assert count == 5
        assert capped is True


class TestReachableFromEntry:
    def test_linear_flow_all_reachable(self):
        graph = _linear_graph(4)
        assert reachable_from_entry(graph) == {"a0", "a1", "a2", "a3"}

    def test_disconnected_node_not_reachable(self):
        graph = _linear_graph(3)
        graph.actions["orphan"] = _action("orphan", [])
        reached = reachable_from_entry(graph)
        assert "orphan" not in reached
