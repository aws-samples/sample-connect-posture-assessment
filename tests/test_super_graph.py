"""Regression tests for iterative Caller Journey super-graph construction."""

from amazon_connect_assessment.journey.models import TierAssignment
from amazon_connect_assessment.journey.super_graph import build_super_graph
from amazon_connect_assessment.models import ContactFlowGraph, FlowAction


def _flow(flow_id: str, next_flow_id: str | None) -> ContactFlowGraph:
    parameters = {"ContactFlowId": next_flow_id} if next_flow_id else {}
    action_type = "TransferToFlow" if next_flow_id else "DisconnectParticipant"
    action = FlowAction(
        action_id="entry",
        action_type=action_type,
        parameters=parameters,
    )
    return ContactFlowGraph(
        flow_id=flow_id,
        flow_name=flow_id,
        flow_type="CONTACT_FLOW",
        actions={"entry": action},
        entry_point_id="entry",
    )


def test_build_super_graph_handles_deep_cross_flow_chain():
    flow_count = 2_000
    parsed_flows = {
        f"flow-{index}": _flow(
            f"flow-{index}",
            f"flow-{index + 1}" if index + 1 < flow_count else None,
        )
        for index in range(flow_count)
    }
    tier_assignments = [
        TierAssignment(
            flow_id="flow-0",
            flow_name="flow-0",
            tier="tier1_did",
            rationale="test entry point",
        )
    ]

    graph = build_super_graph(parsed_flows, tier_assignments)

    assert len(graph.nodes) == flow_count
    assert len(graph.entry_points) == flow_count
    assert graph.successors("flow-0::entry") == ["flow-1::entry"]
    assert graph.successors(f"flow-{flow_count - 2}::entry") == [f"flow-{flow_count - 1}::entry"]
