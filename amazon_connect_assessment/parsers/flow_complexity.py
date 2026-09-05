"""
Descriptive structural metrics for a parsed ``ContactFlowGraph``.

Amazon Connect guidance recommends keeping flows small and modular, but does
not publish a numerical action-count, route-length, or weighted complexity
threshold. These metrics therefore provide review context without claiming an
AWS compliance score.
"""

from ..models import ContactFlowGraph, FlowStructuralMetrics
from . import flow_graph

# Action types that represent external integration points.
_INTEGRATION_ACTION_TYPES = {
    "InvokeLambdaFunction",
    "ConnectToLexBot",
    "ConnectParticipantWithLexBot",
    "TransferContactToPhoneNumber",
    "TransferToPhoneNumber",
    "InvokeFlowModule",
}

_MAX_PATHS = 100


def calculate_flow_metrics(graph: ContactFlowGraph) -> FlowStructuralMetrics:
    """Collect structural review metrics without assigning a compliance score."""
    longest_route, route_analysis_capped = flow_graph.longest_simple_path_analysis(graph)
    paths_enumerated, path_enumeration_capped = flow_graph.count_paths_bounded(
        graph, max_paths=_MAX_PATHS
    )

    return FlowStructuralMetrics(
        total_actions=graph.action_count,
        reachable_actions=len(flow_graph.reachable_from_entry(graph)),
        longest_route_transitions=longest_route,
        route_analysis_capped=route_analysis_capped,
        integration_points=sum(
            1
            for action in graph.actions.values()
            if action.action_type in _INTEGRATION_ACTION_TYPES
        ),
        cycle_count=len(flow_graph.detect_cycles(graph)),
        paths_enumerated=paths_enumerated,
        path_enumeration_capped=path_enumeration_capped,
        module_invocations=sum(
            1 for action in graph.actions.values() if action.action_type == "InvokeFlowModule"
        ),
    )
