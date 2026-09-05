"""
Super-graph construction for Caller Journey Mapping.

Stitches individual ContactFlowGraphs together at transfer/module-invoke
boundaries to form a single instance-wide directed graph.
"""

import logging
from typing import Dict, List, Set

from ..models import ContactFlowGraph
from .models import JourneyNode, SuperGraph, TierAssignment

logger = logging.getLogger("journey.super_graph")

# Action types that create cross-flow edges.
CROSS_FLOW_ACTIONS = {
    "TransferToFlow",
    "TransferContactToFlow",
    "InvokeFlowModule",
}


def build_super_graph(
    parsed_flows: Dict[str, ContactFlowGraph],
    tier_assignments: List[TierAssignment],
) -> SuperGraph:
    """
    Build a super-graph by connecting tier1+tier2 flow graphs at transfer edges.

    Args:
        parsed_flows: All parsed flow graphs indexed by flow_id.
        tier_assignments: Tier classification (only tier1 + tier2 are stitched).

    Returns:
        SuperGraph with all nodes, edges, and entry points.
    """
    graph = SuperGraph()
    in_scope_ids = {
        t.flow_id
        for t in tier_assignments
        if t.tier.startswith("tier1") or t.tier == "tier2_traffic"
    }

    visited: Set[str] = set()
    for flow_id in in_scope_ids:
        if flow_id in parsed_flows:
            _add_flow_to_graph(graph, parsed_flows[flow_id], parsed_flows, visited)

    logger.info(
        f"Super-graph built: {len(graph.nodes)} nodes, "
        f"{sum(len(v) for v in graph.adjacency.values())} edges, "
        f"{len(graph.dynamic_references)} dynamic refs"
    )
    return graph


def _add_flow_to_graph(
    graph: SuperGraph,
    flow: ContactFlowGraph,
    all_flows: Dict[str, ContactFlowGraph],
    visited: Set[str],
) -> None:
    """
    Add a flow and its reachable sub-flows to the super-graph.

    Uses visited set to break circular cross-flow references.
    """
    pending_flows = [flow]
    cross_flow_edges: List[tuple[str, str]] = []

    while pending_flows:
        current_flow = pending_flows.pop()
        if current_flow.flow_id in visited:
            continue
        visited.add(current_flow.flow_id)

        # Add all actions as JourneyNodes.
        for action in current_flow.actions.values():
            node = JourneyNode(
                flow_id=current_flow.flow_id,
                flow_name=current_flow.flow_name,
                action_id=action.action_id,
                action_type=action.action_type,
                parameters=action.parameters,
            )
            graph.nodes[node.key] = node

        # Record entry point.
        if current_flow.entry_point_id:
            entry_key = f"{current_flow.flow_id}::{current_flow.entry_point_id}"
            graph.entry_points[current_flow.flow_id] = entry_key

        # Add intra-flow edges.
        for action in current_flow.actions.values():
            source_key = f"{current_flow.flow_id}::{action.action_id}"
            for transition in action.all_transitions:
                target_id = transition.target_action_id
                target_key = f"{current_flow.flow_id}::{target_id}"
                if target_id in current_flow.actions:
                    graph.adjacency.setdefault(source_key, []).append(target_key)

        # Resolve cross-flow edges. Reachable target flows are added to the
        # explicit stack; links are attached after traversal so every target
        # entry point has been registered before it is referenced.
        for action in current_flow.actions.values():
            if action.action_type not in CROSS_FLOW_ACTIONS:
                continue

            target_flow_id, is_dynamic = _resolve_transfer_target(action, all_flows)

            if is_dynamic:
                graph.dynamic_references.append(
                    {
                        "source_flow": current_flow.flow_id,
                        "source_action": action.action_id,
                        "action_type": action.action_type,
                        "reason": "dynamic — target varies at runtime",
                    }
                )
                continue

            if target_flow_id and target_flow_id in all_flows:
                cross_flow_edges.append(
                    (f"{current_flow.flow_id}::{action.action_id}", target_flow_id)
                )
                if target_flow_id not in visited:
                    pending_flows.append(all_flows[target_flow_id])

    for source_key, target_flow_id in cross_flow_edges:
        target_entry = graph.entry_points.get(target_flow_id)
        if target_entry:
            graph.adjacency.setdefault(source_key, []).append(target_entry)


def _resolve_transfer_target(action, all_flows: Dict[str, ContactFlowGraph]) -> tuple:
    """
    Resolve the target flow_id from a transfer action's parameters.

    Returns: (target_flow_id | None, is_dynamic: bool)
    """
    params = action.parameters or {}

    # Check ContactFlowId parameter.
    flow_ref = params.get("ContactFlowId")
    if isinstance(flow_ref, str):
        if flow_ref in all_flows:
            return (flow_ref, False)
        # Could be a full ARN — extract flow ID from end.
        if "/contact-flow/" in flow_ref:
            extracted = flow_ref.split("/contact-flow/")[-1]
            if extracted in all_flows:
                return (extracted, False)
    if isinstance(flow_ref, dict):
        ref_type = flow_ref.get("Type", "")
        if ref_type in ("Attribute", "UserDefined", "System"):
            return (None, True)
        val = flow_ref.get("Value", "")
        if val in all_flows:
            return (val, False)

    # Check FlowModuleId.
    for key in ("FlowModuleId", "ContactFlowModuleId"):
        module_ref = params.get(key)
        if isinstance(module_ref, str) and module_ref in all_flows:
            return (module_ref, False)

    # Couldn't resolve — might be a dynamic attribute reference embedded
    # in a parameter we don't recognize.
    params_str = str(params)
    if "$." in params_str or "$[" in params_str:
        return (None, True)

    return (None, True)
