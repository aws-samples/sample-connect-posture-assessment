"""
Bounded path enumeration for Caller Journey Mapping.

Traces all possible caller paths from each phone number entry point to
terminal outcomes using iterative DFS with depth and path-count bounds.
"""

import logging
from typing import Any, Dict, List

from .models import JourneyNode, JourneyPath, PhoneNumberEntry, SuperGraph

logger = logging.getLogger("journey.path_enumerator")

# Terminal action types and their outcome classification.
TERMINAL_ACTIONS = {
    "TransferToQueue": "agent_queue",
    "TransferContactToQueue": "agent_queue",
    "DisconnectParticipant": "disconnect",
    "EndFlowExecution": "disconnect",
    "CreateCallback": "callback",
    "SetCallbackNumber": "callback",
    "TransferContactToPhoneNumber": "external_transfer",
    "TransferToPhoneNumber": "external_transfer",
}

# Cross-flow action types — kept in sync with super_graph.CROSS_FLOW_ACTIONS.
# A node of one of these types with no outgoing super-graph edge means the
# target flow reference couldn't be statically resolved (dynamic/attribute
# reference), not that the caller's journey actually dead-ends here.
_CROSS_FLOW_ACTION_TYPES = {
    "TransferToFlow",
    "TransferContactToFlow",
    "InvokeFlowModule",
}

MAX_PATHS_PER_ENTRY = 200
MAX_PATH_DEPTH = 50
MAX_TOTAL_PATHS = 5000


def enumerate_journeys(
    super_graph: SuperGraph,
    phone_entries: List[PhoneNumberEntry],
    max_paths: int = MAX_PATHS_PER_ENTRY,
    max_depth: int = MAX_PATH_DEPTH,
) -> List[JourneyPath]:
    """
    Enumerate all journey paths from each phone number entry point.

    Uses iterative DFS with bounded traversal:
    - max_paths caps combinatorial explosion per entry point
    - max_depth prevents infinite depth on deep topologies
    - visited-set on current path prevents cycles
    """
    all_journeys: List[JourneyPath] = []

    for entry in phone_entries:
        if not entry.contact_flow_id:
            continue
        entry_key = super_graph.entry_points.get(entry.contact_flow_id)
        if not entry_key:
            continue

        paths = _enumerate_from_entry(
            super_graph,
            entry_key,
            entry.phone_number,
            entry.number_type,
            max_paths,
            max_depth,
        )
        all_journeys.extend(paths)
        if len(all_journeys) >= MAX_TOTAL_PATHS:
            logger.warning(
                f"Global path limit ({MAX_TOTAL_PATHS}) reached; stopping enumeration early"
            )
            break

    logger.info(
        f"Enumerated {len(all_journeys)} journey paths across {len(phone_entries)} phone numbers"
    )
    return all_journeys


def _enumerate_from_entry(
    graph: SuperGraph,
    entry_key: str,
    entry_number: str,
    entry_type: str,
    max_paths: int,
    max_depth: int,
) -> List[JourneyPath]:
    """
    Iterative bounded DFS from a single entry point.

    Stack items: (current_node_key, path_so_far, visited_on_path)
    """
    paths: List[JourneyPath] = []
    stack: List[tuple] = [(entry_key, [], frozenset([entry_key]))]

    while stack and len(paths) < max_paths:
        current_key, path_nodes, visited = stack.pop()
        node = graph.get_node(current_key)

        if node is None:
            continue

        current_path = path_nodes + [node]

        # Depth bound. A path that hits this limit is a real journey the
        # caller can actually experience — it just happens to be long — so
        # record it as a truncated path rather than silently dropping it.
        # The prior behavior (`continue` with no recorded path) meant any
        # flow deep/branchy enough to need the depth cap produced ZERO
        # journeys for that branch, which is a false negative: security,
        # containment, and dead-end checks downstream never saw that path
        # at all, so a genuinely dead-ended or unauthenticated long path
        # was invisible to every journey-* finding.
        if len(current_path) > max_depth:
            flows_seen = list(dict.fromkeys(n.flow_id for n in current_path))
            paths.append(
                JourneyPath(
                    entry_number=entry_number,
                    entry_number_type=entry_type,
                    nodes=current_path,
                    terminal_type="truncated",
                    terminal_details={
                        "reason": "max_depth_exceeded",
                        "last_action": node.action_type,
                        "depth": len(current_path),
                    },
                    flows_traversed=flows_seen,
                )
            )
            continue

        # Check if terminal.
        terminal_type = TERMINAL_ACTIONS.get(node.action_type)
        if terminal_type:
            flows_seen = list(dict.fromkeys(n.flow_id for n in current_path))
            paths.append(
                JourneyPath(
                    entry_number=entry_number,
                    entry_number_type=entry_type,
                    nodes=current_path,
                    terminal_type=terminal_type,
                    terminal_details=_extract_terminal_details(node),
                    flows_traversed=flows_seen,
                )
            )
            continue

        # Expand successors.
        successors = graph.successors(current_key)
        if not successors:
            flows_seen = list(dict.fromkeys(n.flow_id for n in current_path))

            # A cross-flow action (TransferToFlow/TransferContactToFlow/
            # InvokeFlowModule) with no outgoing edge is NOT necessarily a
            # dead end — super_graph.build_super_graph only adds an edge
            # when it could statically resolve the target flow. When the
            # target is a dynamic/attribute-based reference (e.g. "transfer
            # to the flow named in $.Attributes.NextFlow"), no edge exists
            # even though the call is actually being routed somewhere at
            # runtime; the graph just can't say where. Labeling that
            # "disconnect" / "dead_end" was fabricating a real defect
            # (journey-res-001 "Dead-End Caller Path", HIGH severity) for
            # what is often a perfectly normal dynamic-routing pattern.
            # Give it its own terminal_type so journey_scorer can decide
            # whether/how to surface it, rather than conflating it with an
            # actual dead end.
            if node.action_type in _CROSS_FLOW_ACTION_TYPES:
                paths.append(
                    JourneyPath(
                        entry_number=entry_number,
                        entry_number_type=entry_type,
                        nodes=current_path,
                        terminal_type="unresolved_transfer",
                        terminal_details={
                            "reason": "dynamic_transfer_target",
                            "last_action": node.action_type,
                        },
                        flows_traversed=flows_seen,
                    )
                )
                continue

            # Genuine dead-end: no successors, not a recognized terminal,
            # and not an unresolved dynamic transfer either.
            paths.append(
                JourneyPath(
                    entry_number=entry_number,
                    entry_number_type=entry_type,
                    nodes=current_path,
                    terminal_type="disconnect",
                    terminal_details={
                        "reason": "dead_end",
                        "last_action": node.action_type,
                    },
                    flows_traversed=flows_seen,
                )
            )
            continue

        for succ_key in successors:
            if succ_key not in visited:
                stack.append(
                    (
                        succ_key,
                        current_path,
                        visited | frozenset([succ_key]),
                    )
                )

    return paths


def _extract_terminal_details(node: JourneyNode) -> Dict[str, Any]:
    """Extract relevant details from a terminal node."""
    details: Dict[str, Any] = {
        "action_type": node.action_type,
        "flow_name": node.flow_name,
    }
    params = node.parameters

    if node.action_type in ("TransferToQueue", "TransferContactToQueue"):
        details["queue"] = params.get("QueueId", params.get("Queue", "unknown"))

    elif node.action_type in ("TransferContactToPhoneNumber", "TransferToPhoneNumber"):
        details["phone_number"] = params.get("PhoneNumber", "unknown")

    return details
