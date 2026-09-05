"""
Graph algorithms over a parsed ``ContactFlowGraph``.

Provides cycle detection (with bounded-exit analysis), path enumeration,
branching-depth calculation, and reachability — used by the loop, error
handling, complexity, and containment checks.

Implemented iteratively to avoid Python recursion limits on large flows.
"""

from typing import List, Set

from ..models import ContactFlowGraph, CycleInfo

# Action/parameter signals that bound a loop (give it a guaranteed exit).
_LOOP_COUNTER_TYPES = {"Loop", "Compare", "CheckAttribute", "CheckContactAttributes"}
_LOOP_COUNTER_HINTS = ("loop", "count", "attempt", "retry", "iteration")
_TIMEOUT_INPUT_TYPES = {"GetParticipantInput", "GetUserInput", "StoreUserInput"}


def successors(graph: ContactFlowGraph, action_id: str) -> List[str]:
    """Return the target action ids of all outgoing transitions for an action."""
    action = graph.actions.get(action_id)
    if not action:
        return []
    return [t.target_action_id for t in action.all_transitions]


def detect_cycles(graph: ContactFlowGraph) -> List[CycleInfo]:
    """
    Detect cycles using iterative DFS with a recursion stack.

    For each back-edge found, the cycle slice is extracted from the current
    DFS path and analyzed for a bounded exit condition.
    """
    visited: Set[str] = set()
    cycles: List[CycleInfo] = []
    seen_cycle_keys: Set[frozenset] = set()

    for root in graph.actions:
        if root in visited:
            continue

        # Iterative DFS carrying the active path and a per-node child index.
        path: List[str] = []
        on_stack: Set[str] = set()
        # stack of (node, iterator-index)
        stack: List[List] = [[root, 0]]

        while stack:
            node, idx = stack[-1]
            if idx == 0:
                visited.add(node)
                on_stack.add(node)
                path.append(node)

            succ = successors(graph, node)
            if idx < len(succ):
                stack[-1][1] += 1
                target = succ[idx]
                if target not in visited:
                    stack.append([target, 0])
                elif target in on_stack:
                    # Back-edge → cycle from `target` to current `node`.
                    start = path.index(target)
                    cycle_actions = path[start:]
                    key = frozenset(cycle_actions)
                    if key not in seen_cycle_keys:
                        seen_cycle_keys.add(key)
                        exit_type = _bounded_exit_type(graph, cycle_actions)
                        cycles.append(
                            CycleInfo(
                                cycle_actions=list(cycle_actions),
                                has_bounded_exit=exit_type is not None,
                                exit_condition_type=exit_type,
                            )
                        )
            else:
                on_stack.discard(node)
                if path and path[-1] == node:
                    path.pop()
                stack.pop()

    return cycles


def _bounded_exit_type(graph: ContactFlowGraph, cycle_actions: List[str]):
    """
    Determine whether a cycle has a bounded exit; return the exit type or None.

    A cycle is bounded if any action in it either:
    - is a loop-counter / comparison construct referencing loop/attempt hints,
    - is an input action with a Timeout parameter, or
    - has a transition leaving the cycle (a conditional escape).
    """
    cycle_set = set(cycle_actions)
    for action_id in cycle_actions:
        action = graph.actions.get(action_id)
        if not action:
            continue

        params_blob = str(action.parameters).lower()

        if action.action_type in _LOOP_COUNTER_TYPES and any(
            hint in params_blob for hint in _LOOP_COUNTER_HINTS
        ):
            return "loop_count"

        if action.action_type in _TIMEOUT_INPUT_TYPES and (
            "timeout" in params_blob or action.parameters.get("Timeout")
        ):
            return "timeout"

        # A transition that leaves the cycle is a conditional escape hatch.
        for t in action.all_transitions:
            if t.target_action_id not in cycle_set:
                return "condition"

    return None


# Same order of magnitude as count_paths' default cap. Bounds the number
# of (node, seen-set) stack entries longest_simple_path_analysis will push
# before returning the best route length found so far.
_MAX_ROUTE_STATES = 20000


def longest_simple_path_analysis(
    graph: ContactFlowGraph, max_states: int = _MAX_ROUTE_STATES
) -> tuple[int, bool]:
    """Return the longest simple route length and whether traversal was capped.

    The route length is measured in transitions from the entry point. The
    iterative traversal does not revisit nodes on the current path, so cycles
    terminate. A state cap prevents combinatorial growth in heavily branching,
    reconverging flows; if reached, the length is a lower bound.
    """
    if not graph.actions:
        return 0, False
    start = (
        graph.entry_point_id if graph.entry_point_id in graph.actions else next(iter(graph.actions))
    )

    best = 0
    states_explored = 0
    stack = [(start, 0, frozenset([start]))]
    while stack:
        if states_explored >= max_states:
            return best, True
        states_explored += 1
        node, depth, seen = stack.pop()
        best = max(best, depth)
        for target in successors(graph, node):
            if target in graph.actions and target not in seen:
                stack.append((target, depth + 1, seen | {target}))
    return best, False


def longest_simple_path_length(graph: ContactFlowGraph, max_states: int = _MAX_ROUTE_STATES) -> int:
    """Return the longest simple route length in transitions from the entry point."""
    return longest_simple_path_analysis(graph, max_states=max_states)[0]


def count_paths_bounded(graph: ContactFlowGraph, max_paths: int = 100) -> tuple[int, bool]:
    """Count simple entry-to-terminal paths and report whether the cap was reached."""
    if not graph.actions:
        return 0, False
    start = (
        graph.entry_point_id if graph.entry_point_id in graph.actions else next(iter(graph.actions))
    )

    count = 0
    stack = [(start, frozenset([start]))]
    while stack and count < max_paths:
        node, seen = stack.pop()
        succ = [
            target
            for target in successors(graph, node)
            if target in graph.actions and target not in seen
        ]
        if not succ:
            count += 1
            continue
        for target in succ:
            stack.append((target, seen | {target}))
    return count, bool(stack)


def count_paths(graph: ContactFlowGraph, max_paths: int = 100) -> int:
    """Count simple entry-to-terminal paths, capped at ``max_paths``."""
    return count_paths_bounded(graph, max_paths=max_paths)[0]


def reachable_from_entry(graph: ContactFlowGraph) -> Set[str]:
    """Return the set of action ids reachable from the entry point."""
    if not graph.actions:
        return set()
    start = (
        graph.entry_point_id if graph.entry_point_id in graph.actions else next(iter(graph.actions))
    )
    seen: Set[str] = set()
    stack = [start]
    while stack:
        node = stack.pop()
        if node in seen or node not in graph.actions:
            continue
        seen.add(node)
        stack.extend(successors(graph, node))
    return seen
