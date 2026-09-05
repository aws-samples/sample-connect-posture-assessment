"""Caller-focused projection for Amazon Connect contact-flow graphs.

The parser deliberately preserves Amazon Connect's action-level structure.  That
is useful for checks, but it is too mechanical for a reader-facing journey map.
This module projects that raw graph into a smaller, inspectable model:

* consecutive invisible processing actions become system-work groups;
* duplicate transitions between the same displayed steps share one connector;
* branch names are translated into plain language without discarding raw values;
* a deterministic terminal-reaching route is marked as the primary caller path.

All traversal is iterative and bounded by the graph size.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Set, Tuple

from ..models import ContactFlowGraph, FlowAction, FlowTransition

ActionLabeler = Callable[[FlowAction], Tuple[str, str]]
ActionScopeLabeler = Callable[[FlowAction], List[str]]
ActionAIDescriber = Callable[[FlowAction], Dict[str, str]]

_ROUTE_PRIORITY = {"normal": 0, "fallback": 1, "exception": 2}
_COMPLETION_WORDS = {"complete", "completed", "resolved", "success", "succeeded", "handled"}
_FALLBACK_TYPES = {"NoMatchingCondition", "InputTimeLimitExceeded"}
_READER_LABELS = {
    "NoMatchingCondition": "Not understood",
    "NoMatchingError": "Catch-all error route",
    "QueueAtCapacity": "Queue full",
    "InputTimeLimitExceeded": "No response",
    "InvalidPhoneNumber": "Invalid phone number",
    "ContactNotLinked": "Contact not linked",
}
_OUTCOME_MEANINGS = {
    "NoMatchingCondition": "The caller's response did not match a configured choice.",
    "NoMatchingError": (
        "A configured catch-all route used only if the action fails and no specific error "
        "condition matches. This does not mean an error was observed."
    ),
    "QueueAtCapacity": "The destination queue cannot accept another contact.",
    "InputTimeLimitExceeded": "The caller did not respond before the input timer expired.",
    "InvalidPhoneNumber": "The captured value is not a valid phone number.",
    "ContactNotLinked": "The contact could not be linked to the requested record.",
}


@dataclass
class JourneyOutcome:
    """One raw Amazon Connect outcome carried by a displayed connector."""

    label: str
    raw_label: str
    route_type: str
    transition_type: str
    meaning: str

    def to_dict(self) -> Dict[str, str]:
        return {
            "label": self.label,
            "raw_label": self.raw_label,
            "route_type": self.route_type,
            "transition_type": self.transition_type,
            "meaning": self.meaning,
        }


@dataclass
class JourneyNode:
    """A caller-visible action or an inspectable group of system actions."""

    key: str
    category: str
    label: str
    summary: str
    actions: List[Dict[str, str]]
    scope: List[str] = field(default_factory=list)
    ai: Dict[str, str] = field(default_factory=dict)
    is_entry: bool = False
    is_primary: bool = False
    absorbed_outcomes: List[Dict[str, str]] = field(default_factory=list)

    @property
    def action_ids(self) -> List[str]:
        return [action["id"] for action in self.actions]

    @property
    def action_types(self) -> List[str]:
        return [action["type"] for action in self.actions]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.label,
            "category": self.category,
            "summary": self.summary,
            "scope": self.scope,
            "ai": self.ai,
            "is_group": len(self.actions) > 1,
            "is_entry": self.is_entry,
            "is_primary": self.is_primary,
            "actions": self.actions,
            "absorbed_outcomes": self.absorbed_outcomes,
        }


@dataclass
class JourneyEdge:
    """A physical connector between two displayed journey steps."""

    key: str
    source: str
    target: str
    label: str
    route_type: str
    outcomes: List[JourneyOutcome]
    is_primary: bool = False
    is_feedback: bool = False

    @property
    def meaning(self) -> str:
        meanings: List[str] = []
        for outcome in self.outcomes:
            if outcome.meaning and outcome.meaning not in meanings:
                meanings.append(outcome.meaning)
        return " ".join(meanings)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.label or "Continue",
            "source": self.source,
            "target": self.target,
            "route_type": self.route_type,
            "summary": self.meaning,
            "is_primary": self.is_primary,
            "is_feedback": self.is_feedback,
            "outcomes": [outcome.to_dict() for outcome in self.outcomes],
        }


@dataclass
class JourneyViewModel:
    """Projected graph consumed by the HTML and standalone SVG renderers."""

    nodes: Dict[str, JourneyNode]
    edges: List[JourneyEdge]
    primary_path: List[str]
    original_action_count: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": {key: node.to_dict() for key, node in self.nodes.items()},
            "edges": {edge.key: edge.to_dict() for edge in self.edges},
            "primary_path": self.primary_path,
            "original_action_count": self.original_action_count,
            "displayed_step_count": len(self.nodes),
        }


@dataclass
class _RawEdge:
    source: str
    target: str
    outcome: JourneyOutcome
    ordinal: int


@dataclass
class _Unit:
    action_ids: List[str]
    first_index: int


def build_journey_view_model(
    graph: ContactFlowGraph,
    label_action: ActionLabeler,
    scope_action: ActionScopeLabeler,
    describe_ai: ActionAIDescriber,
) -> JourneyViewModel:
    """Project ``graph`` into a deterministic caller-facing journey model."""
    action_order = {action_id: index for index, action_id in enumerate(graph.actions)}
    raw_edges = _collect_raw_edges(graph)
    primary_actions = _select_primary_action_path(graph, raw_edges, label_action)

    units = _build_display_units(graph, raw_edges, label_action, action_order)
    units.sort(key=lambda unit: (unit.first_index, unit.action_ids[0]))

    nodes: Dict[str, JourneyNode] = {}
    action_to_node: Dict[str, str] = {}
    primary_action_set = set(primary_actions)
    for index, unit in enumerate(units):
        key = f"n{index}"
        node = _build_node(
            key,
            unit.action_ids,
            graph,
            label_action,
            graph.entry_point_id,
            primary_action_set,
            scope_action,
            describe_ai,
        )
        nodes[key] = node
        for action_id in unit.action_ids:
            action_to_node[action_id] = key

    primary_path: List[str] = []
    for action_id in primary_actions:
        node_key = action_to_node.get(action_id)
        if node_key and (not primary_path or primary_path[-1] != node_key):
            primary_path.append(node_key)
    primary_pairs = set(zip(primary_path, primary_path[1:]))

    grouped: Dict[Tuple[str, str], List[JourneyOutcome]] = {}
    grouped_order: List[Tuple[str, str]] = []
    for raw_edge in raw_edges:
        source_key = action_to_node.get(raw_edge.source)
        target_key = action_to_node.get(raw_edge.target)
        if source_key is None or target_key is None:
            continue
        if source_key == target_key:
            if raw_edge.outcome.transition_type != "default":
                absorbed_outcome = _absorbed_outcome_to_dict(raw_edge, graph, label_action)
                if not _contains_absorbed_outcome(
                    nodes[source_key].absorbed_outcomes, absorbed_outcome
                ):
                    nodes[source_key].absorbed_outcomes.append(absorbed_outcome)
            continue
        pair = (source_key, target_key)
        if pair not in grouped:
            grouped[pair] = []
            grouped_order.append(pair)
        if not _contains_outcome(grouped[pair], raw_edge.outcome):
            grouped[pair].append(raw_edge.outcome)

    outgoing_target_count: Dict[str, int] = {}
    for source_key, _target_key in grouped_order:
        outgoing_target_count[source_key] = outgoing_target_count.get(source_key, 0) + 1

    edges: List[JourneyEdge] = []
    for index, (source_key, target_key) in enumerate(grouped_order):
        outcomes = grouped[(source_key, target_key)]
        route_type = min(outcomes, key=lambda item: _ROUTE_PRIORITY[item.route_type]).route_type
        labels = _display_labels(
            outcomes,
            outgoing_target_count[source_key] > 1,
            nodes[source_key].action_types,
        )
        edge = JourneyEdge(
            key=f"e{index}",
            source=source_key,
            target=target_key,
            label=" / ".join(labels),
            route_type=route_type,
            outcomes=outcomes,
            is_primary=(source_key, target_key) in primary_pairs,
        )
        edges.append(edge)

    _append_route_context(nodes, edges)

    return JourneyViewModel(
        nodes=nodes,
        edges=edges,
        primary_path=primary_path,
        original_action_count=len(graph.actions),
    )


def _append_route_context(nodes: Dict[str, JourneyNode], edges: List[JourneyEdge]) -> None:
    """Explain meaningful branching on the source block without exposing predicates."""
    outgoing: Dict[str, List[JourneyEdge]] = {}
    for edge in edges:
        outgoing.setdefault(edge.source, []).append(edge)

    for source_key, routes in outgoing.items():
        if len(routes) <= 1:
            continue
        node = nodes[source_key]
        for route in routes:
            if not route.label or route.label == "Continue":
                continue
            target = nodes.get(route.target)
            target_label = target.label if target else "the next journey step"
            if len(target_label) > 72:
                target_label = target_label[:69].rstrip() + "…"
            item = f"Routes {route.label} to {target_label}."
            if item not in node.scope:
                node.scope.append(item)


def _collect_raw_edges(graph: ContactFlowGraph) -> List[_RawEdge]:
    edges: List[_RawEdge] = []
    ordinal = 0
    for action in graph.actions.values():
        for transition in action.all_transitions:
            if transition.target_action_id not in graph.actions:
                continue
            edges.append(
                _RawEdge(
                    source=action.action_id,
                    target=transition.target_action_id,
                    outcome=_normalize_outcome(transition),
                    ordinal=ordinal,
                )
            )
            ordinal += 1
    return edges


def _normalize_outcome(transition: FlowTransition) -> JourneyOutcome:
    raw_label = str(transition.condition or "").strip()
    token, operator = _condition_token(raw_label)
    known_token = token if token in _READER_LABELS else raw_label

    if known_token in _FALLBACK_TYPES:
        route_type = "fallback"
    elif transition.transition_type == "error" or known_token in _READER_LABELS:
        route_type = "exception"
    else:
        route_type = "normal"

    if not raw_label:
        label = "Continue"
        meaning = ""
    elif known_token in _READER_LABELS:
        label = _READER_LABELS[known_token]
        meaning = _OUTCOME_MEANINGS[known_token]
    elif token:
        label = _business_label(token)
        if operator and operator.lower() not in {"equals", "equalto"}:
            label = f"{_humanize(operator)} {label}"
        meaning = f"This route is taken when the configured condition matches {token}."
    else:
        label = _humanize(raw_label)
        meaning = "This route is taken when its configured condition or outcome occurs."

    return JourneyOutcome(
        label=label,
        raw_label=raw_label or "Default",
        route_type=route_type,
        transition_type=transition.transition_type or "default",
        meaning=meaning,
    )


def _condition_token(raw_label: str) -> Tuple[str, str]:
    if not raw_label:
        return "", ""
    if raw_label in _READER_LABELS:
        return raw_label, ""
    try:
        parsed = ast.literal_eval(raw_label)
    except (ValueError, SyntaxError):
        return raw_label, ""
    if not isinstance(parsed, dict):
        return raw_label, ""
    operator = str(parsed.get("Operator") or "")
    operands = parsed.get("Operands")
    if isinstance(operands, list) and len(operands) == 1:
        return str(operands[0]), operator
    return raw_label, operator


def _business_label(token: str) -> str:
    normalized = token.strip()
    if normalized.casefold() in _COMPLETION_WORDS:
        return "Resolved"
    if normalized.casefold() == "escalate":
        return "Escalate to specialist"
    return _humanize(normalized)


def _humanize(value: str) -> str:
    cleaned = re.sub(r"[_-]+", " ", value).strip()
    cleaned = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", " ", cleaned)
    return cleaned[:1].upper() + cleaned[1:] if cleaned else "Condition"


def _select_primary_action_path(
    graph: ContactFlowGraph,
    raw_edges: List[_RawEdge],
    label_action: ActionLabeler,
) -> List[str]:
    if not graph.actions:
        return []
    start = (
        graph.entry_point_id
        if graph.entry_point_id in graph.actions
        else _inferred_entry(graph, raw_edges)
    )
    outgoing: Dict[str, List[_RawEdge]] = {}
    for edge in raw_edges:
        outgoing.setdefault(edge.source, []).append(edge)

    terminals = {
        action_id
        for action_id, action in graph.actions.items()
        if label_action(action)[0] == "terminal" or not outgoing.get(action_id)
    }
    if not terminals:
        terminals = {sorted(graph.actions)[-1]}

    allowed_route_types: Set[str] = {"normal"}
    reachable = _terminal_reachable(raw_edges, terminals, allowed_route_types)
    if start not in reachable:
        allowed_route_types.add("fallback")
        reachable = _terminal_reachable(raw_edges, terminals, allowed_route_types)
    if start not in reachable:
        allowed_route_types.add("exception")
        reachable = _terminal_reachable(raw_edges, terminals, allowed_route_types)

    path = [start]
    seen = {start}
    current = start
    while current not in terminals and len(path) <= len(graph.actions):
        candidates = [
            edge
            for edge in outgoing.get(current, [])
            if edge.outcome.route_type in allowed_route_types
            and edge.target in reachable
            and edge.target not in seen
        ]
        if not candidates:
            break
        selected = min(candidates, key=_primary_edge_sort_key)
        current = selected.target
        path.append(current)
        seen.add(current)
    return path


def _inferred_entry(graph: ContactFlowGraph, raw_edges: List[_RawEdge]) -> str:
    incoming = {edge.target for edge in raw_edges}
    roots = sorted(action_id for action_id in graph.actions if action_id not in incoming)
    return roots[0] if roots else sorted(graph.actions)[0]


def _terminal_reachable(
    edges: List[_RawEdge], terminals: Set[str], allowed_route_types: Set[str]
) -> Set[str]:
    reverse: Dict[str, List[str]] = {}
    for edge in edges:
        if edge.outcome.route_type in allowed_route_types:
            reverse.setdefault(edge.target, []).append(edge.source)
    reachable = set(terminals)
    queue = sorted(terminals)
    head = 0
    while head < len(queue):
        current = queue[head]
        head += 1
        for predecessor in reverse.get(current, []):
            if predecessor not in reachable:
                reachable.add(predecessor)
                queue.append(predecessor)
    return reachable


def _primary_edge_sort_key(edge: _RawEdge) -> Tuple[int, str, str, int]:
    label = edge.outcome.label.casefold()
    if label in _COMPLETION_WORDS or label == "resolved":
        priority = 0
    elif edge.outcome.transition_type == "default":
        priority = 1
    elif edge.outcome.route_type == "normal":
        priority = 2
    elif edge.outcome.route_type == "fallback":
        priority = 3
    else:
        priority = 4
    return priority, label, edge.target, edge.ordinal


def _build_display_units(
    graph: ContactFlowGraph,
    raw_edges: List[_RawEdge],
    label_action: ActionLabeler,
    action_order: Dict[str, int],
) -> List[_Unit]:
    processing = {
        action_id
        for action_id, action in graph.actions.items()
        if label_action(action)[0] == "processing"
    }
    neighbors: Dict[str, Set[str]] = {action_id: set() for action_id in processing}
    for edge in raw_edges:
        if edge.source in processing and edge.target in processing:
            neighbors[edge.source].add(edge.target)
            neighbors[edge.target].add(edge.source)

    units: List[_Unit] = []
    seen: Set[str] = set()
    for action_id in sorted(processing, key=lambda item: (action_order[item], item)):
        if action_id in seen:
            continue
        component: List[str] = []
        stack = [action_id]
        seen.add(action_id)
        while stack:
            current = stack.pop()
            component.append(current)
            for neighbor in sorted(
                neighbors[current], key=lambda item: (action_order[item], item), reverse=True
            ):
                if neighbor not in seen:
                    seen.add(neighbor)
                    stack.append(neighbor)
        component.sort(key=lambda item: (action_order[item], item))
        units.append(_Unit(component, min(action_order[item] for item in component)))

    for action_id in graph.actions:
        if action_id not in processing:
            units.append(_Unit([action_id], action_order[action_id]))
    return units


def _build_node(
    key: str,
    action_ids: List[str],
    graph: ContactFlowGraph,
    label_action: ActionLabeler,
    entry_id: str,
    primary_action_set: Set[str],
    scope_action: ActionScopeLabeler,
    describe_ai: ActionAIDescriber,
) -> JourneyNode:
    actions = [graph.actions[action_id] for action_id in action_ids]
    categories_and_labels = [label_action(action) for action in actions]
    is_group = len(actions) > 1
    category = "processing" if is_group else categories_and_labels[0][0]

    if is_group:
        if entry_id in action_ids:
            label = f"System setup · {len(actions)} internal actions"
            summary = "Prepares the contact before the caller-facing journey begins."
        elif any("queue" in action.action_type.casefold() for action in actions):
            label = f"Prepare queue transfer · {len(actions)} actions"
            summary = "Selects and prepares the destination used for the handoff."
        else:
            label = f"System work · {len(actions)} internal actions"
            summary = "Groups consecutive internal actions that are invisible to the caller."
    else:
        category, label = categories_and_labels[0]
        if category == "processing" and "queue" in actions[0].action_type.casefold():
            label = "Prepare queue transfer"
            summary = "Selects and prepares the destination used for the handoff."
        else:
            summary = ""

    action_details = [
        {
            "id": action.action_id,
            "type": action.action_type or "Unknown action",
            "detail": label_action(action)[1],
        }
        for action in actions
    ]
    scope: List[str] = []
    for action in actions:
        action_scope = scope_action(action)
        items = [" ".join(action_scope)] if is_group and action_scope else action_scope
        for item in items:
            if item and item not in scope:
                scope.append(item)

    ai: Dict[str, str] = {}
    for action in actions:
        candidate = describe_ai(action)
        if candidate:
            ai = candidate
            break

    return JourneyNode(
        key=key,
        category=category,
        label=label,
        summary=summary,
        actions=action_details,
        scope=scope,
        ai=ai,
        is_entry=entry_id in action_ids,
        is_primary=any(action_id in primary_action_set for action_id in action_ids),
    )


def _absorbed_outcome_to_dict(
    raw_edge: _RawEdge,
    graph: ContactFlowGraph,
    label_action: ActionLabeler,
) -> Dict[str, str]:
    """Serialize an internal route without losing its source or destination."""
    source_action = graph.actions[raw_edge.source]
    target_action = graph.actions[raw_edge.target]
    _source_category, source_label = label_action(source_action)
    _target_category, target_label = label_action(target_action)
    if source_label in {source_action.action_type, "Internal contact processing"}:
        source_label = _humanize(source_action.action_type)
    if target_label in {target_action.action_type, "Internal contact processing"}:
        target_label = _humanize(target_action.action_type)
    return {
        **raw_edge.outcome.to_dict(),
        "source_action_id": source_action.action_id,
        "source_action_type": source_action.action_type or "Unknown action",
        "source_action_label": source_label,
        "target_action_id": target_action.action_id,
        "target_action_type": target_action.action_type or "Unknown action",
        "target_action_label": target_label,
    }


def _contains_absorbed_outcome(outcomes: List[Dict[str, str]], candidate: Dict[str, str]) -> bool:
    """Deduplicate only routes with the same provenance and Connect outcome."""
    identity_keys = (
        "source_action_id",
        "target_action_id",
        "route_type",
        "transition_type",
        "raw_label",
    )
    return any(
        all(item.get(key) == candidate.get(key) for key in identity_keys) for item in outcomes
    )


def _contains_outcome(outcomes: List[JourneyOutcome], candidate: JourneyOutcome) -> bool:
    return any(
        item.raw_label == candidate.raw_label
        and item.route_type == candidate.route_type
        and item.transition_type == candidate.transition_type
        for item in outcomes
    )


def _display_labels(
    outcomes: List[JourneyOutcome],
    has_siblings: bool,
    source_action_types: List[str],
) -> List[str]:
    """Choose a concise label for one physical, potentially grouped route."""
    default_outcome = next((item for item in outcomes if item.transition_type == "default"), None)
    normal_conditions = [
        item
        for item in outcomes
        if item.transition_type == "condition" and item.route_type == "normal"
    ]
    fallback_outcomes = [item for item in outcomes if item.route_type == "fallback"]

    if default_outcome is not None:
        if (
            any(
                action_type in {"TransferToQueue", "TransferContactToQueue"}
                for action_type in source_action_types
            )
            and has_siblings
        ):
            return ["Connected to agent"]
        if normal_conditions:
            labels = [item.label for item in normal_conditions]
            if fallback_outcomes:
                labels.append("No match")
            return list(dict.fromkeys(labels))
        if len(outcomes) > 1:
            # A default and one or more errors converge on the same next
            # step. The caller still continues normally; the inspector
            # retains the absorbed error aliases without mislabeling the
            # connector as a failure route.
            return ["Continue"]
        return ["Otherwise" if has_siblings else "Continue"]

    labels = [
        item.label
        for item in sorted(
            outcomes,
            key=lambda item: (_ROUTE_PRIORITY[item.route_type], item.label.casefold()),
        )
    ]
    labels = list(dict.fromkeys(labels))
    if set(labels) == {"Queue full", "Catch-all error route"}:
        return ["Queue unavailable"]
    return labels or ["Continue"]
