"""Caller-focused renderer and portable exporters for Amazon Connect flows.

Raw contact-flow actions are first projected into a compact
:class:`JourneyViewModel`: caller-visible steps remain explicit, connected
internal setup actions become inspectable system-work groups, duplicate
physical routes are consolidated, and reader-facing outcome labels replace
Connect implementation identifiers in the diagram.

The server computes one deterministic left-to-right layout. A cycle-filtered
longest-path rank keeps every ordinary route moving right; the main route is
centered, normal alternatives occupy lanes above it, and fallback/technical
routes occupy lanes below it. Connectors use orthogonal SVG ``H``/``V``
segments, with only true feedback routes leaving the forward lanes.

The same accepted layout produces three artifacts:

* an HTML/SVG hybrid with native button controls for the report inspector;
* a self-contained SVG used for SVG and browser-local PNG downloads; and
* native uncompressed mxGraph XML whose nodes and connectors remain editable
  in diagrams.net/draw.io.

Flow-derived text is escaped for its target format. XML exports also remove
characters XML 1.0 cannot represent. Styles, coordinates, element IDs, and
mxGraph cell styles come only from renderer-controlled values. Public render
functions fail open: a broken diagram becomes a report placeholder and missing
portable artifacts disable their corresponding download controls.
"""

from __future__ import annotations

import html
import logging
import textwrap
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple
from xml.etree import ElementTree as ET

from ..models import ContactFlowGraph, FlowAction
from .view_model import (
    JourneyEdge,
    JourneyNode,
    JourneyViewModel,
    build_journey_view_model,
)

logger = logging.getLogger("journey.renderer")

# Absolute cap. Beyond this, we render a placeholder note instead —
# even a static grid layout gets unreadable at this size.
_HARD_CAP = 150

# Categories drive both label style and node color.
#
#   speaks     — the caller hears something
#   chooses    — the caller makes an input
#   waits      — the caller is holding for someone
#   terminal   — the interaction ends
#   processing — anything invisible to the caller (system work)

_CATEGORY_BY_TYPE: Dict[str, str] = {
    "MessageParticipant": "speaks",
    "PlayPrompt": "speaks",
    "MessageParticipantByText": "speaks",
    "GetUserInput": "chooses",
    "GetParticipantInput": "chooses",
    "StoreUserInput": "chooses",
    "StoreCustomerInput": "chooses",
    "ConnectToLexBot": "chooses",
    "ConnectParticipantWithLexBot": "chooses",
    "TransferToQueue": "waits",
    "TransferContactToQueue": "waits",
    "CreateCallback": "waits",
    "SetCallbackNumber": "waits",
    "Wait": "waits",
    "DisconnectParticipant": "terminal",
    "EndFlowExecution": "terminal",
    "TransferParticipantToThirdParty": "terminal",
    "TransferContactToPhoneNumber": "terminal",
    "TransferToPhoneNumber": "terminal",
    "TransferToFlow": "terminal",
    "TransferContactToFlow": "terminal",
}

# Generic labels used when the parameters don't carry anything more
# informative (empty prompts, missing ARNs, etc). Kept in sync with the
# existing test suite's expectations.
_GENERIC_LABEL: Dict[str, str] = {
    "MessageParticipant": "Plays a message",
    "PlayPrompt": "Plays a prompt",
    "MessageParticipantByText": "Sends a text message",
    "GetUserInput": "Asks caller to choose",
    "GetParticipantInput": "Asks caller to choose",
    "StoreUserInput": "Captures caller input",
    "StoreCustomerInput": "Captures caller input",
    "ConnectToLexBot": "Talks to a Lex bot",
    "ConnectParticipantWithLexBot": "Talks to a Lex bot",
    "TransferToQueue": "Waits for an agent",
    "TransferContactToQueue": "Waits for an agent",
    "CreateCallback": "Offered a callback",
    "SetCallbackNumber": "Callback registered",
    "Wait": "Waits",
    "DisconnectParticipant": "Call ends",
    "EndFlowExecution": "Flow ends",
    "TransferParticipantToThirdParty": "Transferred externally",
    "TransferContactToPhoneNumber": "Transferred externally",
    "TransferToPhoneNumber": "Transferred externally",
    "TransferToFlow": "Handed to another flow",
    "TransferContactToFlow": "Handed to another flow",
}

# Cap the visible characters in a node label. Rich prompt text can be
# long; keeping it modest keeps cards a fixed, predictable size.
_LABEL_MAX_CHARS = 60

# Cap the visible characters in an edge (branch condition) label.
_EDGE_LABEL_MAX_CHARS = 24

# What each customer-experience category means — surfaced in every node's
# hover tooltip so a reader doesn't have to guess what "PROCESSING" or
# "WAITS" implies about the caller's experience at that step.
_CATEGORY_EXPLANATION: Dict[str, str] = {
    "speaks": "The caller hears something (a prompt, message, or announcement).",
    "chooses": "The caller provides input — a key press, spoken response, or conversation.",
    "waits": "The caller is placed on hold, queued, or offered a callback.",
    "terminal": "The interaction ends here — disconnect, transfer, or handoff to another flow.",
    "processing": (
        "Invisible to the caller — internal system work such as a data "
        "lookup, setting an attribute, or branching logic."
    ),
}

# Plain-English explanations for branch-condition/error names that are
# not something this tool invented — they're Amazon Connect's own
# built-in identifiers, defined by AWS for the action types that can
# produce them. Verified against the AWS documentation page for each
# action type (see the URLs in the confluence of docs.aws.amazon.com/
# connect/latest/devguide/ for GetParticipantInput, CheckMetricData,
# Transfer to queue, and Grant Connect Customer access to your AWS
# Lambda functions). A condition not in this dict still gets a
# tooltip — a generic explanation of what an error/condition branch
# means structurally — rather than nothing, since an unlabeled hover
# is no better than the bare text the reader is already looking at.
_CONDITION_EXPLANATIONS: Dict[str, str] = {
    "NoMatchingError": (
        "A configured catch-all route used only if this action fails and no "
        "specific error condition matches. This is a flow rule and does not "
        "mean an error was observed."
    ),
    "NoMatchingCondition": (
        "Amazon Connect's built-in catch-all for this action's "
        "conditional branches: taken when the caller's response (a key "
        "press, spoken input, or an attribute's value) doesn't match "
        "any of the specific conditions configured on this action."
    ),
    "InvalidPhoneNumber": (
        "Taken when the input captured from the caller doesn't pass "
        "Amazon Connect's phone-number format validation."
    ),
    "InputTimeLimitExceeded": (
        "Taken when the caller doesn't respond before this action's configured time limit runs out."
    ),
    "QueueAtCapacity": (
        "Taken when the destination queue has already reached its "
        "maximum contacts-in-queue limit, so Amazon Connect routes the "
        "contact down this branch instead of adding it to the queue."
    ),
    "ContactNotLinked": (
        "Taken when the contact could not be linked to the case that "
        "was just created or retrieved — a partial success/failure "
        "from the case action."
    ),
}

_DEFAULT_ERROR_EXPLANATION = (
    "An error branch defined on this action. The exact conditions that "
    "trigger it are specific to this action type — see the AWS "
    "documentation for it."
)
_DEFAULT_CONDITION_EXPLANATION = (
    "A branch defined on this action for a specific caller response "
    "(a key press, a recognized value, or an attribute comparison) — "
    "this is the exact label the flow's author gave that branch."
)

# Minimum vertical pixel gap enforced between two edge-label pills that
# would otherwise render at (near) the same x — see _stack_edge_labels.
# A rendered pill is roughly 18-19px tall (0.7rem text + 0.1rem
# top/bottom padding + a 1px border); 20 comfortably clears that.
_EDGE_LABEL_MIN_GAP = 20

# Two label requests within this many pixels of each other on the x
# axis are treated as "the same column" for stacking purposes. Forward
# edges crossing between the same pair of layers land at the exact
# same mid_x (x is a function of layer, not of the individual node),
# so this only exists as a float-safety margin, not because real
# columns are ever actually 8px apart.
_EDGE_LABEL_X_BUCKET = 8

# ---------------------------------------------------------------------------
# Layout geometry — every dimension below is a plain pixel value used to
# compute node positions and connector bend points. Nothing here is ever
# derived from flow content.
# ---------------------------------------------------------------------------

_NODE_W = 210
_NODE_H = 72
_COL_GAP = 60
_ROW_GAP = 60
_MARGIN = 24
_LANE_GAP = 26
_LANE_START_GAP = 24
_ARROW_LEN = 8
_ARROW_HALF_WIDTH = 5

_COL_PITCH = _NODE_W + _COL_GAP
_ROW_PITCH = _NODE_H + _ROW_GAP


# ---------------------------------------------------------------------------
# Shared layout — computed once, consumed by both output formats
# ---------------------------------------------------------------------------
#
# _compute_layout() is the single source of truth for "where does
# everything go": which actions are visible, what column/row each
# lands in, and which edges are forward vs. back. flow_to_diagram_html
# (HTML cards + inline SVG connectors, for the live report) and
# flow_to_svg_export (one self-contained <svg> document, for
# download/PNG/draw.io) both build on top of the same _Layout so the
# two artifacts are always the same diagram, never two independently-
# computed near-matches that can drift apart.


@dataclass(frozen=True)
class JourneyDiagramArtifacts:
    """All portable artifacts generated from one accepted journey layout."""

    diagram_html: str
    diagram_model: Dict[str, Any]
    svg_markup: Optional[str] = None
    svg_width: Optional[int] = None
    svg_height: Optional[int] = None
    drawio_xml: Optional[str] = None

    def export_payload(self) -> Dict[str, Any]:
        """Return the versioned browser-download payload for this diagram."""
        formats: Dict[str, Dict[str, Any]] = {}
        if self.svg_markup and self.svg_width and self.svg_height:
            formats["svg"] = {
                "content": self.svg_markup,
                "media_type": "image/svg+xml;charset=utf-8",
                "width": self.svg_width,
                "height": self.svg_height,
            }
        if self.drawio_xml:
            formats["drawio"] = {
                "content": self.drawio_xml,
                "media_type": "application/vnd.jgraph.mxfile;charset=utf-8",
            }
        return {"schema_version": 1, "formats": formats}


@dataclass
class _Layout:
    """Fully resolved layout for the caller-focused journey projection."""

    model: JourneyViewModel
    visible: Dict[str, JourneyNode]
    positions: Dict[str, Tuple[int, int]]
    ranks: Dict[str, int]
    lanes: Dict[str, int]
    forward_edges: List[JourneyEdge]
    back_edges: List[JourneyEdge]
    simplified: bool
    hidden_count: int


def _compute_layout(graph: ContactFlowGraph) -> _Layout:
    """Project the raw action graph, then assign compact left-to-right lanes."""
    context_by_action = _effective_action_context(graph)
    model = build_journey_view_model(
        graph,
        _customer_experience_label,
        lambda action: _customer_experience_scope(
            action,
            context_by_action.get(action.action_id, {}),
        ),
        _ai_agent_details,
    )
    forward_edges, back_edges = _split_feedback_edges(model)
    ranks = _assign_longest_path_ranks(model.nodes, forward_edges)
    lanes = _assign_branch_lanes(model, forward_edges, ranks)

    min_lane = min(lanes.values(), default=0)
    positions = {
        key: (
            _MARGIN + ranks.get(key, 0) * _COL_PITCH,
            _MARGIN + (lanes.get(key, 0) - min_lane) * _ROW_PITCH,
        )
        for key in model.nodes
    }
    hidden_count = max(0, model.original_action_count - len(model.nodes))
    return _Layout(
        model=model,
        visible=model.nodes,
        positions=positions,
        ranks=ranks,
        lanes=lanes,
        forward_edges=forward_edges,
        back_edges=back_edges,
        simplified=hidden_count > 0,
        hidden_count=hidden_count,
    )


def _split_feedback_edges(model: JourneyViewModel) -> Tuple[List[JourneyEdge], List[JourneyEdge]]:
    """Build a maximal acyclic edge set; only true loops become feedback routes."""
    route_order = {"normal": 0, "fallback": 1, "exception": 2}
    ordered = sorted(
        model.edges,
        key=lambda edge: (
            not edge.is_primary,
            route_order.get(edge.route_type, 3),
            edge.key,
        ),
    )
    accepted: List[JourneyEdge] = []
    feedback: List[JourneyEdge] = []
    adjacency: Dict[str, List[str]] = {}
    for edge in ordered:
        if _path_exists(adjacency, edge.target, edge.source):
            edge.is_feedback = True
            feedback.append(edge)
            continue
        accepted.append(edge)
        adjacency.setdefault(edge.source, []).append(edge.target)
    accepted.sort(key=lambda edge: _edge_key_index(edge.key))
    feedback.sort(key=lambda edge: _edge_key_index(edge.key))
    return accepted, feedback


def _path_exists(adjacency: Dict[str, List[str]], start: str, target: str) -> bool:
    if start == target:
        return True
    seen = {start}
    stack = [start]
    while stack:
        current = stack.pop()
        for neighbor in adjacency.get(current, []):
            if neighbor == target:
                return True
            if neighbor not in seen:
                seen.add(neighbor)
                stack.append(neighbor)
    return False


def _assign_longest_path_ranks(
    nodes: Dict[str, JourneyNode], edges: List[JourneyEdge]
) -> Dict[str, int]:
    """Assign the smallest ranks that make every non-feedback edge point right."""
    outgoing: Dict[str, List[JourneyEdge]] = {}
    indegree = {key: 0 for key in nodes}
    for edge in edges:
        outgoing.setdefault(edge.source, []).append(edge)
        indegree[edge.target] = indegree.get(edge.target, 0) + 1

    ready = sorted((key for key, degree in indegree.items() if degree == 0), key=_node_key_index)
    ranks = {key: 0 for key in nodes}
    head = 0
    while head < len(ready):
        current = ready[head]
        head += 1
        for edge in sorted(outgoing.get(current, []), key=lambda item: _edge_key_index(item.key)):
            ranks[edge.target] = max(ranks.get(edge.target, 0), ranks[current] + 1)
            indegree[edge.target] -= 1
            if indegree[edge.target] == 0:
                ready.append(edge.target)
    return ranks


def _assign_branch_lanes(
    model: JourneyViewModel,
    edges: List[JourneyEdge],
    ranks: Dict[str, int],
) -> Dict[str, int]:
    """Keep the primary route centered, normal alternatives above, errors below."""
    primary = set(model.primary_path)
    lanes: Dict[str, int] = {key: 0 for key in primary}
    occupied = {(ranks.get(key, 0), 0) for key in primary}
    incoming: Dict[str, List[JourneyEdge]] = {}
    for edge in edges:
        incoming.setdefault(edge.target, []).append(edge)

    ordered_nodes = sorted(model.nodes, key=lambda key: (ranks.get(key, 0), _node_key_index(key)))
    for key in ordered_nodes:
        if key in lanes:
            continue
        candidates = sorted(
            incoming.get(key, []),
            key=lambda edge: (
                edge.source not in lanes,
                {"normal": 0, "fallback": 1, "exception": 2}.get(edge.route_type, 3),
                _edge_key_index(edge.key),
            ),
        )
        selected = next((edge for edge in candidates if edge.source in lanes), None)
        if selected is None:
            preferred = 1
        else:
            source_lane = lanes[selected.source]
            if selected.route_type == "normal":
                preferred = source_lane if source_lane != 0 else -1
            else:
                preferred = source_lane if source_lane > 0 else 1

        direction = -1 if preferred < 0 else 1
        lane = preferred
        rank = ranks.get(key, 0)
        while (rank, lane) in occupied or lane == 0:
            lane += direction
        lanes[key] = lane
        occupied.add((rank, lane))
    return lanes


def _node_key_index(key: str) -> int:
    return int(key[1:]) if len(key) > 1 and key[1:].isdigit() else 10**9


def _edge_key_index(key: str) -> int:
    return int(key[1:]) if len(key) > 1 and key[1:].isdigit() else 10**9


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def flow_to_diagram_html(graph: ContactFlowGraph) -> str:
    """
    Render a contact flow as a static, server-rendered HTML/SVG diagram.

    Returns a self-contained ``<div class="jm-canvas">…</div>`` with
    fixed pixel dimensions: absolutely-positioned cards for each visible
    action, and an overlaid SVG drawing every connector as a sequence of
    horizontal/vertical segments only. No JavaScript library is
    involved in producing or laying out the result — the browser only
    paints markup that already carries its final coordinates.

    Never raises: any error during layout or rendering degrades to a
    placeholder ``<div>`` carrying the failure message.
    """
    return flow_to_diagram_payload(graph)[0]


def flow_to_diagram_payload(graph: ContactFlowGraph) -> Tuple[str, Dict[str, Any]]:
    """Return the rendered diagram and its redacted inspector model."""
    artifacts = flow_to_diagram_artifacts(graph)
    return artifacts.diagram_html, artifacts.diagram_model


def flow_to_diagram_artifacts(graph: ContactFlowGraph) -> JourneyDiagramArtifacts:
    """Generate every report/download artifact from one projected layout."""
    empty_model: Dict[str, Any] = {"nodes": {}, "edges": {}, "primary_path": []}
    try:
        if graph.action_count == 0 or graph.action_count > _HARD_CAP:
            return JourneyDiagramArtifacts(_render(graph), empty_model)
        layout = _compute_layout(graph)
        diagram_html = _render(graph, layout)
        diagram_model = layout.model.to_dict()
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "Failed to render flow %s (%s) as a diagram: %s",
            graph.flow_id,
            graph.flow_name,
            e,
        )
        placeholder = _placeholder_html(
            f"Diagram unavailable for flow '{html.escape(graph.flow_name or graph.flow_id or 'flow')}' (render error)."  # noqa: E501
        )
        return JourneyDiagramArtifacts(placeholder, empty_model)

    svg_markup: Optional[str] = None
    svg_width: Optional[int] = None
    svg_height: Optional[int] = None
    try:
        svg_export = _render_svg_export(graph, layout)
        if svg_export:
            svg_markup, svg_width, svg_height = svg_export
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "Failed to render flow %s (%s) as an SVG export: %s",
            graph.flow_id,
            graph.flow_name,
            e,
        )

    drawio_xml: Optional[str] = None
    try:
        drawio_xml = _render_drawio_export(graph, layout)
    except Exception as e:  # noqa: BLE001
        logger.warning(
            "Failed to render flow %s (%s) as a draw.io export: %s",
            graph.flow_id,
            graph.flow_name,
            e,
        )

    return JourneyDiagramArtifacts(
        diagram_html=diagram_html,
        diagram_model=diagram_model,
        svg_markup=svg_markup,
        svg_width=svg_width,
        svg_height=svg_height,
        drawio_xml=drawio_xml,
    )


def flow_to_svg_export(graph: ContactFlowGraph) -> Optional[Tuple[str, int, int]]:
    """Return a self-contained SVG generated from the accepted journey layout."""
    artifacts = flow_to_diagram_artifacts(graph)
    if not artifacts.svg_markup or not artifacts.svg_width or not artifacts.svg_height:
        return None
    return artifacts.svg_markup, artifacts.svg_width, artifacts.svg_height


def flow_to_drawio_export(graph: ContactFlowGraph) -> Optional[str]:
    """Return native editable mxGraph XML generated from the journey layout."""
    return flow_to_diagram_artifacts(graph).drawio_xml


# ---------------------------------------------------------------------------
# Top-level render — HTML/SVG hybrid (flow_to_diagram_html)
# ---------------------------------------------------------------------------


def _render(graph: ContactFlowGraph, layout: Optional[_Layout] = None) -> str:
    total_actions = graph.action_count

    if total_actions == 0:
        flow_label = html.escape(graph.flow_name or graph.flow_id or "flow")
        return _placeholder_html(f"Flow <em>{flow_label}</em> has no actions to display.")

    if total_actions > _HARD_CAP:
        flow_label = html.escape(graph.flow_name or graph.flow_id or "flow")
        return _placeholder_html(
            f"Flow <em>{flow_label}</em> has {total_actions} actions — "
            "too complex to render as a legible diagram. "
            "Consider splitting into flow modules."
        )

    layout = layout or _compute_layout(graph)
    connector_paths, label_placements, canvas_w, canvas_h = _build_connectors(
        layout.positions, layout.forward_edges, layout.back_edges
    )
    connectors_svg = (
        f'<svg class="jm-connectors" width="{canvas_w}" height="{canvas_h}" '
        f'viewBox="0 0 {canvas_w} {canvas_h}" aria-hidden="true">'
        + connector_paths
        + "</svg>"
        + "".join(_edge_label_html(placement) for placement in label_placements)
    )

    nodes_html = []
    for node_key, node in layout.visible.items():
        x, y = layout.positions[node_key]
        nodes_html.append(_render_node(x, y, node))

    parts = [
        '<p class="jm-primary-note">Main caller route is centered. '
        "Alternatives appear above it; fallback and technical routes appear below.</p>",
        f'<div class="jm-canvas" style="width:{canvas_w}px;height:{canvas_h}px;">',
        connectors_svg,
        "".join(nodes_html),
        "</div>",
    ]

    if layout.simplified:
        grouped_actions = sum(
            len(node.actions) for node in layout.visible.values() if len(node.actions) > 1
        )
        group_count = sum(1 for node in layout.visible.values() if len(node.actions) > 1)
        parts.append(
            f'<p class="jm-hidden-note">{grouped_actions} internal action(s) consolidated into '
            f"{group_count} inspectable system-work step(s).</p>"
        )

    return "".join(parts)


@dataclass
class _EdgeLabelPlacement:
    x: float
    y: float
    edge: JourneyEdge


def _build_connectors(
    positions: Dict[str, Tuple[int, int]],
    forward_edges: List[JourneyEdge],
    back_edges: List[JourneyEdge],
) -> Tuple[str, List[_EdgeLabelPlacement], int, int]:
    """Route projected edges through reserved inter-column tracks."""
    if not positions:
        return "", [], _MARGIN * 2, _MARGIN * 2

    max_x = max(x + _NODE_W for x, _y in positions.values())
    max_y = max(y + _NODE_H for _x, y in positions.values())
    segments: List[str] = []
    label_requests: List[_EdgeLabelPlacement] = []
    gutter_use: Dict[Tuple[int, int], int] = {}

    for edge in forward_edges:
        sx, sy = positions[edge.source]
        tx, ty = positions[edge.target]
        start_x, start_y = sx + _NODE_W, sy + _NODE_H / 2
        end_x, end_y = tx, ty + _NODE_H / 2
        gutter = (int(start_x), int(end_x))
        track_index = gutter_use.get(gutter, 0)
        gutter_use[gutter] = track_index + 1
        track_x = start_x + (end_x - start_x) / 2 + track_index * 8
        path_class, head_class = _connector_classes(edge)
        if start_y == end_y:
            path = f"M {start_x} {start_y} H {end_x}"
            # Same-lane labels live in the reserved band above the
            # cards, not on top of the connector/card text.
            label_y = sy
        else:
            path = f"M {start_x} {start_y} H {track_x} V {end_y} H {end_x}"
            label_y = ty
        segments.append(f'<path class="{path_class}" d="{path}" />')
        segments.append(_arrow_triangle(end_x, end_y, "right", head_class))
        label_requests.append(_EdgeLabelPlacement(track_x, label_y, edge))

    loop_bottom = max_y
    for loop_index, edge in enumerate(back_edges):
        sx, sy = positions[edge.source]
        tx, ty = positions[edge.target]
        path_class, head_class = _connector_classes(edge, is_back=True)
        rank_span = abs(int((sx - tx) / _COL_PITCH))
        if rank_span > 3:
            source_x = sx + _NODE_W
            source_y = sy + _NODE_H / 2
            target_x = tx
            target_y = ty + _NODE_H / 2
            segments.append(
                f'<path class="{path_class} jm-connector-jump" '
                f'd="M {source_x} {source_y} H {source_x + 28}" />'
            )
            segments.append(
                f'<path class="{path_class} jm-connector-jump" '
                f'd="M {target_x - 28} {target_y} H {target_x}" />'
            )
            segments.append(_arrow_triangle(target_x, target_y, "right", head_class))
            label_requests.append(_EdgeLabelPlacement(source_x + 54, source_y, edge))
            continue

        start_x, start_y = sx + _NODE_W / 2, sy + _NODE_H
        end_x, end_y = tx + _NODE_W / 2, ty + _NODE_H
        loop_y = max(sy, ty) + _NODE_H + _LANE_START_GAP + loop_index * _LANE_GAP
        loop_bottom = max(loop_bottom, loop_y)
        segments.append(
            f'<path class="{path_class}" '
            f'd="M {start_x} {start_y} V {loop_y} H {end_x} V {end_y}" />'
        )
        segments.append(_arrow_triangle(end_x, end_y, "up", head_class))
        label_requests.append(_EdgeLabelPlacement((start_x + end_x) / 2, loop_y, edge))

    stacked_labels = _stack_edge_labels(label_requests)
    canvas_w = max_x + _MARGIN
    canvas_h = max(max_y, loop_bottom) + _MARGIN
    if stacked_labels:
        canvas_h = max(canvas_h, max(item.y for item in stacked_labels) + _MARGIN)
    return "".join(segments), stacked_labels, canvas_w, canvas_h


def _connector_classes(edge: JourneyEdge, is_back: bool = False) -> Tuple[str, str]:
    if edge.route_type == "exception":
        base = "jm-connector-error"
    elif edge.route_type == "fallback":
        base = "jm-connector-fallback"
    else:
        base = "jm-connector"
    classes = [base]
    if is_back:
        classes.append("jm-connector-back")
    head_classes = [f"{base}-head"]
    if edge.is_primary:
        classes.append("jm-connector-primary")
        head_classes.append("jm-connector-primary-head")
    return " ".join(classes), " ".join(head_classes)


def _stack_edge_labels(requests: List[_EdgeLabelPlacement]) -> List[_EdgeLabelPlacement]:
    """Separate labels that share a connector track and would overlap."""
    if not requests:
        return []
    groups: Dict[int, List[int]] = {}
    for index, item in enumerate(requests):
        groups.setdefault(round(item.x / _EDGE_LABEL_X_BUCKET), []).append(index)

    adjusted = [_EdgeLabelPlacement(item.x, item.y, item.edge) for item in requests]
    for indices in groups.values():
        indices.sort(key=lambda index: requests[index].y)
        last_y: Optional[float] = None
        for index in indices:
            item = adjusted[index]
            if last_y is not None and item.y - last_y < _EDGE_LABEL_MIN_GAP:
                item.y = last_y + _EDGE_LABEL_MIN_GAP
            last_y = item.y
    return adjusted


def _arrow_triangle(tip_x: float, tip_y: float, direction: str, css_class: str) -> str:
    """Return a small filled SVG arrowhead at ``(tip_x, tip_y)``."""
    if direction == "right":
        p1 = (tip_x - _ARROW_LEN, tip_y - _ARROW_HALF_WIDTH)
        p2 = (tip_x - _ARROW_LEN, tip_y + _ARROW_HALF_WIDTH)
    elif direction == "up":
        p1 = (tip_x - _ARROW_HALF_WIDTH, tip_y + _ARROW_LEN)
        p2 = (tip_x + _ARROW_HALF_WIDTH, tip_y + _ARROW_LEN)
    else:
        p1 = (tip_x - _ARROW_HALF_WIDTH, tip_y - _ARROW_LEN)
        p2 = (tip_x + _ARROW_HALF_WIDTH, tip_y - _ARROW_LEN)
    return (
        f'<path class="{css_class}" d="M {tip_x} {tip_y} L {p1[0]} {p1[1]} L {p2[0]} {p2[1]} Z" />'
    )


def _edge_label_html(placement: _EdgeLabelPlacement) -> str:
    """Return a keyboard-accessible route control anchored to a connector."""
    edge = placement.edge
    raw_label = edge.label or "Continue"
    visible_label = "›" if raw_label == "Continue" else _truncate(raw_label, _EDGE_LABEL_MAX_CHARS)
    text = html.escape(visible_label)
    estimated_width = 24 if visible_label == "›" else max(54, len(visible_label) * 7 + 16)
    left = max(0, placement.x - estimated_width / 2)
    top = max(0, placement.y - 24)
    first_outcome = edge.outcomes[0]
    tooltip = _edge_label_tooltip(
        first_outcome.raw_label,
        first_outcome.transition_type,
    )
    route_class = f" jm-edge-{edge.route_type}"
    primary_class = " jm-edge-primary" if edge.is_primary else ""
    aria_label = html.escape(f"Inspect route: {raw_label}", quote=True)
    return (
        f'<button type="button" class="jm-edge-label{route_class}{primary_class}" '
        f'style="left:{left}px;top:{top}px;" data-jm-edge-key="{edge.key}" '
        f'aria-label="{aria_label}" aria-pressed="false" title="{tooltip}">{text}</button>'
    )


def _edge_label_tooltip(raw_label: str, kind: str) -> str:
    """Build a plain-text hover explanation without exposing raw route values.

    Known Amazon Connect branch identifiers get a specific reader-facing
    explanation. Unknown and structured predicates get only a generic route
    explanation; their raw values remain available exclusively in the
    inspector model.
    """
    if kind == "error":
        explanation = _CONDITION_EXPLANATIONS.get(raw_label, _DEFAULT_ERROR_EXPLANATION)
    elif kind == "condition":
        explanation = _CONDITION_EXPLANATIONS.get(raw_label, _DEFAULT_CONDITION_EXPLANATION)
    else:
        explanation = "The condition under which this transition is taken."
    return html.escape(explanation, quote=True)


# ---------------------------------------------------------------------------
# Standalone SVG export — every element drawn as an SVG shape, so the
# result is one portable image file rather than an HTML/SVG hybrid that
# only means anything inside the report's own page. Colors below are
# the same hex values journey_map.css assigns each category, so the
# exported image matches what the report shows.
# ---------------------------------------------------------------------------

# (fill, left-border stroke, text color) per category — mirrors
# .jm-node-{category} in journey_map.css exactly, so the export looks
# like the live diagram rather than a re-skinned approximation.
_SVG_CATEGORY_COLORS: Dict[str, Tuple[str, str, str]] = {
    "speaks": ("#d4edda", "#28a745", "#155724"),
    "chooses": ("#d1ecf1", "#17a2b8", "#0c5460"),
    "waits": ("#fff3cd", "#ffc107", "#856404"),
    "terminal": ("#f8d7da", "#dc3545", "#721c24"),
    "processing": ("#f8f9fa", "#adb5bd", "#6c757d"),
}
_SVG_ENTRY_OUTLINE = "#ff9900"
_SVG_CONNECTOR_STROKE = "#adb5bd"
_SVG_CONNECTOR_ERROR_STROKE = "#dc3545"
_SVG_LABEL_BG = "#ffffff"
_SVG_LABEL_BORDER = "#dee2e6"
_SVG_LABEL_TEXT = "#495057"

# _build_connectors() produces connector <path> markup carrying the
# same CSS classes flow_to_diagram_html relies on the report's own
# journey_map.css to style (jm-connector, jm-connector-error,
# jm-connector-head, ...). A standalone SVG document has no such
# stylesheet attached, so this embeds the exact equivalent rules
# inline via a <style> element — SVG supports scoped CSS the same way
# HTML does — rather than duplicating _build_connectors just to emit
# `stroke=`/`fill=` attributes directly. Colors are the same hex
# values as journey_map.css's `.jm-connector*` rules.
_SVG_CONNECTOR_STYLE = (
    "<style>"
    f".jm-connector,.jm-connector-back{{fill:none;stroke:{_SVG_CONNECTOR_STROKE};stroke-width:1.75;}}"  # noqa: E501
    f".jm-connector-head,.jm-connector-back-head{{fill:{_SVG_CONNECTOR_STROKE};stroke:none;}}"
    f".jm-connector-fallback,.jm-connector-fallback.jm-connector-back{{fill:none;stroke:#d97706;stroke-width:1.75;stroke-dasharray:3 4;}}"
    f".jm-connector-fallback-head{{fill:#d97706;stroke:none;}}"
    f".jm-connector-error,.jm-connector-error.jm-connector-back{{fill:none;stroke:{_SVG_CONNECTOR_ERROR_STROKE};stroke-width:1.75;stroke-dasharray:5 4;}}"  # noqa: E501
    f".jm-connector-error-head,.jm-connector-error.jm-connector-back-head{{fill:{_SVG_CONNECTOR_ERROR_STROKE};}}"  # noqa: E501
    "</style>"
)

# Node interior padding + line height, in pixels — matches the HTML
# card's 0.5rem/0.75rem CSS padding (at a 16px root font size) closely
# enough that the exported image's text placement doesn't look
# cramped or overflow the card compared to the live diagram.
_SVG_NODE_PAD_X = 12
_SVG_NODE_PAD_Y = 12
_SVG_CATEGORY_FONT_SIZE = 10
_SVG_LABEL_FONT_SIZE = 13
_SVG_LABEL_LINE_HEIGHT = 16
# Rough average character width at _SVG_LABEL_FONT_SIZE for a
# proportional sans-serif font — used only to decide where to wrap a
# label across multiple <text> lines within a node's fixed width.
# SVG has no server-side text-measurement API to do this exactly
# without a real font metrics table, so this is an estimate; being
# slightly conservative (wrapping a little early) is preferable to
# overflowing the card.
_SVG_AVG_CHAR_WIDTH = 6.5


def _render_svg_export(
    graph: ContactFlowGraph, layout: Optional[_Layout] = None
) -> Optional[Tuple[str, int, int]]:
    """Build the standalone SVG document for ``graph``."""
    total_actions = graph.action_count
    if total_actions == 0 or total_actions > _HARD_CAP:
        return None

    layout = layout or _compute_layout(graph)
    if not layout.visible:
        return None

    connector_paths, label_placements, canvas_w, canvas_h = _build_connectors(
        layout.positions, layout.forward_edges, layout.back_edges
    )

    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{canvas_w}" height="{canvas_h}" '
        f'viewBox="0 0 {canvas_w} {canvas_h}" font-family="Arial, Helvetica, sans-serif">',
        _SVG_CONNECTOR_STYLE,
        f'<rect x="0" y="0" width="{canvas_w}" height="{canvas_h}" fill="#ffffff" />',
        connector_paths,
    ]
    for placement in label_placements:
        if placement.edge.label != "Continue":
            parts.append(_svg_edge_label(placement.x, placement.y, placement.edge.label))
    for node_key, node in layout.visible.items():
        x, y = layout.positions[node_key]
        parts.append(_svg_node(x, y, node.category, node.label, node.is_entry))
    parts.append("</svg>")

    return "".join(parts), canvas_w, canvas_h


def _render_drawio_export(graph: ContactFlowGraph, layout: _Layout) -> Optional[str]:
    """Build an uncompressed draw.io document with editable native cells."""
    if not layout.visible:
        return None

    _paths, _labels, canvas_w, canvas_h = _build_connectors(
        layout.positions, layout.forward_edges, layout.back_edges
    )
    mxfile = ET.Element(
        "mxfile",
        {
            "host": "app.diagrams.net",
            "type": "device",
            "compressed": "false",
        },
    )
    diagram_name = "Caller Journey"
    if graph.flow_name:
        diagram_name += f" - {_xml_text(graph.flow_name)}"
    diagram = ET.SubElement(mxfile, "diagram", {"id": "caller-journey", "name": diagram_name})
    model = ET.SubElement(
        diagram,
        "mxGraphModel",
        {
            "dx": str(canvas_w),
            "dy": str(canvas_h),
            "grid": "1",
            "gridSize": "10",
            "guides": "1",
            "tooltips": "1",
            "connect": "1",
            "arrows": "1",
            "fold": "1",
            "page": "0",
            "pageScale": "1",
            "math": "0",
            "shadow": "0",
        },
    )
    root = ET.SubElement(model, "root")
    ET.SubElement(root, "mxCell", {"id": "0"})
    ET.SubElement(root, "mxCell", {"id": "1", "parent": "0"})

    for key, node in layout.visible.items():
        x, y = layout.positions[key]
        cell = ET.SubElement(
            root,
            "mxCell",
            {
                "id": f"node-{key}",
                "value": _xml_text(node.label),
                "style": _drawio_node_style(node),
                "vertex": "1",
                "parent": "1",
            },
        )
        ET.SubElement(
            cell,
            "mxGeometry",
            {
                "x": str(x),
                "y": str(y),
                "width": str(_NODE_W),
                "height": str(_NODE_H),
                "as": "geometry",
            },
        )

    edge_points = _drawio_edge_points(layout)
    for edge in [*layout.forward_edges, *layout.back_edges]:
        value = "" if edge.label == "Continue" else _truncate(edge.label, _EDGE_LABEL_MAX_CHARS)
        cell = ET.SubElement(
            root,
            "mxCell",
            {
                "id": f"edge-{edge.key}",
                "value": _xml_text(value),
                "style": _drawio_edge_style(edge),
                "edge": "1",
                "parent": "1",
                "source": f"node-{edge.source}",
                "target": f"node-{edge.target}",
            },
        )
        geometry = ET.SubElement(cell, "mxGeometry", {"relative": "1", "as": "geometry"})
        points = edge_points.get(edge.key, [])
        if points:
            array = ET.SubElement(geometry, "Array", {"as": "points"})
            for x, y in points:
                ET.SubElement(array, "mxPoint", {"x": f"{x:g}", "y": f"{y:g}"})

    return ET.tostring(mxfile, encoding="unicode", short_empty_elements=True)


def _drawio_edge_points(layout: _Layout) -> Dict[str, List[Tuple[float, float]]]:
    """Return orthogonal waypoints matching the accepted projected lanes."""
    points: Dict[str, List[Tuple[float, float]]] = {}
    gutter_use: Dict[Tuple[int, int], int] = {}
    for edge in layout.forward_edges:
        sx, sy = layout.positions[edge.source]
        tx, ty = layout.positions[edge.target]
        start_x, start_y = sx + _NODE_W, sy + _NODE_H / 2
        end_x, end_y = tx, ty + _NODE_H / 2
        if start_y == end_y:
            points[edge.key] = []
            continue
        gutter = (int(start_x), int(end_x))
        track_index = gutter_use.get(gutter, 0)
        gutter_use[gutter] = track_index + 1
        track_x = start_x + (end_x - start_x) / 2 + track_index * 8
        points[edge.key] = [(track_x, start_y), (track_x, end_y)]

    max_y = max(y + _NODE_H for _x, y in layout.positions.values())
    for loop_index, edge in enumerate(layout.back_edges):
        sx, sy = layout.positions[edge.source]
        tx, ty = layout.positions[edge.target]
        start_x = sx + _NODE_W / 2
        end_x = tx + _NODE_W / 2
        loop_y = max(max_y, sy + _NODE_H, ty + _NODE_H) + _LANE_START_GAP
        loop_y += loop_index * _LANE_GAP
        points[edge.key] = [(start_x, loop_y), (end_x, loop_y)]
    return points


def _drawio_node_style(node: JourneyNode) -> str:
    fill, stroke, text_color = _SVG_CATEGORY_COLORS.get(
        node.category, _SVG_CATEGORY_COLORS["processing"]
    )
    outline = _SVG_ENTRY_OUTLINE if node.is_entry else stroke
    stroke_width = "2" if node.is_entry else "1"
    return (
        "rounded=1;whiteSpace=wrap;html=0;align=left;verticalAlign=middle;"
        "spacingLeft=12;spacingRight=8;fontSize=13;fontStyle=0;"
        f"fillColor={fill};strokeColor={outline};strokeWidth={stroke_width};"
        f"fontColor={text_color};"
    )


def _drawio_edge_style(edge: JourneyEdge) -> str:
    if edge.route_type == "exception":
        color, dashed, dash_pattern = _SVG_CONNECTOR_ERROR_STROKE, "1", "5 4"
    elif edge.route_type == "fallback":
        color, dashed, dash_pattern = "#d97706", "1", "3 4"
    else:
        color, dashed, dash_pattern = _SVG_CONNECTOR_STROKE, "0", ""
    width = "2" if edge.is_primary else "1.75"
    if edge.is_feedback:
        anchors = "exitX=0.5;exitY=1;entryX=0.5;entryY=1;"
    else:
        anchors = "exitX=1;exitY=0.5;entryX=0;entryY=0.5;"
    return (
        "edgeStyle=orthogonalEdgeStyle;rounded=0;orthogonalLoop=1;jettySize=auto;"
        "html=0;endArrow=block;endFill=1;"
        f"{anchors}strokeColor={color};strokeWidth={width};dashed={dashed};"
        f"dashPattern={dash_pattern};"
    )


def _xml_text(value: object) -> str:
    """Strip characters that XML 1.0 cannot represent."""
    text = str(value)
    return "".join(
        char
        for char in text
        if char in "\t\n\r"
        or 0x20 <= ord(char) <= 0xD7FF
        or 0xE000 <= ord(char) <= 0xFFFD
        or 0x10000 <= ord(char) <= 0x10FFFF
    )


def _svg_node(x: int, y: int, category: str, label: str, is_entry: bool) -> str:
    """Return one node as an SVG ``<rect>`` + category/label ``<text>``."""
    fill, border_stroke, text_color = _SVG_CATEGORY_COLORS.get(
        category, _SVG_CATEGORY_COLORS["processing"]
    )
    safe_category = html.escape(_xml_text(category.title()))
    lines = _wrap_for_svg(_xml_text(label), _NODE_W - 2 * _SVG_NODE_PAD_X, _SVG_LABEL_FONT_SIZE)

    parts = [
        f'<rect x="{x}" y="{y}" width="{_NODE_W}" height="{_NODE_H}" rx="6" ry="6" '
        f'fill="{fill}" stroke="#e9ecef" stroke-width="1" />',
        # Left accent border — a thin filled rect flush with the
        # card's left edge, mirroring the HTML card's border-left.
        f'<rect x="{x}" y="{y}" width="4" height="{_NODE_H}" fill="{border_stroke}" />',
    ]
    if is_entry:
        # Entry-point highlight ring, mirroring .jm-node-entry's
        # box-shadow — drawn as an outer stroked rect since SVG has no
        # box-shadow equivalent.
        parts.append(
            f'<rect x="{x - 2}" y="{y - 2}" width="{_NODE_W + 4}" height="{_NODE_H + 4}" '
            f'rx="8" ry="8" fill="none" stroke="{_SVG_ENTRY_OUTLINE}" stroke-width="2" />'
        )

    text_x = x + _SVG_NODE_PAD_X
    category_y = y + _SVG_NODE_PAD_Y + _SVG_CATEGORY_FONT_SIZE
    parts.append(
        f'<text x="{text_x}" y="{category_y}" font-size="{_SVG_CATEGORY_FONT_SIZE}" '
        f'font-weight="700" letter-spacing="0.5" fill="{text_color}" opacity="0.75">'
        f"{safe_category}</text>"
    )

    label_y = category_y + _SVG_LABEL_LINE_HEIGHT
    for line in lines:
        parts.append(
            f'<text x="{text_x}" y="{label_y}" font-size="{_SVG_LABEL_FONT_SIZE}" '
            f'font-weight="500" fill="{text_color}">{html.escape(line)}</text>'
        )
        label_y += _SVG_LABEL_LINE_HEIGHT

    return "".join(parts)


def _svg_edge_label(x: float, y: float, label: str) -> str:
    """Return an edge-condition label as an SVG background ``<rect>`` + ``<text>``."""
    text = _truncate(_xml_text(label), _EDGE_LABEL_MAX_CHARS)
    safe_text = html.escape(text)
    # Rough pill sizing from character count — same rationale as
    # _SVG_AVG_CHAR_WIDTH: no text-measurement API available server-
    # side, so this estimates a comfortably wide pill rather than
    # measuring exactly. Uses a wider per-character estimate than node
    # labels (7.5 vs. 6.5) because this text is bold (font-weight 600)
    # and therefore measurably wider than the node label's medium-
    # weight (500) text at the same font size.
    pill_w = max(40, len(text) * 7.5 + 16)
    pill_h = 18
    left = x - pill_w / 2
    top = y - 22
    return (
        f'<rect x="{left}" y="{top}" width="{pill_w}" height="{pill_h}" rx="9" ry="9" '
        f'fill="{_SVG_LABEL_BG}" stroke="{_SVG_LABEL_BORDER}" stroke-width="1" />'
        f'<text x="{x}" y="{top + pill_h - 5}" font-size="11" font-weight="600" '
        f'text-anchor="middle" fill="{_SVG_LABEL_TEXT}">{safe_text}</text>'
    )


def _wrap_for_svg(label: str, max_width_px: float, font_size: float) -> List[str]:
    """
    Wrap `label` into lines that fit `max_width_px`, for multi-line SVG
    ``<text>`` (SVG text does not wrap on its own — there is no CSS
    ``word-wrap`` equivalent for a plain ``<text>`` element). Caps at 3
    lines to keep the fixed-height node card from overflowing; a label
    long enough to hit that cap already went through the same
    ``_LABEL_MAX_CHARS`` truncation the HTML renderer applies.
    """
    truncated = _truncate(label, _LABEL_MAX_CHARS)
    avg_char_w = font_size * (_SVG_AVG_CHAR_WIDTH / _SVG_LABEL_FONT_SIZE)
    chars_per_line = max(1, int(max_width_px / avg_char_w))
    lines = textwrap.wrap(truncated, width=chars_per_line) or [""]
    if len(lines) > 3:
        lines = lines[:3]
        lines[-1] = lines[-1].rstrip() + "…"
    return lines


# ---------------------------------------------------------------------------
# Node rendering
# ---------------------------------------------------------------------------


def _render_node(x: int, y: int, node: JourneyNode) -> str:
    entry_class = " jm-node-entry" if node.is_entry else ""
    primary_class = " jm-node-primary" if node.is_primary else ""
    group_class = " jm-node-group" if len(node.actions) > 1 else ""
    truncated_label = _truncate(node.label, _LABEL_MAX_CHARS)
    safe_label = html.escape(truncated_label)
    safe_category = html.escape("System work" if len(node.actions) > 1 else node.category.title())
    tooltip = _node_tooltip(node, truncated_label != node.label)
    aria_label = html.escape(f"Inspect step: {node.label}", quote=True)
    if node.is_primary:
        badge_label = "Includes main-route steps" if len(node.actions) > 1 else "Main route"
        route_badge = f'<span class="jm-node-route">{badge_label}</span>'
    else:
        route_badge = ""
    return (
        f'<button type="button" class="jm-node jm-node-{node.category}{entry_class}'
        f'{primary_class}{group_class}" '
        f'style="left:{x}px;top:{y}px;width:{_NODE_W}px;height:{_NODE_H}px;" '
        f'data-jm-node-key="{node.key}" aria-label="{aria_label}" '
        f'aria-pressed="false" title="{tooltip}">'
        f'<span class="jm-node-category">{safe_category}</span>'
        f'<span class="jm-node-label">{safe_label}</span>'
        f"{route_badge}</button>"
    )


def _node_tooltip(node: JourneyNode, was_truncated: bool) -> str:
    """Build concise reader-facing hover text without Connect implementation metadata."""
    lines: List[str] = []
    if len(node.actions) == 1:
        category_note = _CATEGORY_EXPLANATION.get(node.category, "")
        if category_note:
            lines.append(category_note)
    if node.ai:
        identity = node.ai.get("identity") or "Configured AI agent"
        lines.append(f"AI agent: {identity}")
        context = [node.ai.get("technology", ""), node.ai.get("subtype", "")]
        alias = node.ai.get("alias")
        if alias:
            context.append(f"Alias: {alias}")
        context = [item for item in context if item]
        if context:
            lines.append(" · ".join(context))
    if node.summary:
        lines.append(node.summary)
    if node.scope:
        heading = "What this setup does:" if len(node.actions) > 1 else "What this block does:"
        lines.append(heading)
        lines.extend(f"• {item}" for item in node.scope)
    if was_truncated:
        lines.append(f"Full text: {node.label}")
    return html.escape("\n".join(lines), quote=True)


def _placeholder_html(message: str) -> str:
    """Return a minimal diagram carrying a human-readable message. `message` may
    contain pre-escaped inline HTML (``<em>``) but no user-controlled attributes."""
    return f'<div class="jm-placeholder">{message}</div>'


# ---------------------------------------------------------------------------
# Label extraction — turn action parameters into user-facing labels
# ---------------------------------------------------------------------------


def _customer_experience_label(action: FlowAction) -> Tuple[str, str]:
    """
    Return (category, label) for an action.

    When the action's parameters carry something informative — prompt
    text, Lambda function name, Lex bot, queue reference, phone number —
    the label surfaces that content so the diagram tells the actual
    story of the flow. Falls back to a generic label per category when
    parameters are missing or opaque.
    """
    category = _CATEGORY_BY_TYPE.get(action.action_type, "processing")
    params = action.parameters or {}

    rich = _extract_rich_label(action.action_type, params, action.resource_details)
    if rich:
        return category, rich

    if action.action_type in _GENERIC_LABEL:
        return category, _GENERIC_LABEL[action.action_type]

    # Slightly better fallbacks for common processing types than the raw
    # action type name.
    if action.action_type == "InvokeLambdaFunction":
        return "processing", "Looks up data"
    if action.action_type in ("SetContactAttributes", "UpdateContactAttributes"):
        return "processing", "Sets attributes"
    if action.action_type in ("CheckAttribute", "CheckContactAttributes"):
        return "processing", "Branches on attribute"
    if action.action_type == "Loop":
        return "processing", "Loops"

    return "processing", "Internal contact processing"


def _effective_action_context(graph: ContactFlowGraph) -> Dict[str, Dict[str, str]]:
    """Propagate reader-relevant TTS and queue state through the flow graph."""
    if not graph.actions:
        return {}

    incoming_count = {action_id: 0 for action_id in graph.actions}
    for action in graph.actions.values():
        for transition in action.all_transitions:
            if transition.target_action_id in incoming_count:
                incoming_count[transition.target_action_id] += 1

    roots: List[str] = []
    if graph.entry_point_id in graph.actions:
        roots.append(graph.entry_point_id)
    roots.extend(
        action_id
        for action_id in graph.actions
        if incoming_count[action_id] == 0 and action_id not in roots
    )
    roots.extend(action_id for action_id in graph.actions if action_id not in roots)

    before: Dict[str, Dict[str, str]] = {}
    after: Dict[str, Dict[str, str]] = {}
    for root in roots:
        if root in before:
            continue
        before[root] = {}
        queue = [root]
        head = 0
        while head < len(queue):
            action_id = queue[head]
            head += 1
            action = graph.actions[action_id]
            outgoing = _apply_action_context(before[action_id], action)
            if after.get(action_id) == outgoing:
                continue
            after[action_id] = outgoing
            for transition in action.all_transitions:
                target = transition.target_action_id
                if target not in graph.actions:
                    continue
                merged = _merge_action_context(before.get(target), outgoing)
                if before.get(target) != merged:
                    before[target] = merged
                    queue.append(target)
    return before


def _apply_action_context(context: Dict[str, str], action: FlowAction) -> Dict[str, str]:
    updated = dict(context)
    params = action.parameters or {}
    if action.action_type == "UpdateContactTextToSpeechVoice":
        settings = {
            "tts_voice": params.get("TextToSpeechVoice"),
            "tts_engine": params.get("TextToSpeechEngine"),
            "tts_style": params.get("TextToSpeechStyle"),
        }
        for key, value in settings.items():
            if isinstance(value, str) and value.strip():
                updated[key] = value.strip()
    elif action.action_type == "UpdateContactTargetQueue":
        updated["queue"] = _queue_identity(action, {})
    return updated


def _merge_action_context(
    current: Optional[Dict[str, str]], candidate: Dict[str, str]
) -> Dict[str, str]:
    if current is None:
        return dict(candidate)
    merged: Dict[str, str] = {}
    for key in set(current) | set(candidate):
        left = current.get(key, "")
        right = candidate.get(key, "")
        if left == right:
            if left:
                merged[key] = left
        else:
            merged[key] = "varies by route"
    return merged


def _customer_experience_scope(
    action: FlowAction, context: Optional[Dict[str, str]] = None
) -> List[str]:
    """Describe one action as an Amazon Connect practitioner would explain it."""
    context = context or {}
    action_type = action.action_type
    params = action.parameters or {}

    if action_type in ("MessageParticipant", "PlayPrompt"):
        return _voice_prompt_scope(params, context)
    if action_type == "MessageParticipantByText":
        text = _text_param(params)
        details = ["Sends a text-channel message to the customer."]
        if text:
            source = "dynamic" if _is_dynamic_text(text) else "static"
            details.append(f'Uses {source} message text: "{_display_text(text)}"')
        return details
    if action_type in ("GetUserInput", "GetParticipantInput"):
        details = _voice_prompt_scope(
            params, context, opening="Prompts the caller before collecting input"
        )
        timeout = _first_parameter(params, "InputTimeLimitSeconds", "Timeout", "TimeoutSeconds")
        max_digits = _first_parameter(params, "MaxDigits", "MaximumDigits")
        if max_digits and timeout:
            details.append(f"Waits up to {timeout} seconds for as many as {max_digits} digits.")
        elif timeout:
            details.append(f"Waits up to {timeout} seconds for the caller's response.")
        elif max_digits:
            details.append(f"Collects as many as {max_digits} digits from the caller.")
        else:
            details.append("Waits for a spoken response or keypad input from the caller.")
        return details
    if action_type in ("StoreUserInput", "StoreCustomerInput"):
        details = _voice_prompt_scope(
            params, context, opening="Prompts the caller before storing input"
        )
        max_digits = _first_parameter(params, "MaxDigits", "MaximumDigits")
        if max_digits:
            details.append(
                f"Stores as many as {max_digits} entered digits for later flow decisions."
            )
        else:
            details.append("Stores the caller's input for later routing or data-processing steps.")
        return details
    if action_type in ("ConnectToLexBot", "ConnectParticipantWithLexBot"):
        ai = _ai_agent_details(action)
        identity = ai.get("identity", "the configured Lex bot")
        alias = ai.get("alias")
        subtype = ai.get("subtype", "Lex bot")
        first = f"Starts an Amazon Lex conversation with {identity} ({subtype})"
        if alias:
            first += f" using alias {alias}"
        details = [first + "."]
        details.extend(
            _voice_prompt_scope(params, context, opening="Opens the conversation with a prompt")
        )
        return details
    if action_type == "UpdateFlowLoggingBehavior":
        behavior = str(params.get("FlowLoggingBehavior") or "Enabled").casefold()
        verb = "Disables" if behavior == "disabled" else "Enables"
        return [f"{verb} flow logging for subsequent actions."]
    if action_type == "InvokeLambdaFunction":
        function_name = _function_name(params.get("FunctionArn") or params.get("LambdaFunctionARN"))
        identity = function_name or "the configured Lambda function"
        details = [f"Invokes {identity} to retrieve or process contact data."]
        timeout = _first_parameter(params, "InvocationTimeLimitSeconds", "TimeoutSeconds")
        validation = params.get("ResponseValidation")
        response_type = validation.get("ResponseType") if isinstance(validation, dict) else None
        if timeout and response_type:
            readable_type = str(response_type).replace("_", " ").casefold()
            details.append(
                f"Waits up to {timeout} seconds and validates the response as a {readable_type}."
            )
        elif timeout:
            details.append(f"Waits up to {timeout} seconds for the function response.")
        elif response_type:
            readable_type = str(response_type).replace("_", " ").casefold()
            details.append(f"Validates the function response as a {readable_type}.")
        return details
    if action_type in ("SetContactAttributes", "UpdateContactAttributes"):
        attributes = params.get("Attributes") if isinstance(params, dict) else None
        if not isinstance(attributes, dict) or not attributes:
            return ["Sets contact attributes used by later routing and personalization steps."]
        names = [str(name) for name in attributes]
        display_names = names[:6]
        suffix = "" if len(names) <= 6 else f", and {len(names) - 6} more"
        values = list(attributes.values())
        from_lambda = values and all(
            isinstance(value, str) and value.startswith("$.External.") for value in values
        )
        if from_lambda:
            return [
                "Copies "
                + ", ".join(display_names)
                + suffix
                + " from the Lambda response into contact attributes."
            ]
        return [f"Sets contact attributes: {', '.join(display_names)}{suffix}."]
    if action_type in ("CheckAttribute", "CheckContactAttributes"):
        attribute = _friendly_reference(params.get("Attribute"))
        if attribute:
            return [
                f"Evaluates {attribute} and follows the first matching configured condition route."
            ]
        return ["Evaluates contact data and follows the first matching configured condition route."]
    if action_type == "CreateWisdomSession":
        assistant = action.resource_details.get("q_connect_assistant", {})
        identity = assistant.get("identity")
        subtype = assistant.get("subtype")
        if identity and identity != "Configured assistant" and subtype:
            return [
                f"Starts an Amazon Q in Connect session with {identity} "
                f"(assistant type: {subtype})."
            ]
        if identity and identity != "Configured assistant":
            return [f"Starts an Amazon Q in Connect session with {identity}."]
        return ["Starts an Amazon Q in Connect session with the configured assistant."]
    if action_type == "UpdateContactData":
        if params.get("WisdomSessionArn"):
            return ["Associates the active Amazon Q in Connect session with the contact."]
        fields = [str(key) for key in params if not str(key).endswith("Arn")]
        if fields:
            return [f"Updates contact data fields: {', '.join(fields[:6])}."]
        return ["Updates contact data used by subsequent flow and routing steps."]
    if action_type == "UpdateContactTextToSpeechVoice":
        voice = params.get("TextToSpeechVoice")
        engine = params.get("TextToSpeechEngine")
        if voice and engine:
            return [
                f"Sets subsequent synthesized prompts and Lex speech to use {voice} "
                f"with the {engine} text-to-speech engine."
            ]
        if voice:
            return [f"Sets subsequent synthesized prompts and Lex speech to use {voice}."]
        return ["Sets the Amazon Polly voice used by subsequent prompts and Lex interactions."]
    if action_type == "UpdateContactRecordingBehavior":
        behavior = params.get("RecordingBehavior")
        participants = behavior.get("RecordedParticipants") if isinstance(behavior, dict) else None
        if isinstance(participants, list) and participants:
            names = [
                "caller" if str(item).casefold() == "customer" else str(item).casefold()
                for item in participants
            ]
            if set(names) == {"agent", "caller"}:
                return ["Configures contact recording to capture both caller and agent audio."]
            return [f"Configures contact recording to capture {', '.join(names)} audio."]
        status = str(params.get("RecordingStatus") or params.get("RecordingBehavior") or "")
        if status and not isinstance(behavior, dict):
            return [f"Sets contact recording behavior to {status.replace('_', ' ').casefold()}."]
        return ["Configures which participants are captured in contact recordings."]
    if action_type == "UpdateContactTargetQueue":
        queue = _queue_identity(action, context)
        return [
            f"Selects {queue} as the destination for the next queue transfer.",
            "Prepares routing only; the caller is transferred by a later block.",
        ]
    if action_type in ("TransferToQueue", "TransferContactToQueue"):
        queue = _queue_identity(action, context)
        details = [f"Transfers the caller to {queue} to wait for an available agent."]
        if _has_outcome(action, "QueueAtCapacity"):
            details.append("Uses a separate configured route when the queue is at capacity.")
        return details
    if action_type == "CreateCallback":
        queue = _queue_identity(action, context)
        return [f"Creates a callback request in {queue} so the caller does not remain on hold."]
    if action_type == "SetCallbackNumber":
        return ["Stores the confirmed callback number for a later callback request."]
    if action_type == "Wait":
        duration = _first_parameter(params, "TimeLimitSeconds", "WaitTimeSeconds", "Seconds")
        if duration:
            return [f"Pauses this journey route for {duration} seconds before continuing."]
        return ["Pauses this journey route for the configured interval before continuing."]
    if action_type in (
        "TransferParticipantToThirdParty",
        "TransferContactToPhoneNumber",
        "TransferToPhoneNumber",
    ):
        destination = _phone_destination(params)
        if destination:
            if destination == "a number selected from contact data":
                return ["Transfers the caller to an external number selected from contact data."]
            return [f"Transfers the caller to an external number ending in {destination[-4:]}."]
        return ["Transfers the caller to the configured external destination."]
    if action_type in ("TransferToFlow", "TransferContactToFlow"):
        flow = action.resource_details.get("flow", {}).get("identity")
        if flow:
            return [f"Hands the contact to the {flow} flow for the next part of the journey."]
        return ["Hands the contact to another configured flow for the next part of the journey."]
    if action_type == "Loop":
        count = _first_parameter(params, "LoopCount", "Iterations", "Count")
        if count:
            return [f"Repeats the connected journey steps up to {count} times before exiting."]
        return ["Repeats the connected journey steps until a configured exit route is taken."]
    if action_type == "DisconnectParticipant":
        return ["Disconnects the voice contact; no further flow actions run for the caller."]
    if action_type == "EndFlowExecution":
        return [
            "Stops this flow execution and returns control to its invoking context when applicable."
        ]

    category = _CATEGORY_BY_TYPE.get(action_type, "processing")
    if category == "speaks":
        return ["Delivers the configured message or prompt to the customer."]
    if category == "chooses":
        return ["Collects customer input and uses it to continue the journey."]
    if category == "waits":
        return ["Places the caller into a configured waiting or callback step."]
    if category == "terminal":
        return ["Ends or hands off this part of the customer journey."]
    return [
        "Performs an internal contact-processing step whose detailed configuration "
        "is not yet interpreted by this report."
    ]


def _voice_prompt_scope(
    params: Dict,
    context: Dict[str, str],
    opening: str = "Plays a prompt to the caller",
) -> List[str]:
    text = _text_param(params)
    details: List[str] = []
    if text:
        if _is_dynamic_text(text):
            details.append(f"{opening} using dynamic text assembled from contact data.")
        elif text.lstrip().startswith("<speak"):
            details.append(f"{opening} using inline SSML text.")
        else:
            details.append(f"{opening} using inline static text.")
        details.append(_tts_delivery_scope(context))
        details.append(f'Prompt: "{_display_text(text)}"')
        return details
    if params.get("PromptId") or params.get("PromptArn"):
        return [
            f"{opening} using a saved audio prompt.",
            "Plays the prerecorded prompt configured in Amazon Connect.",
        ]
    return [f"{opening} using the configured prompt source."]


def _tts_delivery_scope(context: Dict[str, str]) -> str:
    voice = context.get("tts_voice")
    engine = context.get("tts_engine")
    if "varies by route" in {voice, engine}:
        return "Synthesizes the prompt with Amazon Polly using settings that vary by route."
    if voice and engine:
        return f"Synthesizes the prompt with Amazon Polly using {voice} and the {engine} engine."
    if voice:
        return f"Synthesizes the prompt with Amazon Polly using the {voice} voice."
    return "Synthesizes the prompt with Amazon Polly using the flow's active voice settings."


def _queue_identity(action: FlowAction, context: Dict[str, str]) -> str:
    resolved = action.resource_details.get("queue", {}).get("identity")
    if isinstance(resolved, str) and resolved:
        return resolved
    inherited = context.get("queue")
    if inherited and inherited != "varies by route":
        return inherited
    if inherited == "varies by route":
        return "a queue that varies by route"
    queue_id = (action.parameters or {}).get("QueueId")
    if isinstance(queue_id, str) and queue_id.startswith("$"):
        return "a queue selected from contact data"
    return "the configured queue"


def _first_parameter(params: Dict, *names: str) -> Optional[str]:
    for name in names:
        value = params.get(name)
        if value is not None and str(value).strip():
            return str(value).strip()
    return None


def _friendly_reference(value: object) -> Optional[str]:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.startswith("$."):
        return text.rsplit(".", 1)[-1].replace("_", " ")
    return text.replace("_", " ")


def _is_dynamic_text(text: str) -> bool:
    return "$." in text or "{{" in text or "${" in text


def _display_text(text: str, limit: int = 260) -> str:
    collapsed = " ".join(text.split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1].rstrip() + "…"


def _has_outcome(action: FlowAction, token: str) -> bool:
    return any(token in str(transition.condition or "") for transition in action.all_transitions)


def _ai_agent_details(action: FlowAction) -> Dict[str, str]:
    """Return verified-or-derived identity details for a conversational AI action."""
    if action.action_type not in ("ConnectToLexBot", "ConnectParticipantWithLexBot"):
        return {}

    params = action.parameters or {}
    resolved = action.resource_details.get("ai", {})
    is_v2 = isinstance(params.get("LexV2Bot"), dict)
    identity = resolved.get("identity") or _lex_bot_name(params) or "Configured Lex bot"
    details = {
        "technology": resolved.get("technology") or "Amazon Lex",
        "identity": identity,
        "subtype": resolved.get("subtype") or ("V2 bot" if is_v2 else "V1 bot"),
    }
    alias = resolved.get("alias") or _lex_bot_alias(params)
    if alias:
        details["alias"] = alias
    return details


def _extract_rich_label(
    action_type: str,
    params: Dict,
    resource_details: Optional[Dict[str, Any]] = None,
) -> Optional[str]:
    """
    Pull a user-facing label out of an action's parameters.

    Returns ``None`` when the parameters don't carry anything more
    informative than what the generic label already conveys.
    """
    if action_type in ("MessageParticipant", "PlayPrompt"):
        text = _text_param(params)
        if text:
            return f'Plays: "{text}"'

    if action_type == "MessageParticipantByText":
        text = _text_param(params)
        if text:
            return f'Sends: "{text}"'

    if action_type in ("GetUserInput", "GetParticipantInput"):
        text = _text_param(params)
        if text:
            return f'Asks: "{text}"'

    if action_type in ("StoreUserInput", "StoreCustomerInput"):
        text = _text_param(params)
        if text:
            return f'Captures input: "{text}"'

    if action_type == "InvokeLambdaFunction":
        fn = _function_name(params.get("FunctionArn") or params.get("LambdaFunctionARN"))
        if fn:
            return f"Lambda: {fn}"

    if action_type in ("ConnectToLexBot", "ConnectParticipantWithLexBot"):
        prompt = _text_param(params)
        if prompt:
            return f'AI conversation: "{prompt}"'
        resource_details = resource_details or {}
        resolved_ai = resource_details.get("ai", {})
        bot = resolved_ai.get("identity") or _lex_bot_name(params)
        if bot:
            return f"Lex bot: {bot}"

    if action_type in ("TransferToQueue", "TransferContactToQueue"):
        resource_details = resource_details or {}
        queue = resource_details.get("queue", {}).get("identity") or _queue_reference(params)
        if queue:
            return f"Queue: {queue}"

    if action_type in (
        "TransferParticipantToThirdParty",
        "TransferContactToPhoneNumber",
        "TransferToPhoneNumber",
    ):
        phone = _phone_destination(params)
        if phone:
            return f"Transfer to {phone}"

    if action_type in ("TransferToFlow", "TransferContactToFlow"):
        resource_details = resource_details or {}
        target_name = resource_details.get("flow", {}).get("identity")
        if target_name:
            return f"To flow: {target_name}"
        if params.get("ContactFlowId") or params.get("FlowId"):
            return "Hands off to another flow"

    if action_type in ("SetContactAttributes", "UpdateContactAttributes"):
        attrs = params.get("Attributes") if isinstance(params, dict) else None
        if isinstance(attrs, dict) and attrs:
            keys = ", ".join(list(attrs.keys())[:3])
            return f"Sets: {keys}"

    if action_type in ("CheckAttribute", "CheckContactAttributes"):
        attr = params.get("Attribute") if isinstance(params, dict) else None
        friendly = _friendly_reference(attr)
        if friendly:
            return f"Checks: {friendly}"

    return None


def _text_param(params: Dict) -> Optional[str]:
    """Extract prompt text from a params dict, handling common shapes."""
    if not isinstance(params, dict):
        return None
    # Direct Text parameter (MessageParticipant, PlayPrompt).
    text = params.get("Text")
    if isinstance(text, str) and text.strip():
        return text.strip()
    # Nested Media.Text (some GetParticipantInput shapes carry the
    # prompt inside a Media dict).
    media = params.get("Media")
    if isinstance(media, dict):
        media_text = media.get("Text") or media.get("SsmlText")
        if isinstance(media_text, str) and media_text.strip():
            return media_text.strip()
    # SSMLText fallback.
    ssml = params.get("SSML")
    if isinstance(ssml, str) and ssml.strip():
        return ssml.strip()
    return None


def _function_name(arn: object) -> Optional[str]:
    """Extract the bare Lambda function name from an ARN or reference."""
    if not isinstance(arn, str) or not arn.strip():
        return None
    # ARN shape: arn:aws:lambda:region:acct:function:my-function[:qualifier]
    if ":function:" in arn:
        tail = arn.split(":function:")[-1]
        # Strip any trailing :qualifier for readability.
        return tail.split(":")[0]
    # Not an ARN — assume the caller passed a plain function name.
    return arn


def _lex_bot_name(params: Dict) -> Optional[str]:
    """Extract a Lex bot name from either v1 or v2 param shapes."""
    if not isinstance(params, dict):
        return None
    # v1: BotName parameter at top level.
    name = params.get("BotName")
    if isinstance(name, str) and name.strip():
        return name.strip()
    # V2 display names may be present directly. Alias ARNs only contain
    # opaque bot/alias IDs and are intentionally not surfaced.
    v2 = params.get("LexV2Bot") or params.get("LexBot")
    if isinstance(v2, dict):
        nested_name = v2.get("Name") or v2.get("BotName")
        if isinstance(nested_name, str) and nested_name.strip():
            return nested_name.strip()
    return None


def _lex_bot_alias(params: Dict) -> Optional[str]:
    """Extract a Lex alias name or ID from v1/v2 parameter shapes."""
    if not isinstance(params, dict):
        return None
    alias = params.get("BotAlias") or params.get("Alias")
    if isinstance(alias, str) and alias.strip():
        return alias.strip()
    nested = params.get("LexV2Bot") or params.get("LexBot")
    if not isinstance(nested, dict):
        return None
    alias = nested.get("AliasName") or nested.get("BotAlias")
    if isinstance(alias, str) and alias.strip():
        return alias.strip()
    # Alias ARNs contain only opaque IDs; resolved display names arrive
    # through resource_details and are intentionally the only ARN fallback.
    return None


def _queue_reference(params: Dict) -> Optional[str]:
    """Return a safe queue description without exposing JSON paths or IDs."""
    if not isinstance(params, dict):
        return None
    queue_id = params.get("QueueId")
    if isinstance(queue_id, str) and queue_id.strip():
        if queue_id.startswith("$"):
            return "Queue selected from contact data"
        return "Configured queue"
    queue = params.get("Queue")
    if isinstance(queue, dict) and (queue.get("Arn") or queue.get("Id")):
        return "Configured queue"
    return None


def _phone_destination(params: Dict) -> Optional[str]:
    """Extract a phone destination, masking to preserve some privacy in the report."""
    if not isinstance(params, dict):
        return None
    endpoint = params.get("Endpoint")
    if isinstance(endpoint, dict):
        address = endpoint.get("Address")
        if isinstance(address, str) and address.strip():
            return _mask_phone(address.strip())
    phone = params.get("PhoneNumber")
    if isinstance(phone, str) and phone.strip():
        return _mask_phone(phone.strip())
    return None


def _mask_phone(number: str) -> str:
    """Mask all but the last 4 digits of a phone number or hide a dynamic path."""
    if number.startswith("$"):
        return "a number selected from contact data"
    digits = "".join(c for c in number if c.isdigit())
    if len(digits) <= 4:
        return number
    return "***" + digits[-4:]


def _short_id(identifier: str) -> str:
    """Return a shortened UUID-ish identifier for display."""
    if len(identifier) <= 12:
        return identifier
    return identifier[:8] + "…"


def _truncate(label: str, max_chars: int) -> str:
    """Cap a label at `max_chars` characters."""
    cleaned = label.replace("\n", " ").strip()
    if len(cleaned) > max_chars:
        cleaned = cleaned[: max_chars - 1] + "…"
    return cleaned
