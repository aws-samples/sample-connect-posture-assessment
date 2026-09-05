"""
Amazon Connect contact flow parser.

Converts contact flow JSON into a structured ``ContactFlowGraph`` and back,
preserving structural fidelity (round-trip) including unknown action types.

Graph algorithms (cycle detection, paths), pattern detection, and complexity
scoring live in sibling modules (``flow_graph``, ``flow_patterns``,
``flow_complexity``) so each concern can evolve independently.
"""

from typing import Any, Dict, List

from ..models import ContactFlowGraph, FlowAction, FlowTransition


class ContactFlowParseError(ValueError):
    """Raised when contact flow JSON cannot be parsed into a graph."""


class ContactFlowParser:
    """Parse and serialize Amazon Connect contact flow JSON."""

    DEFAULT_VERSION = "2019-10-30"

    def parse(self, flow_json: Dict[str, Any]) -> ContactFlowGraph:
        """
        Parse contact flow JSON into a ``ContactFlowGraph``.

        Args:
            flow_json: The contact flow document (a dict).

        Returns:
            ContactFlowGraph: structured representation.

        Raises:
            ContactFlowParseError: if ``flow_json`` is not a dict.
        """
        if not isinstance(flow_json, dict):
            raise ContactFlowParseError(
                f"Contact flow JSON must be a dict, got {type(flow_json).__name__}"
            )

        actions: Dict[str, FlowAction] = {}
        for raw_action in flow_json.get("Actions", []) or []:
            if not isinstance(raw_action, dict):
                # Skip non-dict entries but do not crash.
                continue
            action = self._parse_action(raw_action)
            if action is not None:
                actions[action.action_id] = action

        return ContactFlowGraph(
            flow_id=flow_json.get("Identifier", "") or "",
            flow_name=flow_json.get("Name", "") or "",
            flow_type=flow_json.get("Type", "") or "",
            actions=actions,
            entry_point_id=flow_json.get("StartAction", "") or "",
            version=flow_json.get("Version", self.DEFAULT_VERSION) or self.DEFAULT_VERSION,
            metadata=flow_json.get("Metadata", {}) or {},
        )

    def serialize(self, graph: ContactFlowGraph) -> Dict[str, Any]:
        """
        Serialize a ``ContactFlowGraph`` back to contact flow JSON.

        Uses each action's preserved ``raw_json`` so that round-tripping a
        parsed flow reproduces a semantically equivalent document, including
        unknown action types.
        """
        return {
            "Version": graph.version,
            "Identifier": graph.flow_id,
            "Name": graph.flow_name,
            "Type": graph.flow_type,
            "StartAction": graph.entry_point_id,
            "Actions": [action.raw_json for action in graph.actions.values()],
            "Metadata": graph.metadata,
        }

    # -- internal helpers ---------------------------------------------------

    def _parse_action(self, raw: Dict[str, Any]) -> FlowAction:
        identifier = raw.get("Identifier")
        if not identifier:
            # Without an identifier the action cannot be placed in the graph.
            return None

        transitions, error_transitions = self._parse_transitions(raw, identifier)
        return FlowAction(
            action_id=identifier,
            action_type=raw.get("Type", "") or "",
            parameters=raw.get("Parameters", {}) or {},
            transitions=transitions,
            error_transitions=error_transitions,
            raw_json=raw,
        )

    def _parse_transitions(self, raw: Dict[str, Any], source_id: str):
        """Return (default+condition transitions, error transitions)."""
        transitions: List[FlowTransition] = []
        error_transitions: List[FlowTransition] = []

        raw_transitions = raw.get("Transitions", {}) or {}

        # Default next action.
        next_action = raw_transitions.get("NextAction")
        if next_action:
            transitions.append(
                FlowTransition(
                    source_action_id=source_id,
                    target_action_id=next_action,
                    transition_type="default",
                )
            )

        # Conditional branches.
        for cond in raw_transitions.get("Conditions", []) or []:
            target = cond.get("NextAction")
            if target:
                condition = cond.get("Condition")
                transitions.append(
                    FlowTransition(
                        source_action_id=source_id,
                        target_action_id=target,
                        condition=str(condition) if condition is not None else None,
                        transition_type="condition",
                    )
                )

        # Error branches.
        for err in raw_transitions.get("Errors", []) or []:
            target = err.get("NextAction")
            if target:
                error_transitions.append(
                    FlowTransition(
                        source_action_id=source_id,
                        target_action_id=target,
                        condition=err.get("ErrorType"),
                        transition_type="error",
                    )
                )

        return transitions, error_transitions
