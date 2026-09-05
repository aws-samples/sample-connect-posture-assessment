"""
Performance efficiency checks for Amazon Connect contact flows.

- perf-lambda-count-001       : Observational route-aware Lambda usage inventory
- perf-sequential-lambda-001  : Reachable Lambda sequences without interaction
- perf-flow-complexity-001    : Descriptive flow structure review
"""

from collections import deque
from typing import Any, Optional

from ..models import (
    CheckStatus,
    ContactFlow,
    ContactFlowGraph,
    FlowAction,
    FlowTransition,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from ..parsers import ContactFlowParser, calculate_flow_metrics, reachable_from_entry
from .base import BaseCheck, CheckContext

_PARSER = ContactFlowParser()
_MAX_SEQUENCE_EVIDENCE_ROWS = 100
_MAX_LAMBDA_ROUTE_STATES = 20000

_INTERACTION_TYPES = {
    "GetParticipantInput",
    "GetUserInput",
    "StoreUserInput",
    "MessageParticipant",
    "PlayPrompt",
    "ConnectToLexBot",
    "ConnectParticipantWithLexBot",
}


def _parse_flow(flow: ContactFlow) -> Optional[ContactFlowGraph]:
    if not flow.content or not isinstance(flow.content, dict):
        return None
    try:
        return _PARSER.parse(flow.content)
    except Exception:
        return None


def _parameter_value(parameters: dict[str, Any], *names: str) -> str:
    """Return a readable static or dynamic Connect flow parameter value."""
    value: Any = None
    for name in names:
        if name in parameters:
            value = parameters[name]
            break

    while isinstance(value, dict):
        if "Value" in value:
            value = value["Value"]
            continue
        if "StaticValue" in value:
            value = value["StaticValue"]
            continue
        namespace = value.get("Namespace")
        key = value.get("Key")
        if namespace or key:
            return ".".join(str(part) for part in (namespace, key) if part)
        break

    if value is None:
        return "not specified in flow export"
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    return str(value)


def _lambda_function_name(function_arn: str) -> str:
    if function_arn == "not specified in flow export":
        return function_arn
    if ":function:" in function_arn:
        return function_arn.split(":function:", 1)[1]
    return function_arn.rsplit(":", 1)[-1].rsplit("/", 1)[-1]


def _lambda_evidence(action: FlowAction, prefix: str) -> dict[str, Any]:
    function_arn = _parameter_value(action.parameters, "FunctionArn", "LambdaFunctionARN")
    response_validation = action.parameters.get("ResponseValidation", {})
    response_type = (
        _parameter_value(response_validation, "ResponseType")
        if isinstance(response_validation, dict)
        else str(response_validation)
    )
    return {
        f"{prefix}_action_id": action.action_id,
        f"{prefix}_function_name": _lambda_function_name(function_arn),
        f"{prefix}_function_arn": function_arn,
        f"{prefix}_invocation_type": _parameter_value(
            action.parameters, "InvocationType", "InvocationMode"
        ),
        f"{prefix}_timeout_seconds": _parameter_value(
            action.parameters, "InvocationTimeLimitSeconds", "Timeout"
        ),
        f"{prefix}_response_type": response_type,
        f"{prefix}_has_error_branch": bool(action.error_transitions),
        f"{prefix}_error_targets": [
            transition.target_action_id for transition in action.error_transitions
        ],
    }


def _transition_label(transition: FlowTransition) -> str:
    if transition.condition:
        return f"{transition.transition_type} ({transition.condition})"
    return transition.transition_type


def _next_lambda_pairs(graph: ContactFlowGraph) -> list[dict[str, Any]]:
    """Find each reachable Lambda followed by the next Lambda before interaction.

    Traversal follows default, conditional, and error routes through processing
    blocks. It stops at a customer-facing interaction or the next Lambda. A
    breadth-first search records one shortest route for each source/target pair.
    """
    reachable = reachable_from_entry(graph)
    found: list[dict[str, Any]] = []
    seen_pairs: set[tuple[str, str]] = set()

    for source_id in sorted(reachable):
        source = graph.actions[source_id]
        if source.action_type != "InvokeLambdaFunction":
            continue

        queue: deque[tuple[str, list[str], list[str], list[str]]] = deque()
        for transition in source.all_transitions:
            queue.append(
                (
                    transition.target_action_id,
                    [source_id, transition.target_action_id],
                    [source.action_type],
                    [_transition_label(transition)],
                )
            )
        visited = {source_id}

        while queue:
            current_id, path_ids, path_types, route = queue.popleft()
            if current_id in visited or current_id not in reachable:
                continue
            visited.add(current_id)
            current = graph.actions[current_id]
            current_path_types = [*path_types, current.action_type]

            if current.action_type in _INTERACTION_TYPES:
                continue

            if current.action_type == "InvokeLambdaFunction":
                pair_key = (source_id, current_id)
                if pair_key not in seen_pairs:
                    seen_pairs.add(pair_key)
                    intermediate = [
                        f"{action_id} ({action_type})"
                        for action_id, action_type in zip(
                            path_ids[1:-1], current_path_types[1:-1], strict=True
                        )
                    ]
                    found.append(
                        {
                            **_lambda_evidence(source, "first"),
                            **_lambda_evidence(current, "second"),
                            "path_action_ids": path_ids,
                            "intermediate_actions": (
                                " -> ".join(intermediate)
                                if intermediate
                                else "none (direct transition)"
                            ),
                            "transition_route": " -> ".join(route),
                            "route_contains_error_transition": any(
                                step.startswith("error") for step in route
                            ),
                        }
                    )
                continue

            for transition in current.all_transitions:
                target_id = transition.target_action_id
                if target_id not in visited:
                    queue.append(
                        (
                            target_id,
                            [*path_ids, target_id],
                            current_path_types,
                            [*route, _transition_label(transition)],
                        )
                    )

    return found


def _max_lambda_blocks_on_simple_route(
    graph: ContactFlowGraph, max_states: int = _MAX_LAMBDA_ROUTE_STATES
) -> tuple[int, bool]:
    """Return the largest Lambda-block count on one bounded simple route."""
    if not graph.actions:
        return 0, False
    start = (
        graph.entry_point_id if graph.entry_point_id in graph.actions else next(iter(graph.actions))
    )

    maximum = 0
    states_explored = 0
    stack = [(start, 0, frozenset([start]))]
    while stack:
        if states_explored >= max_states:
            return maximum, True
        states_explored += 1
        action_id, lambda_count, seen = stack.pop()
        action = graph.actions[action_id]
        route_lambda_count = lambda_count + int(action.action_type == "InvokeLambdaFunction")
        maximum = max(maximum, route_lambda_count)
        for transition in action.all_transitions:
            target_id = transition.target_action_id
            if target_id in graph.actions and target_id not in seen:
                stack.append((target_id, route_lambda_count, seen | {target_id}))
    return maximum, False


def _lambda_action_row(
    flow: ContactFlow, action: FlowAction, reachable: set[str]
) -> dict[str, Any]:
    details = _lambda_evidence(action, "lambda")
    return {
        "flow": flow.name,
        "flow_id": flow.id,
        "reachable_from_entry": action.action_id in reachable,
        **details,
        "outgoing_transitions": [
            f"{_transition_label(transition)} -> {transition.target_action_id}"
            for transition in action.all_transitions
        ],
    }


class LambdaInvocationCountCheck(BaseCheck):
    """Inventory Lambda usage without assigning an unsupported count limit."""

    def __init__(self):
        super().__init__(
            check_id="perf-lambda-count-001",
            name="Lambda Usage Structure Review",
            pillar=Pillar.PERFORMANCE_EFFICIENCY,
            severity=Severity.LOW,
            description=(
                "Inventories authored and reachable Lambda blocks and route-level "
                "usage without applying an unsupported numerical threshold."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flow_usage: list[dict[str, Any]] = []
        lambda_actions: list[dict[str, Any]] = []
        flows_skipped = 0

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                flows_skipped += 1
                continue

            reachable = reachable_from_entry(graph)
            lambda_blocks = sorted(
                (
                    action
                    for action in graph.actions.values()
                    if action.action_type == "InvokeLambdaFunction"
                ),
                key=lambda action: action.action_id,
            )
            reachable_lambda_blocks = sum(action.action_id in reachable for action in lambda_blocks)
            maximum_on_route, route_analysis_capped = _max_lambda_blocks_on_simple_route(graph)
            flow_usage.append(
                {
                    "flow": flow.name,
                    "flow_id": flow.id,
                    "total_lambda_blocks": len(lambda_blocks),
                    "reachable_lambda_blocks": reachable_lambda_blocks,
                    "unreachable_lambda_blocks": (len(lambda_blocks) - reachable_lambda_blocks),
                    "max_lambda_blocks_on_simple_route": maximum_on_route,
                    "route_analysis_capped": route_analysis_capped,
                }
            )
            lambda_actions.extend(
                _lambda_action_row(flow, action, reachable) for action in lambda_blocks
            )

        flow_usage.sort(key=lambda row: (str(row["flow"]).casefold(), str(row["flow_id"])))
        lambda_actions.sort(
            key=lambda row: (
                str(row["flow"]).casefold(),
                str(row["lambda_action_id"]),
            )
        )
        evidence = {
            "flows_discovered": len(instance.contact_flows),
            "flows_analyzed": len(flow_usage),
            "flows_skipped": flows_skipped,
            "total_lambda_blocks": sum(int(row["total_lambda_blocks"]) for row in flow_usage),
            "reachable_lambda_blocks": sum(
                int(row["reachable_lambda_blocks"]) for row in flow_usage
            ),
            "numeric_compliance_threshold_applied": False,
            "flow_lambda_usage": flow_usage,
            "lambda_action_details": lambda_actions,
        }

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"**Lambda usage inventory completed for {len(flow_usage)} of "
                f"{len(instance.contact_flows)} contact flow(s).**\n\n"
                "Amazon Connect does not publish a maximum number of Lambda blocks "
                "that makes a flow compliant or noncompliant. This check therefore "
                "does not fail a flow from a locally selected count.\n\n"
                "**How to read the evidence.** `Total Lambda blocks` counts every "
                "authored Lambda action in a flow. `Reachable Lambda blocks` excludes "
                "disconnected actions. `Max Lambda blocks on simple route` is the "
                "largest number one caller route can traverse without revisiting an "
                "action; it avoids incorrectly adding mutually exclusive branches "
                "together. A capped route analysis is explicitly marked and is a "
                "lower bound. Per-action evidence records the normalized function "
                "ARN/name, mode, timeout, response validation, reachability, outgoing "
                "transitions, and Error branches.\n\n"
                "Use the separate **Sequential Lambda Invocations** result for the "
                "AWS-backed 20-second sequence and caller-silence review.\n\n"
                "**Status meaning:** PASS means the inventory completed; it does not "
                "certify that a specific number of Lambda calls is optimal. See "
                "[Connect Lambda functions](https://docs.aws.amazon.com/connect/"
                "latest/adminguide/connect-lambda-functions.html) and the "
                "[AWS Lambda flow block](https://docs.aws.amazon.com/connect/latest/"
                "adminguide/invoke-lambda-function-block.html)."
            ),
            evidence=evidence,
        )


class SequentialLambdaCheck(BaseCheck):
    """Detect reachable Lambda sequences without customer interaction."""

    def __init__(self):
        super().__init__(
            check_id="perf-sequential-lambda-001",
            name="Sequential Lambda Invocations",
            pillar=Pillar.PERFORMANCE_EFFICIENCY,
            severity=Severity.LOW,
            description=(
                "Reviews reachable flow routes where one Lambda invocation is followed "
                "by another before a customer-facing interaction."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged: list[dict[str, Any]] = []
        flows_analyzed = 0
        flows_skipped = 0

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                flows_skipped += 1
                continue
            flows_analyzed += 1
            for pair in _next_lambda_pairs(graph):
                flagged.append({"flow": flow.name, "flow_id": flow.id, **pair})

        flagged.sort(
            key=lambda pair: (
                str(pair["flow"]).casefold(),
                str(pair["first_action_id"]),
                str(pair["second_action_id"]),
            )
        )
        details = flagged[:_MAX_SEQUENCE_EVIDENCE_ROWS]
        evidence = {
            "flows_discovered": len(instance.contact_flows),
            "flows_analyzed": flows_analyzed,
            "flows_skipped": flows_skipped,
            "affected_flows": len({pair["flow_id"] for pair in flagged}),
            "sequential_pairs": len(flagged),
            "detail_rows_shown": len(details),
            "detail_rows_omitted": len(flagged) - len(details),
        }

        if flagged:
            evidence["sequence_details"] = details
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(flagged)} reachable Lambda sequence(s) were found across "
                    f"{evidence['affected_flows']} flow(s).** This is a review signal, "
                    "not a blanket prohibition on calling two functions.\n\n"
                    "**Why it is called out.** While a synchronous Lambda runs, the "
                    "contact waits and callers hear silence. Amazon Connect limits a "
                    "sequence of Lambda functions to 20 seconds and recommends "
                    "inserting a **Play prompt** between functions to keep callers "
                    "engaged and break up long chains. A synchronous invocation can "
                    "wait up to 8 seconds; asynchronous "
                    "mode supports up to 60 seconds. Throttles, service failures, and "
                    "function errors may be retried up to three times until the "
                    "configured timeout, after which Connect routes the contact down "
                    "the Error branch. Two calls can therefore compound silence, "
                    "latency, and failure handling.\n\n"
                    "**What this check traced.** Starting at each reachable Lambda, "
                    "the check follows default, conditional, and error transitions "
                    "through non-interaction processing blocks. It stops at a "
                    "customer-facing prompt/input/bot block or at the next Lambda. "
                    "The evidence identifies both functions, configured modes and "
                    "timeouts, intermediate actions, transition route, and Error "
                    "branches.\n\n"
                    "See [Connect Lambda functions](https://docs.aws.amazon.com/connect/"
                    "latest/adminguide/connect-lambda-functions.html) and the "
                    "[AWS Lambda flow block](https://docs.aws.amazon.com/connect/latest/"
                    "adminguide/invoke-lambda-function-block.html)."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        "Review each Lambda sequence for data dependency, caller audio, "
                        "timeout, and Error-branch behavior."
                    ),
                    target_resources=[
                        f"{pair['flow_id']}:{pair['first_action_id']}" for pair in details
                    ],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each evidence row, determine whether the second "
                                "function consumes the first function's result. Do not "
                                "reorder or parallelize dependent calls."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "If both calls perform one cohesive, dependent operation, "
                                "consider consolidating that work only when doing so "
                                "preserves ownership, observability, retries, and failure "
                                "isolation."
                            ),
                        ),
                        RemediationStep(
                            order=3,
                            instruction=(
                                "If work does not require an immediate response, evaluate "
                                "asynchronous invocation and a Wait/Load Lambda Result "
                                "pattern instead of making the caller wait synchronously."
                            ),
                        ),
                        RemediationStep(
                            order=4,
                            instruction=(
                                "If separate synchronous calls must remain, add a Play "
                                "prompt between long-running calls as Amazon Connect "
                                "recommends so the caller does not experience unexplained "
                                "silence."
                            ),
                            console_path="Connect console -> Routing -> Flows",
                        ),
                        RemediationStep(
                            order=5,
                            instruction=(
                                "Set intentional timeouts, retain and test each Error "
                                "branch, and verify success, timeout, throttle, service-"
                                "failure, and function-error routes before publishing."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Connect Lambda functions",
                            url=(
                                "https://docs.aws.amazon.com/connect/latest/adminguide/"
                                "connect-lambda-functions.html"
                            ),
                        ),
                        RemediationReference(
                            title="AWS Lambda function flow block",
                            url=(
                                "https://docs.aws.amazon.com/connect/latest/adminguide/"
                                "invoke-lambda-function-block.html"
                            ),
                        ),
                    ],
                    applies_if=(
                        "a reachable route invokes another Lambda before a customer-facing "
                        "interaction."
                    ),
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                "No reachable route invokes a second Lambda before first reaching a "
                "customer-facing prompt, input, or bot interaction."
            ),
            evidence=evidence,
        )


class FlowComplexityCheck(BaseCheck):
    """Collect neutral structural metrics for flow maintainability review."""

    def __init__(self):
        super().__init__(
            check_id="perf-flow-complexity-001",
            name="Contact Flow Structure Review",
            pillar=Pillar.PERFORMANCE_EFFICIENCY,
            severity=Severity.LOW,
            description=(
                "Collects descriptive contact-flow structure metrics without applying "
                "an unsupported numerical complexity threshold."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flow_metrics: list[dict[str, Any]] = []
        flows_skipped = 0

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                flows_skipped += 1
                continue
            metrics = calculate_flow_metrics(graph)
            flow_metrics.append(
                {
                    "flow": flow.name,
                    "flow_id": flow.id,
                    "total_actions": metrics.total_actions,
                    "reachable_actions": metrics.reachable_actions,
                    "longest_route_transitions": metrics.longest_route_transitions,
                    "route_analysis_capped": metrics.route_analysis_capped,
                    "integration_points": metrics.integration_points,
                    "cycles": metrics.cycle_count,
                    "paths_enumerated": metrics.paths_enumerated,
                    "path_enumeration_capped": metrics.path_enumeration_capped,
                    "module_invocations": metrics.module_invocations,
                }
            )

        flow_metrics.sort(key=lambda row: (str(row["flow"]).casefold(), str(row["flow_id"])))
        evidence = {
            "flows_discovered": len(instance.contact_flows),
            "flows_analyzed": len(flow_metrics),
            "flows_skipped": flows_skipped,
            "numeric_compliance_threshold_applied": False,
            "flow_structural_metrics": flow_metrics,
        }

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"**Structure review completed for {len(flow_metrics)} of "
                f"{len(instance.contact_flows)} contact flow(s).**\n\n"
                "Amazon Connect recommends making flows as small as possible and "
                "using reusable flows/modules to reduce maintenance and regression "
                "risk. The published guidance does **not** define a maximum action "
                "count, route length, branching-depth cutoff, or weighted complexity "
                "score. This check therefore does not classify a flow as compliant or "
                "noncompliant from invented numbers.\n\n"
                "The evidence is an observational inventory: total and reachable "
                "actions, longest simple route measured in transitions, integration "
                "points, detected cycles, bounded path enumeration, and module "
                "invocations. Use these values with the flow's business purpose, "
                "change history, ownership, test coverage, and caller experience to "
                "prioritize human architecture review. A capped route or path analysis "
                "is explicitly marked and is a lower bound, not an exact total.\n\n"
                "**Status meaning:** PASS means the structural inventory completed; it "
                "does not certify flow maintainability. See [flow best practices]"
                "(https://docs.aws.amazon.com/connect/latest/adminguide/"
                "bp-contact-flows.html), [Operational Excellence]"
                "(https://docs.aws.amazon.com/connect/latest/adminguide/"
                "operational-excellence.html), and [flow modules]"
                "(https://docs.aws.amazon.com/connect/latest/adminguide/"
                "contact-flow-modules.html)."
            ),
            evidence=evidence,
        )


def register_performance_efficiency_checks(registry) -> None:
    """Register all performance efficiency checks."""
    registry.register_check(LambdaInvocationCountCheck())
    registry.register_check(SequentialLambdaCheck())
    registry.register_check(FlowComplexityCheck())
