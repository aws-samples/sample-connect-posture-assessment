"""
Operational-intelligence cost checks (Phase 4 / Task 9).

These checks analyze contact flow structure and queue metrics for cost waste:

- cost-containment-001     : Self-service containment scoring (Req 28)
- cost-wait-time-001       : Queue wait time / callback opportunity (Req 29)
- cost-occupancy-001       : Agent occupancy / staffing efficiency (Req 30)
- cost-fcr-001             : Repeat contact / FCR indicators (Req 31)
- cost-acw-001             : After-contact work duration (Req 32)
- cost-data-continuity-001 : IVR-to-agent data continuity (Req 40)
"""

from typing import Optional

from ..cost.cost_estimator import AGENT_HANDLED_COST_AVG, TELEPHONY_PER_MINUTE
from ..models import (
    CheckStatus,
    ContactFlow,
    ContactFlowGraph,
    FlowAction,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from ..parsers import ContactFlowParser, is_default_sample_flow
from ..parsers.flow_patterns import (
    AGENT_ROUTING_ACTION_TYPES,
    SELF_SERVICE_ACTION_TYPES,
)
from .base import BaseCheck, CheckContext

_PARSER = ContactFlowParser()

_INPUT_COLLECTION_ACTIONS = {
    "GetParticipantInput",
    "GetUserInput",
    "StoreUserInput",
    "InvokeLambdaFunction",
    "ConnectToLexBot",
    "ConnectParticipantWithLexBot",
}
_ATTRIBUTE_SET_ACTIONS = {"UpdateContactAttributes", "SetContactAttributes"}
_QUEUE_TRANSFER_ACTIONS = {"TransferToQueue", "TransferContactToQueue"}
_CALLBACK_ACTIONS = {"CreateCallback", "SetCallbackNumber"}
_RETURNING_CALLER_HINTS = (
    "previous",
    "returning",
    "repeat",
    "history",
    "contactid",
    "crm",
    "profile",
)


def _parse_flow(flow: ContactFlow) -> Optional[ContactFlowGraph]:
    if not flow.content or not isinstance(flow.content, dict):
        return None
    try:
        return _PARSER.parse(flow.content)
    except Exception:
        return None


class SelfServiceContainmentCheck(BaseCheck):
    """Analyze self-service vs. agent-routed paths in flows (Req 28)."""

    def __init__(self):
        super().__init__(
            check_id="cost-containment-001",
            name="Self-Service Containment Analysis",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.HIGH,
            description=(
                "Analyzes contact flows for self-service automation "
                "(IVR, bots, lookups) vs. direct agent routing to "
                "identify containment opportunities."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        zero_containment_flows = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            has_self_service = any(
                a.action_type in SELF_SERVICE_ACTION_TYPES for a in graph.actions.values()
            )
            has_queue = any(
                a.action_type in AGENT_ROUTING_ACTION_TYPES for a in graph.actions.values()
            )
            if has_queue and not has_self_service:
                zero_containment_flows.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                    }
                )

        evidence = {
            "flows_analyzed": len(instance.contact_flows),
            "zero_containment_count": len(zero_containment_flows),
        }

        if zero_containment_flows:
            evidence["zero_containment_flows"] = zero_containment_flows[:10]
            evidence["agent_handled_cost_per_contact_usd"] = AGENT_HANDLED_COST_AVG
            flow_names = ", ".join(f"`{f['flow']}`" for f in zero_containment_flows[:5])
            more_note = (
                f" (+{len(zero_containment_flows) - 5} more)"
                if len(zero_containment_flows) > 5
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(zero_containment_flows)} flow(s) route directly "
                    "to agents without a detected self-service step:** "
                    f"{flow_names}{more_note}.\n\n"
                    "The evidence records an industry-average agent-handled "
                    f"cost of ${AGENT_HANDLED_COST_AVG:.2f} per contact as a "
                    "prioritization reference, not a measured saving. Connect "
                    "does not expose per-flow volume here, so validate traffic "
                    "and actual handling cost before estimating monthly impact."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Add self-service automation before agent routing.",
                    target_resources=[f["flow_id"] for f in zero_containment_flows[:5]],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each flagged flow, add at least one "
                                "automation step (Lex bot for FAQ deflection, "
                                "Lambda for account lookup, or DTMF menu) "
                                "before the queue transfer."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Add an Amazon Lex bot to a flow",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/amazon-lex.html",  # noqa: E501
                        )
                    ],
                    applies_if="call volume justifies automation investment.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description="All queue-routing flows include self-service steps.",
            evidence=evidence,
        )


class QueueWaitTimeCheck(BaseCheck):
    """Detect high wait times without callback offering (Req 29)."""

    def __init__(self):
        super().__init__(
            check_id="cost-wait-time-001",
            name="Queue Wait Time / Callback Opportunity",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.HIGH,
            description=(
                "Checks whether flows that route to queues offer a callback "
                "option, reducing hold-time telephony costs."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        queues_without_callback = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            has_queue = any(
                a.action_type in _QUEUE_TRANSFER_ACTIONS for a in graph.actions.values()
            )
            has_callback = any(a.action_type in _CALLBACK_ACTIONS for a in graph.actions.values())
            if has_queue and not has_callback:
                queues_without_callback.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                    }
                )

        evidence = {
            "flows_analyzed": len(instance.contact_flows),
            "flows_missing_callback": len(queues_without_callback),
        }

        if queues_without_callback:
            evidence["details"] = queues_without_callback[:10]
            evidence["telephony_cost_per_hold_minute_usd"] = TELEPHONY_PER_MINUTE
            flow_names = ", ".join(f"`{f['flow']}`" for f in queues_without_callback[:5])
            more_note = (
                f" (+{len(queues_without_callback) - 5} more)"
                if len(queues_without_callback) > 5
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(queues_without_callback)} flow(s) transfer callers "
                    "to a queue without a detected callback option:** "
                    f"{flow_names}{more_note}.\n\n"
                    "An inbound caller on hold remains a billed telephony "
                    f"minute (approximately ${TELEPHONY_PER_MINUTE}/minute "
                    "for the documented US reference rate). The avoidable "
                    "amount depends on actual queue wait time, region, number "
                    "type, and callback behavior; validate those metrics before "
                    "claiming savings."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Add callback offering before queue transfers.",
                    target_resources=[f["flow_id"] for f in queues_without_callback[:5]],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Before each TransferToQueue, add a "
                                "GetParticipantInput that offers 'Press 1 for "
                                "a callback' and wire it to a CreateCallback "
                                "action. This eliminates hold-time charges."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Set up queued callbacks",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/setup-queued-cb.html",  # noqa: E501
                        )
                    ],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description="All queue-routing flows include a callback offering.",
            evidence=evidence,
        )


class AgentOccupancyCheck(BaseCheck):
    """Agent occupancy / staffing efficiency indicators (Req 30)."""

    def __init__(self):
        super().__init__(
            check_id="cost-occupancy-001",
            name="Agent Occupancy / Staffing Efficiency",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.MEDIUM,
            description=(
                "Provides an informational check noting that agent occupancy "
                "metrics should be monitored for staffing cost efficiency."
            ),
        )

    def execute(self, context: CheckContext):
        # Occupancy requires historical real-time metrics (GetCurrentMetricData)
        # which need specific queue/routing-profile IDs. For MVP, surface as
        # a PASS with guidance to monitor.
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=context.instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                "Agent occupancy analysis requires historical real-time metrics; "
                "monitor via Connect dashboards and CloudWatch."
            ),
            evidence={
                "recommendation": (
                    "Set up CloudWatch alarms for agent idle time and "
                    "occupancy thresholds (< 40% = overstaffed, > 85% = understaffed)."
                )
            },
        )


class RepeatContactFCRCheck(BaseCheck):
    """Detect returning-caller detection logic in flows (Req 31)."""

    def __init__(self):
        super().__init__(
            check_id="cost-fcr-001",
            name="Repeat Contact / First Call Resolution Indicator",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.MEDIUM,
            description=(
                "Checks whether contact flows perform returning-caller "
                "detection to enable routing optimization and FCR tracking."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flows_with_detection = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                blob = (action.action_type + " " + str(action.parameters)).lower()
                if any(h in blob for h in _RETURNING_CALLER_HINTS):
                    flows_with_detection.append(flow.name)
                    break

        evidence = {
            "flows_analyzed": len(instance.contact_flows),
            "flows_with_returning_caller_detection": len(flows_with_detection),
        }

        if not flows_with_detection and len(instance.contact_flows) > 0:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    "No contact flow performs returning-caller detection; "
                    "repeat contacts cannot be identified or routed optimally."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Add returning-caller detection to inbound flows.",
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Add a Lambda or Check Attribute step at flow "
                                "entry that looks up the caller's previous "
                                "contact history via Connect Customer Profiles "
                                "or a CRM integration."
                            ),
                        ),
                    ],
                    applies_if="repeat contacts are a meaningful portion of volume.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"{len(flows_with_detection)} flow(s) include returning-caller detection logic."
            ),
            evidence=evidence,
        )


class AfterContactWorkCheck(BaseCheck):
    """Flag excessive after-contact work as a cost signal (Req 32)."""

    def __init__(self):
        super().__init__(
            check_id="cost-acw-001",
            name="After-Contact Work Duration",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.LOW,
            description=(
                "Notes that ACW duration should be monitored; excessive ACW "
                "increases cost per contact."
            ),
        )

    def execute(self, context: CheckContext):
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=context.instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                "ACW duration analysis requires per-queue historical metrics; "
                "monitor via Connect dashboards."
            ),
            evidence={
                "recommendation": (
                    "Track AfterContactWorkTime per queue. If average > 120s, "
                    "review agent disposition workflows."
                )
            },
        )


class IVRToAgentDataContinuityCheck(BaseCheck):
    """Detect IVR-collected data not persisted for agents (Req 40)."""

    def __init__(self):
        super().__init__(
            check_id="cost-data-continuity-001",
            name="IVR-to-Agent Data Continuity",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.MEDIUM,
            description=(
                "Checks whether data the IVR already collected from the "
                "caller (DTMF digits, Lex bot slots, a Lambda account "
                "lookup) is saved as a contact attribute before the flow "
                "transfers to a queue. If it isn't, the agent's screen pop "
                "shows nothing and they re-ask the caller for information "
                "the flow already has — extra call time and a worse caller "
                "experience, on every call that reaches an agent."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        flagged_flows = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue

            inputs_collected = 0
            attrs_set = 0
            has_queue = False

            for action in graph.actions.values():
                if action.action_type in _INPUT_COLLECTION_ACTIONS:
                    inputs_collected += 1
                if action.action_type in _ATTRIBUTE_SET_ACTIONS:
                    # Count individual attribute keys persisted, not actions.
                    attr_dict = action.parameters.get("Attributes", {})
                    if isinstance(attr_dict, dict):
                        attrs_set += len(attr_dict)
                if action.action_type in _QUEUE_TRANSFER_ACTIONS:
                    has_queue = True

            if has_queue and inputs_collected >= 3 and attrs_set < 2:
                flagged_flows.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                        "inputs_collected": inputs_collected,
                        "attributes_set": attrs_set,
                    }
                )

        evidence = {
            "flows_analyzed": len(instance.contact_flows),
            "flagged_count": len(flagged_flows),
        }

        if flagged_flows:
            evidence["flagged_flows"] = flagged_flows[:10]
            flow_lines = [
                f"* `{f['flow']}`: collects {f['inputs_collected']} input(s), "
                f"persists {f['attributes_set']} as attribute(s)"
                for f in flagged_flows[:3]
            ]
            more_note = (
                f"\n\n_+ {len(flagged_flows) - 3} additional flow(s); see "
                "JSON export for the full list._"
                if len(flagged_flows) > 3
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(flagged_flows)} flow(s) collect 3 or more pieces "
                    "of caller input in the IVR but save fewer than 2 of them "
                    "as contact attributes before transferring to a queue.**\n\n"
                    '**What this means in practice.** "Input collection" '
                    "here is any DTMF entry (Get customer input), Lex bot "
                    "slot, or Lambda lookup result the flow captures from "
                    "or about the caller — account number, reason for "
                    "calling, order number, whatever the IVR asked for. "
                    '"Persisting" means a Set contact attributes block '
                    "saves that value so it survives the transfer to an "
                    "agent. When a flow collects several of these but saves "
                    "almost none of them, the agent's screen pop is mostly "
                    "empty and they ask the caller to repeat information the "
                    "flow already has.\n\n"
                    "**Cost angle.** Every repeated question adds call "
                    "duration — multiplied across every call that reaches "
                    "an agent through one of these flows, that's a "
                    "recurring, measurable increase in average handle time.\n\n"
                    f"**Flagged flow(s):**\n\n{chr(10).join(flow_lines)}{more_note}"
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Persist IVR-collected data as contact attributes.",
                    target_resources=[f["flow_id"] for f in flagged_flows[:5]],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "After each input-collection step, add a "
                                "Set Contact Attributes action storing the "
                                "value. This appears in the agent's screen pop."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Use contact attributes",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-attrib-list.html",  # noqa: E501
                        )
                    ],
                    applies_if="agents currently re-ask questions the IVR already answered.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description="IVR-collected data is persisted before agent transfer.",
            evidence=evidence,
        )


_LEX_ACTION_TYPES = {"ConnectToLexBot", "ConnectParticipantWithLexBot"}
_INPUT_ACTION_TYPES = {
    "GetParticipantInput",
    "GetUserInput",
    "StoreCustomerInput",
    "StoreUserInput",
}
_LEX_PARAMETER_KEYS = {
    "botalias",
    "botaliasarn",
    "botaliasid",
    "botname",
    "lexbot",
    "lexv2bot",
}
_DTMF_PARAMETER_KEYS = {"maximumdigits", "maxdigits"}
_DTMF_TEXT_MARKERS = ("dtmf", "digit", "keypad", "press ", "enter ")
_MAX_ROUTE_DEPTH = 50
_MAX_QUEUE_ROUTES = 200
_MAX_ROUTE_STATES = 5000


def _nested_parameter_items(parameters: dict) -> list[tuple[str, object]]:
    """Return nested parameter keys and values without recursive traversal."""
    items: list[tuple[str, object]] = []
    stack: list[object] = [parameters]
    while stack:
        value = stack.pop()
        if isinstance(value, dict):
            for key in sorted(value, reverse=True):
                nested = value[key]
                items.append((str(key).casefold(), nested))
                stack.append(nested)
        elif isinstance(value, list):
            stack.extend(reversed(value))
    return items


def _is_lex_input(action: FlowAction) -> bool:
    if action.action_type in _LEX_ACTION_TYPES:
        return True
    if action.action_type not in {"GetParticipantInput", "GetUserInput"}:
        return False
    return any(
        key in _LEX_PARAMETER_KEYS and value not in (None, "", {}, [])
        for key, value in _nested_parameter_items(action.parameters or {})
    )


def _is_dtmf_input(action: FlowAction) -> bool:
    if action.action_type not in _INPUT_ACTION_TYPES or _is_lex_input(action):
        return False
    if action.action_type in {"StoreCustomerInput", "StoreUserInput"}:
        return True

    for key, value in _nested_parameter_items(action.parameters or {}):
        if key in _DTMF_PARAMETER_KEYS and value not in (None, ""):
            return True
        if key in {"inputmethod", "inputmode", "inputtype"}:
            mode = str(value).casefold()
            if any(marker in mode for marker in ("dtmf", "digit", "keypad")):
                return True
            if any(marker in mode for marker in ("speech", "voice")):
                return False
        if isinstance(value, str) and any(
            marker in value.casefold() for marker in _DTMF_TEXT_MARKERS
        ):
            return True
    return False


def _queue_routes(graph: ContactFlowGraph) -> tuple[list[list[str]], bool]:
    """Enumerate bounded simple entry-to-queue routes deterministically."""
    if not graph.actions or graph.entry_point_id not in graph.actions:
        return [], False

    routes: list[list[str]] = []
    stack: list[tuple[str, tuple[str, ...]]] = [(graph.entry_point_id, (graph.entry_point_id,))]
    states_explored = 0
    capped = False

    while stack:
        if states_explored >= _MAX_ROUTE_STATES or len(routes) >= _MAX_QUEUE_ROUTES:
            capped = True
            break
        action_id, path = stack.pop()
        states_explored += 1
        action = graph.actions[action_id]
        if action.action_type in AGENT_ROUTING_ACTION_TYPES:
            routes.append(list(path))
            continue

        targets = sorted(
            {
                transition.target_action_id
                for transition in action.all_transitions
                if transition.target_action_id in graph.actions
                and transition.target_action_id not in path
            },
            reverse=True,
        )
        if len(path) >= _MAX_ROUTE_DEPTH:
            capped = capped or bool(targets)
            continue
        for target_id in targets:
            stack.append((target_id, (*path, target_id)))

    routes.sort(key=lambda path: tuple(path))
    return routes, capped


class LegacySelfServiceTierCheck(BaseCheck):
    """Identify reachable DTMF-only routes to an agent queue."""

    def __init__(self):
        super().__init__(
            check_id="cost-self-service-tier-001",
            name="Legacy DTMF-Only Self-Service",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.LOW,
            description=(
                "Identifies reachable queue routes that use DTMF menu input without a Lex "
                "conversation on that same route. This is an opportunity flag, not a defect."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        customer_flows = sorted(
            (flow for flow in instance.contact_flows if not is_default_sample_flow(flow)),
            key=lambda flow: ((flow.name or "").casefold(), flow.id),
        )
        affected_routes = []
        skipped_flows = []
        capped_flows = []
        flows_analyzed = 0
        eligible_queue_routes = 0

        for flow in customer_flows:
            if not flow.content or not isinstance(flow.content, dict):
                skipped_flows.append(
                    {"flow": flow.name, "flow_id": flow.id, "reason": "flow content unavailable"}
                )
                continue
            graph = _parse_flow(flow)
            if graph is None:
                skipped_flows.append(
                    {"flow": flow.name, "flow_id": flow.id, "reason": "flow content parse failed"}
                )
                continue
            if graph.actions and graph.entry_point_id not in graph.actions:
                skipped_flows.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                        "reason": "entry action is missing or invalid",
                    }
                )
                continue

            flows_analyzed += 1
            routes, capped = _queue_routes(graph)
            if capped:
                capped_flows.append({"flow": flow.name, "flow_id": flow.id})
            eligible_queue_routes += len(routes)

            for route in routes:
                actions = [graph.actions[action_id] for action_id in route]
                dtmf_actions = [action for action in actions if _is_dtmf_input(action)]
                lex_actions = [action for action in actions if _is_lex_input(action)]
                if not dtmf_actions or lex_actions:
                    continue
                affected_routes.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                        "route_action_ids": route,
                        "dtmf_actions": [
                            {
                                "action_id": action.action_id,
                                "action_type": action.action_type,
                            }
                            for action in dtmf_actions
                        ],
                        "queue_action_id": route[-1],
                        "queue_action_type": actions[-1].action_type,
                    }
                )

        affected_routes.sort(
            key=lambda row: (
                str(row["flow"]).casefold(),
                str(row["flow_id"]),
                tuple(row["route_action_ids"]),
            )
        )
        affected_flow_ids = {str(row["flow_id"]) for row in affected_routes}
        limitations = []
        if skipped_flows:
            limitations.append(f"{len(skipped_flows)} flow(s) could not be analyzed")
        if capped_flows:
            limitations.append(f"route enumeration was capped for {len(capped_flows)} flow(s)")
        evidence = {
            "flows_discovered": len(instance.contact_flows),
            "customer_flows_discovered": len(customer_flows),
            "sample_flows_excluded": len(instance.contact_flows) - len(customer_flows),
            "flows_analyzed": flows_analyzed,
            "flows_skipped": len(skipped_flows),
            "skipped_flow_details": skipped_flows,
            "route_analysis_capped_flows": capped_flows,
            "eligible_reachable_queue_routes": eligible_queue_routes,
            "dtmf_only_route_count": len(affected_routes),
            "dtmf_only_flow_count": len(affected_flow_ids),
            "analysis_complete": not limitations,
            "limitations": limitations,
        }

        if affected_routes:
            evidence["details"] = affected_routes[:20]
            limitation_note = (
                " Analysis was additionally limited because " + "; ".join(limitations) + "."
                if limitations
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{len(affected_routes)} reachable queue route(s) across "
                    f"{len(affected_flow_ids)} flow(s) use DTMF input without a Lex "
                    "conversation on the same route.** Lex on another branch does not "
                    f"change the affected caller route.{limitation_note} Review the listed "
                    "DTMF actions and retain simple menus where they remain the right fit."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Evaluate conversational self-service on the listed DTMF-only routes.",
                    target_resources=[
                        action["action_id"]
                        for route in affected_routes[:10]
                        for action in route["dtmf_actions"]
                    ],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Review each listed route and consider Lex when free-form intent "
                                "handling would improve containment beyond a numbered menu."
                            ),
                            console_path="Connect console -> Routing -> Flows",
                        )
                    ],
                    references=[
                        RemediationReference(
                            title="Add an Amazon Lex bot to a flow",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/amazon-lex.html",  # noqa: E501
                        )
                    ],
                    applies_if="call volume and menu complexity justify the conversion effort.",
                ),
            )

        if limitations:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    "Self-service tier analysis was incomplete and cannot report PASS: "
                    + "; ".join(limitations)
                    + "."
                ),
                evidence=evidence,
            )

        if eligible_queue_routes == 0:
            return self.not_applicable(
                context,
                "no reachable customer-authored route transfers to an agent queue",
                resource_type="ContactFlow",
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"Analyzed {eligible_queue_routes} reachable queue route(s); none use DTMF "
                "input without a Lex conversation on that same route."
            ),
            evidence=evidence,
        )


def register_cost_containment_checks(registry) -> None:
    """Register all operational-intelligence cost checks."""
    registry.register_check(SelfServiceContainmentCheck())
    registry.register_check(QueueWaitTimeCheck())
    registry.register_check(AgentOccupancyCheck())
    registry.register_check(RepeatContactFCRCheck())
    registry.register_check(AfterContactWorkCheck())
    registry.register_check(IVRToAgentDataContinuityCheck())
    registry.register_check(LegacySelfServiceTierCheck())
