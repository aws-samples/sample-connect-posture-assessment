"""
Contact flow behavior checks (Phase 5 / Task 11).

These checks wrap the parser's graph/pattern functions into assessment findings:

- sec-flow-auth-001       : Authentication pattern detection (Req 5)
- cx-personalization-001  : Personalization & transfer analysis (Req 6)
- res-flow-errors-001     : Error handling completeness (Req 3)
- res-flow-loops-001      : Unbounded loop detection (Req 4)
"""

from typing import Optional

from ..models import (
    CheckStatus,
    ContactFlow,
    ContactFlowGraph,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from ..parsers import (
    ContactFlowParser,
    detect_cycles,
    is_default_sample_flow,
    reachable_from_entry,
)
from ..parsers.flow_patterns import (
    AGENT_ROUTING_ACTION_TYPES,
    detect_authentication,
    detect_personalization,
    detect_transfers,
)
from .base import BaseCheck, CheckContext

_PARSER = ContactFlowParser()

# Action types that can produce an error transition.
_ERROR_CAPABLE_TYPES = {
    "InvokeLambdaFunction",
    "ConnectToLexBot",
    "ConnectParticipantWithLexBot",
    "TransferToQueue",
    "TransferContactToQueue",
    "TransferContactToPhoneNumber",
    "TransferToPhoneNumber",
    "GetParticipantInput",
    "GetUserInput",
    "StoreUserInput",
    "InvokeFlowModule",
}


def _parse_flow(flow: ContactFlow) -> Optional[ContactFlowGraph]:
    if not flow.content or not isinstance(flow.content, dict):
        return None
    try:
        return _PARSER.parse(flow.content)
    except Exception:
        return None


class AuthenticationPatternCheck(BaseCheck):
    """Detect whether customer-authored flows implement caller authentication (Req 5)."""

    def __init__(self):
        super().__init__(
            check_id="sec-flow-auth-001",
            name="Contact Flow Authentication Pattern",
            pillar=Pillar.SECURITY,
            severity=Severity.LOW,
            description=(
                "Notes contact flows that route to agent queues without an "
                "upstream caller-authentication step. Authentication is "
                "optional and depends on your business requirements — many "
                "flows legitimately route to agents with no identity check "
                "at all (general inquiries, sales, anything not touching an "
                "account). This is only worth acting on for flows that "
                "expose sensitive account operations."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        unprotected = []
        # AWS's default sample flows (see is_default_sample_flow) route to
        # queues to demonstrate the pattern, not because they front a real
        # account operation — flagging them would just report on AWS's own
        # demo content. Reviewer feedback: exclude them and only look at
        # customer-authored flows.
        customer_flows = [f for f in instance.contact_flows if not is_default_sample_flow(f)]

        for flow in customer_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            has_queue = any(
                a.action_type in AGENT_ROUTING_ACTION_TYPES for a in graph.actions.values()
            )
            auth_patterns = detect_authentication(graph)
            if has_queue and not auth_patterns:
                unprotected.append({"flow": flow.name, "flow_id": flow.id})

        evidence = {
            "flows_analyzed": len(customer_flows),
            "sample_flows_excluded": len(instance.contact_flows) - len(customer_flows),
            "unprotected_count": len(unprotected),
        }

        if unprotected:
            evidence["unprotected_flows"] = unprotected[:10]
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{len(unprotected)} customer-authored flow(s) route to "
                    "agents without an upstream caller-authentication step "
                    "(AWS's default sample flows are excluded from this "
                    "count).\n\n"
                    "**This is optional, not a requirement.** Whether a flow "
                    "needs caller authentication depends entirely on what "
                    "happens once the caller reaches an agent. A flow "
                    "routing to a general sales or support queue has no "
                    "reason to authenticate the caller first. The cases "
                    "worth reviewing are flows where the agent can pull up "
                    "or act on account-specific, financial, or otherwise "
                    "sensitive information — for those, verify identity "
                    "(PIN, account lookup, DTMF challenge) before the queue "
                    "transfer so the agent isn't handing out account details "
                    "to an unverified caller."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        "Review the flagged flows and add authentication "
                        "only to the ones that expose account-specific or "
                        "sensitive operations."
                    ),
                    target_resources=[f["flow_id"] for f in unprotected[:5]],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each flagged flow, confirm whether the "
                                "destination queue's agents can access "
                                "account-specific, financial, or otherwise "
                                "sensitive caller information. If not (general "
                                "inquiries, sales), no change is needed."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "For flows that do expose sensitive "
                                "operations, add a Lambda-based "
                                "authentication step (account + PIN "
                                "verification) or DTMF collection before the "
                                "queue transfer."
                            ),
                        ),
                    ],
                    applies_if="the destination queue's agents can access sensitive account operations.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description="All queue-routing, customer-authored flows include authentication patterns.",
            evidence=evidence,
        )


class PersonalizationAnalysisCheck(BaseCheck):
    """Detect personalization patterns and transfer complexity (Req 6)."""

    def __init__(self):
        super().__init__(
            check_id="cx-personalization-001",
            name="Personalization & Transfer Analysis",
            pillar=Pillar.SECURITY,
            severity=Severity.LOW,
            description=(
                "Summarizes personalization patterns and transfer types "
                "per contact flow for CX quality evaluation."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        summary = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            pers = detect_personalization(graph)
            transfers = detect_transfers(graph)
            if pers or transfers:
                summary.append(
                    {
                        "flow": flow.name,
                        "personalization_patterns": len(pers),
                        "transfer_count": len(transfers),
                        "transfer_types": list(
                            {t.details.get("transfer_type", "unknown") for t in transfers}
                        ),
                    }
                )

        evidence = {
            "flows_analyzed": len(instance.contact_flows),
            "flows_with_patterns": len(summary),
            "details": summary[:10],
        }

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"Personalization/transfer analysis complete for "
                f"{len(instance.contact_flows)} flow(s)."
            ),
            evidence=evidence,
        )


class ErrorHandlingCompletenessCheck(BaseCheck):
    """Detect missing error branches in contact flows (Req 3)."""

    def __init__(self):
        super().__init__(
            check_id="res-flow-errors-001",
            name="Contact Flow Error Handling Completeness",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "Checks that error-capable actions in contact flows have "
                "defined error transitions to prevent dead-end paths."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        worst_flow = None
        worst_ratio = 0.0
        # Aggregate stats surface in the PASS description so readers see
        # what was actually checked, not just "within thresholds".
        flows_with_error_capable_actions = 0
        flows_fully_covered = 0
        total_error_capable = 0
        total_missing = 0

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            error_capable = [
                a for a in graph.actions.values() if a.action_type in _ERROR_CAPABLE_TYPES
            ]
            if not error_capable:
                continue
            flows_with_error_capable_actions += 1
            missing = [a for a in error_capable if not a.error_transitions]
            total_error_capable += len(error_capable)
            total_missing += len(missing)
            ratio = len(missing) / len(error_capable)
            if len(missing) == 0:
                flows_fully_covered += 1
            if ratio > worst_ratio:
                worst_ratio = ratio
                worst_flow = {
                    "flow": flow.name,
                    "flow_id": flow.id,
                    "error_capable_count": len(error_capable),
                    "missing_error_count": len(missing),
                    "missing_action_ids": [a.action_id for a in missing[:10]],
                }

        evidence = {
            "flows_analyzed": len(instance.contact_flows),
            "flows_with_error_capable_actions": flows_with_error_capable_actions,
            "flows_fully_covered": flows_fully_covered,
            "total_error_capable_actions": total_error_capable,
            "total_missing_error_branches": total_missing,
            "worst_flow_missing_ratio": round(worst_ratio, 3),
            "fail_threshold": 0.20,
        }

        if worst_flow and worst_ratio > 0.20:
            evidence.update(worst_flow)
            missing_id_list = ", ".join(f"`{a}`" for a in worst_flow["missing_action_ids"][:5])
            more_ids = (
                f" (+ {worst_flow['missing_error_count'] - 5} more)"
                if worst_flow["missing_error_count"] > 5
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**Flow `{worst_flow['flow']}` has "
                    f"{worst_flow['missing_error_count']} of "
                    f"{worst_flow['error_capable_count']} error-capable "
                    "actions with no Error branch defined** — "
                    f"{worst_ratio:.0%} of them, above the 20% threshold "
                    "this check applies.\n\n"
                    "**What an error-capable action is.** Any flow block "
                    "that can hit a runtime problem (Invoke Lambda times "
                    "out, Get customer input hits a Lex 5xx, Transfer to "
                    "queue fails, Check hours of operation can't reach the "
                    "config). The block has two exit paths in the visual "
                    "designer: the default arrow, and a red **Error** arrow. "
                    "When the Error arrow is left unconnected, that path "
                    "becomes a dead end at runtime.\n\n"
                    "**What the caller experiences.** When the block fails "
                    "and there's no Error branch, Amazon Connect has "
                    "nowhere to send the contact. The result is usually "
                    "one of: (1) the caller hears silence for a few "
                    "seconds and then the line drops; (2) the contact "
                    "shows up as `Disconnect` in the CTR with no "
                    "resolution; (3) the caller phones back and hits the "
                    "same trap. None of it looks like an outage from your "
                    "side — the flow just quietly disconnected people.\n\n"
                    f"**Actions in `{worst_flow['flow']}` missing an "
                    f"Error branch:** {missing_id_list}{more_ids}\n\n"
                    "**How to fix.** For each flagged action, open the "
                    "flow in the Connect designer, drag the **Error** "
                    "output to somewhere useful. A minimum viable pattern "
                    'is: Error → *Play prompt* ("Sorry, something went '
                    'wrong on our side") → *Transfer to queue* (a '
                    "generic support queue). A better pattern is a "
                    "reusable **error-handling flow module** that every "
                    "flow's Error branches point to — one place to update "
                    "apology text, one place to change the fallback "
                    "queue."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        f"Wire up the Error branch on {worst_flow['missing_error_count']} "
                        f"action(s) in `{worst_flow['flow']}` so failures don't dead-end callers."
                    ),
                    target_resources=worst_flow["missing_action_ids"][:5],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Open the flow in the Connect designer. "
                                "Each flagged action has an unconnected "
                                "red Error output — connect it to a Play "
                                "prompt block that apologizes, then to a "
                                "Transfer to queue that routes to a "
                                "human agent."
                            ),
                            console_path="Connect console -> Routing -> Flows",
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "For instances with many flows, extract "
                                "the apology-and-transfer sequence into a "
                                "Flow Module and point every flow's "
                                "Error branches at that module. Saves "
                                "duplicated logic and gives you one place "
                                "to change the fallback behavior."
                            ),
                            console_path=("Connect console -> Routing -> Flow modules"),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Contact flow error handling actions",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/contact-flow-actions.html",  # noqa: E501
                        ),
                        RemediationReference(
                            title="Reusable flow modules",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/contact-flow-modules.html",  # noqa: E501
                        ),
                    ],
                ),
            )

        # PASS description tells the reader exactly what was checked and
        # what the numbers look like — no more vague "within thresholds".
        if flows_with_error_capable_actions == 0:
            description = (
                f"No flows on this instance contain error-capable actions "
                f"(InvokeLambdaFunction, GetUserInput, etc.), so there was "
                f"nothing to audit for error-branch coverage. "
                f"{len(instance.contact_flows)} flow(s) analyzed."
            )
        elif worst_flow is None or worst_ratio == 0.0:
            description = (
                f"Every error-capable action across "
                f"{flows_with_error_capable_actions} flow(s) has an error "
                f"branch defined ({total_error_capable} action(s) checked "
                f"in total)."
            )
        else:
            description = (
                f"{flows_fully_covered} of {flows_with_error_capable_actions} "
                f"flow(s) have complete error-branch coverage. "
                f"Worst flow: '{worst_flow['flow']}' — "
                f"{worst_flow['missing_error_count']}/"
                f"{worst_flow['error_capable_count']} error-capable actions "
                f"missing an error branch ({worst_ratio:.0%}, below the 20% "
                f"threshold that would fail this check)."
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=description,
            evidence=evidence,
        )


class LoopDetectionCheck(BaseCheck):
    """Detect unbounded loops in contact flows (Req 4)."""

    def __init__(self):
        super().__init__(
            check_id="res-flow-loops-001",
            name="Contact Flow Loop Detection",
            pillar=Pillar.RESILIENCE,
            severity=Severity.MEDIUM,
            description=(
                "Detects infinite-loop patterns in contact flows that could "
                "trap callers in unbounded cycles."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        unbounded_flows = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            cycles = detect_cycles(graph)
            unbounded = [c for c in cycles if not c.has_bounded_exit]
            if unbounded:
                unbounded_flows.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                        "unbounded_cycles": len(unbounded),
                        "cycle_actions": unbounded[0].cycle_actions[:10],
                    }
                )

        evidence = {
            "flows_analyzed": len(instance.contact_flows),
            "flows_with_unbounded_loops": len(unbounded_flows),
        }

        if unbounded_flows:
            evidence["details"] = unbounded_flows[:5]
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{len(unbounded_flows)} flow(s) contain unbounded loops "
                    "that could trap callers indefinitely."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Add exit conditions to unbounded loops.",
                    target_resources=[f["flow_id"] for f in unbounded_flows[:5]],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Add a loop counter (Set Attribute + Compare) "
                                "or a timeout to each detected cycle so callers "
                                "exit after a bounded number of iterations."
                            ),
                        ),
                    ],
                ),
            )

        # PASS description in plain language: what a "loop" is in a Connect
        # flow, what "unbounded" means, and why it matters — not everyone
        # reading this is a contact-flow author.
        analyzed = evidence["flows_analyzed"]
        description = (
            f"Analyzed {analyzed} contact flow(s) for looping patterns "
            "where an action's transition targets an earlier action in the "
            "same flow. None of your flows contain an unbounded loop — "
            "every cycle we found either has a counter that increments "
            "each pass, a timeout, or a caller-input branch that lets the "
            "loop exit. Unbounded loops matter because a caller who hits "
            "one is trapped inside the flow (no agent transfer, no "
            "disconnect), which drives up telephony charges and CSAT "
            "complaints. Nothing to fix here."
        )
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=description,
            evidence=evidence,
        )


class UnreachableActionsCheck(BaseCheck):
    """Detect customer-authored flow actions that have no path from the entry point."""

    def __init__(self):
        super().__init__(
            check_id="ops-unreachable-blocks-001",
            name="Unreachable Contact Flow Blocks",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            severity=Severity.LOW,
            description=(
                "Walks every default, conditional, and error transition from each "
                "contact flow entry point and identifies authored blocks that no caller "
                "path can reach."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        customer_flows = sorted(
            (flow for flow in instance.contact_flows if not is_default_sample_flow(flow)),
            key=lambda flow: ((flow.name or "").casefold(), flow.id),
        )
        skipped_flows = []
        flagged_flows = []
        analyzed = 0

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
            if not graph.actions:
                skipped_flows.append(
                    {"flow": flow.name, "flow_id": flow.id, "reason": "flow has no actions"}
                )
                continue
            if graph.entry_point_id not in graph.actions:
                skipped_flows.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                        "reason": "entry action is missing or invalid",
                    }
                )
                continue

            analyzed += 1
            reachable = reachable_from_entry(graph)
            unreachable_ids = sorted(set(graph.actions) - reachable)
            if unreachable_ids:
                flagged_flows.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                        "unreachable_count": len(unreachable_ids),
                        "unreachable_actions": [
                            {
                                "action_id": action_id,
                                "action_type": graph.actions[action_id].action_type,
                            }
                            for action_id in unreachable_ids
                        ],
                    }
                )

        flagged_flows.sort(
            key=lambda row: (
                -int(row["unreachable_count"]),
                str(row["flow"]).casefold(),
                str(row["flow_id"]),
            )
        )
        total_unreachable = sum(int(row["unreachable_count"]) for row in flagged_flows)
        evidence = {
            "flows_discovered": len(instance.contact_flows),
            "customer_flows_discovered": len(customer_flows),
            "sample_flows_excluded": len(instance.contact_flows) - len(customer_flows),
            "flows_analyzed": analyzed,
            "flows_skipped": len(skipped_flows),
            "skipped_flow_details": skipped_flows,
            "flows_with_unreachable_blocks": len(flagged_flows),
            "total_unreachable_actions": total_unreachable,
            "analysis_complete": not skipped_flows,
        }

        if flagged_flows:
            evidence["details"] = flagged_flows[:10]
            limitations = (
                f" Analysis was incomplete for {len(skipped_flows)} additional flow(s); "
                "see skipped_flow_details."
                if skipped_flows
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"**{total_unreachable} action(s) across {len(flagged_flows)} "
                    "customer-authored flow(s) have no path from the flow entry point.** "
                    "The analysis followed default, conditional, and error transitions."
                    f"{limitations} Open each listed flow and reconnect an intentionally "
                    "retained block or remove stale dead-code blocks."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Reconnect or remove unreachable contact flow blocks.",
                    target_resources=[
                        action["action_id"]
                        for flow in flagged_flows[:5]
                        for action in flow["unreachable_actions"][:3]
                    ],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Open each listed flow in the Connect designer. Reconnect blocks "
                                "that belong on a caller path, or delete blocks left behind by an edit."
                            ),
                            console_path="Connect console -> Routing -> Flows",
                        )
                    ],
                ),
            )

        if skipped_flows:
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"Unreachable-block analysis was incomplete: {analyzed} flow(s) were "
                    f"analyzed and {len(skipped_flows)} were skipped. A PASS cannot be "
                    "reported until every discovered customer flow has usable content and "
                    "a valid entry action."
                ),
                evidence=evidence,
            )

        if analyzed == 0:
            return self.not_applicable(
                context,
                "no customer-authored contact flow with actions was available to analyze",
                resource_type="ContactFlow",
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"Every action in {analyzed} analyzed customer-authored contact flow(s) is "
                "reachable from its flow entry point."
            ),
            evidence=evidence,
        )


def register_contact_flow_behavior_checks(registry) -> None:
    """Register all contact-flow behavior checks."""
    registry.register_check(AuthenticationPatternCheck())
    registry.register_check(PersonalizationAnalysisCheck())
    registry.register_check(ErrorHandlingCompletenessCheck())
    registry.register_check(LoopDetectionCheck())
    registry.register_check(UnreachableActionsCheck())
