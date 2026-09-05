"""
Journey scoring — evaluates each caller path for security, containment,
resilience, and CX maturity gaps.
"""

import logging
from typing import Any, Dict, List

from ..models import (
    CheckStatus,
    Finding,
    Pillar,
    Remediation,
    RemediationStep,
    Severity,
)
from ..parsers.flow_patterns import (
    AUTHENTICATION_INDICATORS,
    PERSONALIZATION_INDICATORS,
    SELF_SERVICE_ACTION_TYPES,
)
from .models import JourneyMapResult, JourneyNode, JourneyPath, JourneyScore

logger = logging.getLogger("journey.scorer")

_CALLBACK_ACTIONS = {"CreateCallback", "SetCallbackNumber", "OfferCallback"}
_RETURNING_HINTS = ("returning", "previous", "history", "repeat", "last_call", "crm")


def _mask_number(number: str) -> str:
    """Mask a phone number for report evidence, preserving the last 4 digits.

    Evidence dicts are surfaced in the HTML/JSON report, so the full DID is
    reduced to a trailing fragment (e.g. ``***-***-1234``) — enough to identify
    which number triggered a finding without publishing the whole number.
    """
    if not number:
        return number
    digits = [c for c in number if c.isdigit()]
    if len(digits) < 4:
        return "***"
    return f"***-***-{''.join(digits[-4:])}"


def score_journeys(journeys: List[JourneyPath], config: Dict[str, Any]) -> Dict[str, JourneyScore]:
    """Score each journey path; return results keyed by path_hash."""
    scores: Dict[str, JourneyScore] = {}
    for journey in journeys:
        scores[journey.path_hash] = _score_single_path(journey)
    return scores


def _score_single_path(path: JourneyPath) -> JourneyScore:
    """Score a single journey path across all dimensions."""
    score = JourneyScore()

    for i, node in enumerate(path.nodes):
        # Security: authentication
        if not score.has_authentication and _matches_indicators(node, AUTHENTICATION_INDICATORS):
            score.has_authentication = True
            score.auth_position = i

        # Self-service
        if node.action_type in SELF_SERVICE_ACTION_TYPES:
            score.has_self_service = True
            score.self_service_actions.append(node.action_id)

        # Callback
        if node.action_type in _CALLBACK_ACTIONS:
            score.has_callback_offering = True

        # Personalization
        if not score.has_personalization and _matches_indicators(node, PERSONALIZATION_INDICATORS):
            score.has_personalization = True

        # NLU / Bot
        if node.action_type in ("ConnectParticipantWithLexBot", "ConnectToLexBot"):
            score.has_nlu_bot = True

        # Returning caller detection
        if not score.has_returning_caller_detection:
            if node.action_type in (
                "CheckContactAttributes",
                "CheckAttribute",
                "InvokeLambdaFunction",
            ):
                blob = str(node.parameters).lower()
                if any(h in blob for h in _RETURNING_HINTS):
                    score.has_returning_caller_detection = True

        # Dynamic prompt
        if not score.has_dynamic_prompt:
            if node.action_type in ("MessageParticipant", "PlayPrompt"):
                text = str(node.parameters.get("Text", ""))
                if "$." in text:
                    score.has_dynamic_prompt = True

    # CX maturity
    cx = score.cx_feature_count
    if cx >= 4:
        score.cx_maturity = "Advanced"
    elif cx >= 2:
        score.cx_maturity = "Intermediate"
    else:
        score.cx_maturity = "Basic"

    # Deficiencies
    if not score.has_authentication and path.terminal_type == "agent_queue":
        score.deficiencies.append("🔓 No authentication before agent queue")
    if not score.has_self_service:
        score.deficiencies.append("💰 No self-service automation")
    if not score.has_callback_offering and path.terminal_type == "agent_queue":
        score.deficiencies.append("📞 No callback offering before queue")
    if not score.has_personalization:
        score.deficiencies.append("👤 No personalization")
    if path.terminal_type == "disconnect" and path.terminal_details.get("reason") == "dead_end":
        score.deficiencies.append("⚠️ Dead-end disconnect")

    return score


def _matches_indicators(node: JourneyNode, indicators: Dict[str, List[str]]) -> bool:
    hints = indicators.get(node.action_type)
    if not hints:
        return False
    blob = (node.action_type + " " + str(node.parameters)).lower()
    return any(h in blob for h in hints)


def generate_journey_findings(result: JourneyMapResult) -> List[Finding]:
    """Produce Finding objects from scored journey results."""
    findings: List[Finding] = []

    # Group journeys by entry number for per-DID analysis.
    by_number: Dict[str, List[JourneyPath]] = {}
    for j in result.journeys:
        by_number.setdefault(j.entry_number, []).append(j)

    for number, paths in by_number.items():
        # Security: any path to queue without auth?
        unauthed_queue_paths = [
            p
            for p in paths
            if p.terminal_type == "agent_queue"
            and not result.scores.get(p.path_hash, JourneyScore()).has_authentication
        ]
        if unauthed_queue_paths:
            p = unauthed_queue_paths[0]
            findings.append(
                Finding(
                    check_id="journey-sec-001",
                    check_name="Journey Reaches Agent Queue Without Authentication",
                    pillar=Pillar.SECURITY,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    resource_id=number,
                    resource_type="PhoneNumberJourney",
                    description=(
                        f"Caller journey from {number} reaches queue "
                        f"'{p.terminal_details.get('queue', 'unknown')}' without "
                        f"any authentication step ({len(unauthed_queue_paths)} path(s))."
                    ),
                    remediation="Insert caller authentication before routing to agent queue.",
                    evidence={
                        "phone_number": _mask_number(number),
                        "unauthed_paths": len(unauthed_queue_paths),
                        "first_path_flows": p.flows_traversed,
                    },
                    structured_remediation=Remediation(
                        summary=f"Insert auth in flow '{p.nodes[0].flow_name}' before queue transfer.",
                        target_resources=[number, p.nodes[0].flow_name],
                        steps=[
                            RemediationStep(
                                order=1,
                                instruction=(
                                    f"Add a Lambda verification or DTMF PIN step in "
                                    f"flow '{p.nodes[0].flow_name}' before the "
                                    f"TransferToQueue action."
                                ),
                            ),
                        ],
                    ),
                )
            )

        # Containment: zero self-service?
        no_ss_paths = [
            p for p in paths if not result.scores.get(p.path_hash, JourneyScore()).has_self_service
        ]
        if len(no_ss_paths) == len(paths) and paths:
            findings.append(
                Finding(
                    check_id="journey-cost-001",
                    check_name="Zero Self-Service Paths",
                    pillar=Pillar.COST_OPTIMIZATION,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    resource_id=number,
                    resource_type="PhoneNumberJourney",
                    description=(
                        f"All {len(paths)} journey path(s) from {number} route to "
                        f"agents without any self-service automation."
                    ),
                    remediation="Add self-service options (Lex bot, DTMF menu, Lambda lookup).",
                    evidence={
                        "phone_number": _mask_number(number),
                        "total_paths": len(paths),
                        "containment_score": result.containment_scores.get(number, 0),
                    },
                    structured_remediation=Remediation(
                        summary=f"Add self-service automation to flow '{paths[0].nodes[0].flow_name}'.",
                        target_resources=[number, paths[0].nodes[0].flow_name],
                        steps=[
                            RemediationStep(
                                order=1,
                                instruction=(
                                    "Add a Lex bot or DTMF menu before the queue "
                                    "transfer to deflect common requests."
                                ),
                            ),
                        ],
                    ),
                )
            )

        # Resilience: dead-end paths?
        dead_ends = [
            p
            for p in paths
            if p.terminal_type == "disconnect" and p.terminal_details.get("reason") == "dead_end"
        ]
        if dead_ends:
            findings.append(
                Finding(
                    check_id="journey-res-001",
                    check_name="Dead-End Caller Path",
                    pillar=Pillar.RESILIENCE,
                    severity=Severity.HIGH,
                    status=CheckStatus.FAIL,
                    resource_id=number,
                    resource_type="PhoneNumberJourney",
                    description=(
                        f"{len(dead_ends)} path(s) from {number} end in a dead-end "
                        f"disconnect with no agent/callback/bot option."
                    ),
                    remediation="Replace dead-end disconnects with callback or queue transfer.",
                    evidence={
                        "phone_number": _mask_number(number),
                        "dead_end_count": len(dead_ends),
                    },
                    structured_remediation=Remediation(
                        summary="Replace dead-end disconnects with fallback routing.",
                        target_resources=[number],
                        steps=[
                            RemediationStep(
                                order=1,
                                instruction=(
                                    "Add a callback offer or overflow queue before "
                                    "the DisconnectParticipant action."
                                ),
                            ),
                        ],
                    ),
                )
            )

    # Dormant flows finding.
    if len(result.dormant_flows) > 5:
        findings.append(
            Finding(
                check_id="journey-scope-001",
                check_name="Dormant Flows Detected",
                pillar=Pillar.COST_OPTIMIZATION,
                severity=Severity.LOW,
                status=CheckStatus.FAIL,
                resource_id="instance",
                resource_type="ConnectInstance",
                description=(
                    f"{len(result.dormant_flows)} flows have zero traffic and no phone "
                    "number association — consider deleting unused flows."
                ),
                remediation="Review and delete dormant flows to reduce clutter.",
                evidence={"dormant_flow_count": len(result.dormant_flows)},
            )
        )

    return findings
