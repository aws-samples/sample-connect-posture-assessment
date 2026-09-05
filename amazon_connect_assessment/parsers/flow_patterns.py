"""
Behavioral pattern detection over a parsed ``ContactFlowGraph``.

Detects authentication, personalization, transfer, and self-service patterns.
Indicator dictionaries are module-level and overridable so detection rules can
evolve independently of the check logic that consumes them.
"""

from typing import Dict, List

from ..models import ContactFlow, ContactFlowGraph, FlowAction, FlowPattern

# Amazon Connect creates a set of default sample flows in every new
# instance to demonstrate common patterns (A/B testing, queued callback,
# secure input, Lambda integration, recording behavior, etc.) — see
# https://docs.aws.amazon.com/connect/latest/adminguide/contact-flow-samples.html.
# Every one of these ships with a name starting with "Sample " (confirmed
# against the current AWS documentation's flow list: "Sample inbound
# flow", "Sample flow ... for A/B contact distribution testing", "Sample
# queued callback flow", "Sample Lambda integration flow", "Sample
# recording behavior", "Sample secure customer data entry input ...",
# etc). They are not customer-authored, are not meant to be used
# unmodified in production, and are usually still present (unclaimed and
# unpublished) even in accounts that never touch them — flagging them for
# customer-facing findings like hardcoded routing or missing
# authentication produces noise about AWS's own demo content rather than
# the customer's actual configuration.
_SAMPLE_FLOW_NAME_PREFIX = "sample "


def is_default_sample_flow(flow: ContactFlow) -> bool:
    """
    True if ``flow`` is one of Amazon Connect's built-in default sample
    flows rather than a customer-authored flow.

    Best-effort name-prefix match — Connect does not expose a
    machine-readable "is this a sample flow" field via the API, so this
    is the same signal a human reviewer uses (the flows literally show up
    named "Sample ..." in the flow list). A customer flow that happens to
    start with the word "Sample" would be a false exclusion, but that's
    an unlikely naming choice and errs toward not flagging AWS's own demo
    content as a customer defect.
    """
    return (flow.name or "").strip().lower().startswith(_SAMPLE_FLOW_NAME_PREFIX)


# Action types that constitute "self-service" automation (no live agent).
SELF_SERVICE_ACTION_TYPES = {
    "GetParticipantInput",
    "GetUserInput",
    "StoreUserInput",
    "InvokeLambdaFunction",
    "ConnectParticipantWithLexBot",
    "ConnectToLexBot",
    "MessageParticipant",
    "PlayPrompt",
    "PlayAudio",
}

# Action types that route a contact to a human agent queue.
AGENT_ROUTING_ACTION_TYPES = {
    "TransferToQueue",
    "TransferContactToQueue",
}

# Transfer action types by classification.
TRANSFER_ACTION_TYPES = {
    "TransferToQueue": "queue",
    "TransferContactToQueue": "queue",
    "TransferToFlow": "flow",
    "TransferContactToFlow": "flow",
    "TransferContactToPhoneNumber": "phone_number",
    "TransferToPhoneNumber": "phone_number",
}

# Substring hints (case-insensitive) keyed by the action type they apply to.
# These are DETECTION patterns for spotting authentication/PII collection in a
# customer's flows — not example attribute names to adopt. When SSN/DOB/PIN
# patterns are detected, the finding should prompt a compliance review
# (HIPAA for healthcare, PCI-DSS for payment, GDPR for EU personal data).
AUTHENTICATION_INDICATORS: Dict[str, List[str]] = {
    "InvokeLambdaFunction": ["auth", "verify", "validate", "authenticate", "identity"],
    "GetParticipantInput": ["pin", "ssn", "account", "dob", "passcode", "password"],
    "GetUserInput": ["pin", "ssn", "account", "dob", "passcode", "password"],
    "CheckContactAttributes": ["authenticated", "verified"],
    "CheckAttribute": ["authenticated", "verified"],
}

PERSONALIZATION_INDICATORS: Dict[str, List[str]] = {
    "CheckContactAttributes": ["language", "vip", "tier", "segment", "preference"],
    "CheckAttribute": ["language", "vip", "tier", "segment", "preference"],
    "InvokeLambdaFunction": ["lookup", "profile", "customer", "personalize", "crm"],
    "UpdateContactAttributes": ["language", "vip", "tier", "segment"],
}


def _matches(action: FlowAction, indicators: Dict[str, List[str]]) -> bool:
    hints = indicators.get(action.action_type)
    if not hints:
        return False
    blob = (action.action_type + " " + str(action.parameters)).lower()
    return any(h in blob for h in hints)


def detect_authentication(graph: ContactFlowGraph) -> List[FlowPattern]:
    matched = [
        a.action_id for a in graph.actions.values() if _matches(a, AUTHENTICATION_INDICATORS)
    ]
    if not matched:
        return []
    return [FlowPattern(pattern_type="authentication", action_ids=matched)]


def detect_personalization(graph: ContactFlowGraph) -> List[FlowPattern]:
    matched = [
        a.action_id for a in graph.actions.values() if _matches(a, PERSONALIZATION_INDICATORS)
    ]
    if not matched:
        return []
    return [FlowPattern(pattern_type="personalization", action_ids=matched)]


def detect_transfers(graph: ContactFlowGraph) -> List[FlowPattern]:
    patterns: List[FlowPattern] = []
    for action in graph.actions.values():
        kind = TRANSFER_ACTION_TYPES.get(action.action_type)
        if kind:
            patterns.append(
                FlowPattern(
                    pattern_type="transfer",
                    action_ids=[action.action_id],
                    details={"transfer_type": kind},
                )
            )
    return patterns


def detect_self_service(graph: ContactFlowGraph) -> List[FlowPattern]:
    matched = [
        a.action_id for a in graph.actions.values() if a.action_type in SELF_SERVICE_ACTION_TYPES
    ]
    if not matched:
        return []
    return [FlowPattern(pattern_type="self_service", action_ids=matched)]


def detect_patterns(graph: ContactFlowGraph) -> List[FlowPattern]:
    """Run all pattern detectors and return the combined list."""
    patterns: List[FlowPattern] = []
    patterns.extend(detect_authentication(graph))
    patterns.extend(detect_personalization(graph))
    patterns.extend(detect_transfers(graph))
    patterns.extend(detect_self_service(graph))
    return patterns
