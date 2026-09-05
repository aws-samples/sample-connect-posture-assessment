"""
Telephony topology resolution for Caller Journey Mapping.

Discovers which phone numbers (DID + toll-free) map to which contact flows
and classifies all flows into three tiers for scoping.
"""

import logging
from typing import Any, Dict, List, Optional, Set, Tuple

from ..aws_client_factory import AWSClientFactory
from ..models import ContactFlowGraph
from .models import PhoneNumberEntry, TierAssignment

logger = logging.getLogger("journey.topology")

# Transfer action types that indicate cross-flow reachability.
_TRANSFER_ACTIONS = {
    "TransferToFlow",
    "TransferContactToFlow",
    "InvokeFlowModule",
}


def resolve_topology(
    instance_id: str,
    instance_arn: str,
    factory: AWSClientFactory,
    parsed_flows: Dict[str, ContactFlowGraph],
    config: Dict[str, Any],
) -> Tuple[List[PhoneNumberEntry], List[TierAssignment]]:
    """
    Resolve the full telephony topology: phone numbers → flows → tiers.

    Returns:
        (phone_entries, tier_assignments)
    """
    # Step 1: List all phone numbers.
    phone_entries = _list_phone_numbers(instance_id, instance_arn, factory, parsed_flows)
    logger.info(f"Discovered {len(phone_entries)} phone numbers")

    # Step 2: Build transitive reachability from phone-anchored flows.
    phone_flow_ids = {e.contact_flow_id for e in phone_entries if e.contact_flow_id}
    reachable = _compute_transitive_reachability(phone_flow_ids, parsed_flows)

    # Step 3: Classify tiers.
    max_traffic_flows = config.get("journey_map", {}).get("max_traffic_flows", 10)
    tier_assignments = _classify_tiers(phone_entries, parsed_flows, reachable, max_traffic_flows)

    return phone_entries, tier_assignments


def _list_phone_numbers(
    instance_id: str,
    instance_arn: str,
    factory: AWSClientFactory,
    parsed_flows: Dict[str, ContactFlowGraph],
) -> List[PhoneNumberEntry]:
    """
    Paginate ListPhoneNumbersV2 to get all DIDs + toll-free numbers, then
    resolve each number's assigned flow via ListFlowAssociations.

    ListPhoneNumbersV2's ``TargetArn`` is documented by AWS as "the ARN
    for Connect instances or traffic distribution groups that phone
    number inbound traffic is routed through" — it is always an
    instance/TDG ARN, never a contact-flow ARN, regardless of what flow
    is assigned to the number in the console. The number -> flow mapping
    instead comes from ``connect:ListFlowAssociations`` with
    ``ResourceType=VOICE_PHONE_NUMBER``, matched here by ``PhoneNumberArn``.
    """
    entries: List[PhoneNumberEntry] = []
    client = factory.get_connect_client()

    flow_id_by_phone_arn = _list_voice_flow_associations(instance_id, factory)

    next_token: Optional[str] = None
    try:
        while True:
            kwargs: Dict[str, Any] = {
                "TargetArn": instance_arn,
                "MaxResults": 50,
            }
            if next_token:
                kwargs["NextToken"] = next_token

            resp = factory.call_api_with_resilience(
                client, "list_phone_numbers_v2", "connect", **kwargs
            )
            for num in resp.get("ListPhoneNumbersSummaryList", []):
                flow_id = flow_id_by_phone_arn.get(num.get("PhoneNumberArn", ""))
                flow_name = None
                if flow_id and flow_id in parsed_flows:
                    flow_name = parsed_flows[flow_id].flow_name

                entries.append(
                    PhoneNumberEntry(
                        phone_number=num.get("PhoneNumber", ""),
                        number_type=num.get("PhoneNumberType", "DID"),
                        country_code=num.get("PhoneNumberCountryCode", ""),
                        contact_flow_id=flow_id,
                        contact_flow_name=flow_name,
                        target_arn=num.get("TargetArn"),
                    )
                )

            next_token = resp.get("NextToken")
            if not next_token:
                break

    except Exception as e:
        if factory.is_access_denied(e):
            logger.warning("Access denied for ListPhoneNumbersV2; topology will be empty")
        else:
            logger.error(f"Failed to list phone numbers: {e}")

    return entries


# Resource types ListFlowAssociations supports that represent a phone
# number (as opposed to INBOUND_EMAIL / OUTBOUND_EMAIL /
# ANALYTICS_CONNECTOR). A single Connect number can be channel-bound
# under more than one of these — e.g. a toll-free number claimed for
# voice and separately wired for SMS replies via AWS End User
# Messaging — so all three are queried and merged.
_FLOW_ASSOCIATION_PHONE_RESOURCE_TYPES = (
    "VOICE_PHONE_NUMBER",
    "SMS_PHONE_NUMBER",
    "WHATSAPP_MESSAGING_PHONE_NUMBER",
)


def _list_voice_flow_associations(
    instance_id: str,
    factory: AWSClientFactory,
) -> Dict[str, str]:
    """
    Paginate ListFlowAssociations across every phone-number resource
    type (voice, SMS, WhatsApp) and return a merged mapping of phone
    number ARN -> contact flow ID.

    ``FlowId`` in the response is a full flow ARN
    (``…/contact-flow/{id}``); this returns just the trailing ID.
    Fails open (returns an empty mapping) on any error, including
    access denied, so a missing permission degrades to "no flow
    association found" rather than crashing topology resolution.
    """
    flow_id_by_phone_arn: Dict[str, str] = {}
    client = factory.get_connect_client()

    for resource_type in _FLOW_ASSOCIATION_PHONE_RESOURCE_TYPES:
        next_token: Optional[str] = None
        try:
            while True:
                kwargs: Dict[str, Any] = {
                    "InstanceId": instance_id,
                    "ResourceType": resource_type,
                    "MaxResults": 1000,
                }
                if next_token:
                    kwargs["NextToken"] = next_token

                resp = factory.call_api_with_resilience(
                    client, "list_flow_associations", "connect", **kwargs
                )
                for assoc in resp.get("FlowAssociationSummaryList", []):
                    phone_arn = assoc.get("ResourceId") or ""
                    flow_arn = assoc.get("FlowId") or ""
                    if phone_arn and flow_arn:
                        flow_id_by_phone_arn[phone_arn] = flow_arn.rsplit("/", 1)[-1]

                next_token = resp.get("NextToken")
                if not next_token:
                    break

        except Exception as e:
            if factory.is_access_denied(e):
                logger.warning("Access denied for ListFlowAssociations; topology will be empty")
            else:
                logger.error(f"Failed to list flow associations: {e}")

    return flow_id_by_phone_arn


def _compute_transitive_reachability(
    seed_flow_ids: Set[str],
    parsed_flows: Dict[str, ContactFlowGraph],
) -> Set[str]:
    """
    From a set of seed flows, walk all transfer edges to find all
    transitively reachable flows (the closure).
    """
    reachable: Set[str] = set()
    stack = list(seed_flow_ids)

    while stack:
        flow_id = stack.pop()
        if flow_id in reachable:
            continue
        if flow_id not in parsed_flows:
            continue
        reachable.add(flow_id)

        graph = parsed_flows[flow_id]
        for action in graph.actions.values():
            if action.action_type in _TRANSFER_ACTIONS:
                target = _resolve_static_transfer(action, parsed_flows)
                if target and target not in reachable:
                    stack.append(target)

    return reachable


def _resolve_static_transfer(action, parsed_flows: Dict[str, ContactFlowGraph]) -> Optional[str]:
    """Resolve a static transfer target flow ID from action parameters."""
    params = action.parameters or {}

    # Try ContactFlowId
    flow_ref = params.get("ContactFlowId")
    if isinstance(flow_ref, str) and flow_ref in parsed_flows:
        return flow_ref
    if isinstance(flow_ref, dict):
        val = flow_ref.get("Value", "")
        if val in parsed_flows:
            return val

    # Try FlowModuleId
    module_ref = params.get("FlowModuleId") or params.get("ContactFlowModuleId")
    if isinstance(module_ref, str) and module_ref in parsed_flows:
        return module_ref

    return None


def _classify_tiers(
    phone_entries: List[PhoneNumberEntry],
    parsed_flows: Dict[str, ContactFlowGraph],
    reachable: Set[str],
    max_traffic_flows: int,
) -> List[TierAssignment]:
    """Three-tier classification for all flows."""
    assignments: List[TierAssignment] = []
    remaining = set(parsed_flows.keys()) - reachable

    # Tier 1: phone-reachable
    for flow_id in reachable:
        # Find which number anchors this flow (if directly associated).
        anchor = next((e for e in phone_entries if e.contact_flow_id == flow_id), None)
        if anchor:
            tier = "tier1_tollfree" if anchor.number_type == "TOLL_FREE" else "tier1_did"
            rationale = f"Reachable from {anchor.phone_number} [{anchor.number_type}]"
        else:
            tier = "tier1_did"
            rationale = "Sub-flow reachable from phone-anchored flow"

        assignments.append(
            TierAssignment(
                flow_id=flow_id,
                flow_name=parsed_flows[flow_id].flow_name,
                tier=tier,
                rationale=rationale,
            )
        )

    # Tier 2 and Tier 3: no traffic data available in this implementation
    # (would require GetMetricDataV2 which is expensive). For now, all
    # non-reachable flows go to tier3_dormant. Tier 2 traffic lookup is
    # added in a follow-up when the API is confirmed available.
    for flow_id in remaining:
        assignments.append(
            TierAssignment(
                flow_id=flow_id,
                flow_name=parsed_flows[flow_id].flow_name,
                tier="tier3_dormant",
                rationale="Not reachable from any phone number",
            )
        )

    return assignments
