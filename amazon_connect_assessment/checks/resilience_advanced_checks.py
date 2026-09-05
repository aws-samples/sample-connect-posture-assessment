"""
Advanced resilience checks (Phase 3 / Task 7).

Deep-inspection checks for Connect resilience posture:

- res-acgr-config-001         : ACGR configuration discovery (informational)
- res-acgr-identity-001       : SAML identity required for ACGR agent failover
- res-acgr-tdg-status-001     : Traffic distribution group in ACTIVE status
- res-acgr-traffic-dist-001   : Active-active vs passive-only traffic split
- res-acgr-failover-test-001  : Failover tested in the last 90 days
- res-acgr-numbers-001        : Phone numbers claimed against the TDG
- res-cloudwatch-001          : CloudWatch alarm coverage for critical metrics
- res-carrier-diversity-001   : Phone number carrier/country diversity
- res-hardcoded-routing-001   : Hardcoded routing values in contact flows

ACGR design note: the six res-acgr-* checks exist as a set because a
half-configured ACGR is worse than no ACGR — customers believe they have
DR and don't. `res-acgr-config-001` is the discovery probe: it always
returns PASS, records whether a TDG is present, and (per product decision)
never nags customers who don't need ACGR (~95% of deployments). The five
audit sub-checks each short-circuit to NOT_APPLICABLE when no TDG exists,
so they stay silent on those instances and only fire real findings when
ACGR is on and misconfigured.

Each check degrades to SKIPPED on AccessDenied and emits evidence-specific
structured remediation.
"""

import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

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
from ..parsers import ContactFlowParser, is_default_sample_flow, reachable_from_entry
from .base import BaseCheck, CheckContext

_PARSER = ContactFlowParser()

# Bounded page pull, mirroring engine.py's _list_phone_numbers_for_instance:
# 20 pages * 100 per page = 2000 numbers, comfortably above any single
# instance's or TDG's real phone number count while still bounding worst
# case API calls.
_MAX_PHONE_NUMBER_PAGES = 20
_PHONE_NUMBER_PAGE_SIZE = 100


def _list_all_phone_numbers(factory, target_arn: str) -> List[Dict[str, Any]]:
    """
    Paginate ``connect:ListPhoneNumbersV2`` for a single TargetArn (an
    instance ARN or a traffic distribution group ARN) and return every
    claimed number.

    A single unpaginated call with ``MaxResults=50`` silently truncates
    deployments with more than 50 numbers bound to a given target,
    undercounting (or in the worst case, zeroing out) the "numbers on
    this TDG" evidence used by ACGRPhoneNumberBindingCheck. Raises on
    error so callers can distinguish AccessDenied from "no numbers".
    """
    all_numbers: List[Dict[str, Any]] = []
    next_token: Optional[str] = None
    for _ in range(_MAX_PHONE_NUMBER_PAGES):
        kwargs: Dict[str, Any] = {
            "TargetArn": target_arn,
            "MaxResults": _PHONE_NUMBER_PAGE_SIZE,
        }
        if next_token:
            kwargs["NextToken"] = next_token
        resp = factory.call_api_with_resilience(
            factory.get_connect_client(),
            "list_phone_numbers_v2",
            "connect",
            **kwargs,
        )
        all_numbers.extend(resp.get("ListPhoneNumbersSummaryList") or [])
        next_token = resp.get("NextToken")
        if not next_token:
            break
    return all_numbers


# Required CloudWatch alarm metrics for a well-monitored instance.
_REQUIRED_ALARM_METRICS = [
    "ConcurrentCalls",
    "ConcurrentCallsPercentage",
    "ThrottledCalls",
    "MissedCalls",
    "CallsPerInterval",
]

# Transfer action types to check for hardcoded routing.
_ROUTING_ACTION_TYPES = {
    "TransferContactToPhoneNumber",
    "TransferToPhoneNumber",
    "TransferToQueue",
    "TransferContactToQueue",
    "TransferToFlow",
    "TransferContactToFlow",
}

# ACGR identity requirement: only SAML supports agent Global Sign-in
# across the paired regions. CONNECT_MANAGED and EXISTING_DIRECTORY do not.
_ACGR_ELIGIBLE_IDENTITY_TYPES = {"SAML"}

# CloudTrail lookback window for the failover-tested probe.
_FAILOVER_TEST_LOOKBACK_DAYS = 90


# ---------------------------------------------------------------------------
# ACGR context cache
#
# Six checks in this module all need the same TDG data. Rather than each
# check re-issuing list/describe/get calls, we memoize per instance the
# first time any ACGR check runs. The cache is keyed by instance_id and
# guarded by a lock because ParallelAssessmentEngine executes checks in a
# thread pool. Each field is Optional — we track separately whether the
# fetch succeeded, was denied, or has not been attempted, so downstream
# checks can degrade to SKIPPED individually rather than the whole set.
# ---------------------------------------------------------------------------


@dataclass
class _ACGRContext:
    """Cached ACGR-related API results for a single Connect instance."""

    tdgs: List[Dict[str, Any]] = field(default_factory=list)
    tdgs_denied: bool = False
    tdgs_denied_permission: str = "connect:ListTrafficDistributionGroups"
    # Per-TDG details, keyed by TDG Id.
    tdg_details: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    tdg_details_denied: bool = False
    tdg_details_denied_permission: str = "connect:DescribeTrafficDistributionGroup"
    # Traffic distribution per TDG, keyed by TDG Id.
    traffic_distributions: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    traffic_denied: bool = False
    traffic_denied_permission: str = "connect:GetTrafficDistribution"
    # True once every fetch step below has run to completion (successfully
    # or via a recorded denial) — distinguishes a fully-populated context
    # from a bare placeholder. Only contexts with fetch_complete=True are
    # ever placed into _acgr_cache; see _get_acgr_context.
    fetch_complete: bool = False


_acgr_cache: Dict[str, _ACGRContext] = {}
_acgr_cache_lock = threading.Lock()

# Per-instance locks used to serialize the *fetch* of ACGR data (not just
# the cache insertion). See _get_acgr_context for why a single global lock
# isn't sufficient here.
_acgr_fetch_locks: Dict[str, threading.Lock] = {}
_acgr_fetch_locks_guard = threading.Lock()


def _reset_acgr_cache() -> None:
    """Clear the ACGR cache and per-instance fetch locks. Called from tests to isolate cases."""
    with _acgr_cache_lock:
        _acgr_cache.clear()
    with _acgr_fetch_locks_guard:
        _acgr_fetch_locks.clear()


def _get_acgr_context(context: CheckContext) -> _ACGRContext:
    """
    Return a memoized ``_ACGRContext`` for this instance.

    The first ACGR check that runs for a given instance fetches all the
    ACGR-related API data once; subsequent checks reuse it. Errors are
    recorded on the context per-field so downstream checks can decide
    whether to skip or continue on their own.

    Concurrency note: under the parallel engine, multiple ACGR checks for
    the *same instance* can be scheduled onto different worker threads at
    roughly the same time. The original implementation inserted an empty
    ``_ACGRContext`` into ``_acgr_cache`` under the lock, released the
    lock, and *then* made the slow API calls to fill it in. A second
    thread arriving in that window found the (still-empty) cached context,
    read ``ctx.tdgs == []``, and concluded "ACGR not configured" — even
    though the first thread's fetch was still in flight and would have
    found real traffic distribution groups. That's a silent false
    negative on a real DR misconfiguration, and it was also an
    unsynchronized read/write race on the dataclass fields themselves.

    Fixed by giving each instance its own fetch lock: the winning thread
    holds that lock for the entire fetch (list + describe + traffic-dist
    calls), and any other thread for the same instance blocks until the
    fetch is complete and then returns the *fully populated* context —
    never a half-filled one. Different instances still fetch fully in
    parallel (separate per-instance locks), so this doesn't serialize the
    whole assessment, just concurrent ACGR checks on one instance.
    """
    instance = context.instance
    instance_id = instance.instance_id

    with _acgr_cache_lock:
        cached = _acgr_cache.get(instance_id)
        if cached is not None:
            return cached
        # Get (or create) this instance's dedicated fetch lock while still
        # holding the cache lock, so two threads can't each create their
        # own separate lock for the same instance_id.
        with _acgr_fetch_locks_guard:
            fetch_lock = _acgr_fetch_locks.setdefault(instance_id, threading.Lock())

    # Acquire the per-instance fetch lock OUTSIDE _acgr_cache_lock so other
    # instances' cache lookups aren't blocked while this instance's fetch
    # is in flight.
    with fetch_lock:
        # Re-check the cache: another thread may have finished the fetch
        # and populated it while we were waiting for fetch_lock.
        with _acgr_cache_lock:
            cached = _acgr_cache.get(instance_id)
            if cached is not None and cached.fetch_complete:
                return cached

        ctx = _ACGRContext()
        factory = context.aws_client_factory

        # Step 1: list TDGs.
        try:
            resp = factory.call_api_with_resilience(
                factory.get_connect_client(),
                "list_traffic_distribution_groups",
                "connect",
                InstanceId=instance_id,
                MaxResults=10,
            )
            ctx.tdgs = resp.get("TrafficDistributionGroupSummaryList", []) or []
        except Exception as e:
            if factory.is_access_denied(e):
                ctx.tdgs_denied = True
            # If the API isn't available (older region) treat as no TDG configured.

        if ctx.tdgs:
            # Step 2: describe each TDG (Status field lives here).
            for tdg in ctx.tdgs:
                tdg_id = tdg.get("Id")
                if not tdg_id:
                    continue
                try:
                    resp = factory.call_api_with_resilience(
                        factory.get_connect_client(),
                        "describe_traffic_distribution_group",
                        "connect",
                        TrafficDistributionGroupId=tdg_id,
                    )
                    ctx.tdg_details[tdg_id] = resp.get("TrafficDistributionGroup", {}) or {}
                except Exception as e:
                    if factory.is_access_denied(e):
                        ctx.tdg_details_denied = True
                        break

            # Step 3: get_traffic_distribution for each TDG.
            for tdg in ctx.tdgs:
                tdg_id = tdg.get("Id")
                if not tdg_id:
                    continue
                try:
                    resp = factory.call_api_with_resilience(
                        factory.get_connect_client(),
                        "get_traffic_distribution",
                        "connect",
                        Id=tdg_id,
                    )
                    ctx.traffic_distributions[tdg_id] = resp
                except Exception as e:
                    if factory.is_access_denied(e):
                        ctx.traffic_denied = True
                        break

        ctx.fetch_complete = True
        with _acgr_cache_lock:
            _acgr_cache[instance_id] = ctx
        return ctx


def _parse_flow(flow: ContactFlow) -> Optional[ContactFlowGraph]:
    if not flow.content or not isinstance(flow.content, dict):
        return None
    try:
        return _PARSER.parse(flow.content)
    except Exception:
        return None


def _is_dynamic_reference(value) -> bool:
    if not isinstance(value, str):
        return False
    return value.startswith("$.") or value.startswith("$[")


def _mask_phone(number: str) -> str:
    """Partially mask a phone number for evidence (show last 4 digits)."""
    if not number or len(number) < 5:
        return number or ""
    return "***" + number[-4:]


def _instance_name(instance) -> str:
    """Return a human-friendly name.

    Thin wrapper around :attr:`ConnectInstance.display_name` — kept only so
    downstream call sites don't have to change all at once. New code should
    use ``instance.display_name`` directly.
    """
    return instance.display_name


# ---------------------------------------------------------------------------
# ACGR check set
#
# Together these six checks answer:
#   1. Is ACGR configured at all? (discovery — informational only)
#   2..6. If it is, is it configured correctly? (audit — HIGH severity)
#
# Customers who don't have ACGR (~95%) see only check #1 and no findings —
# by product decision we do not call ACGR absence out as a deficiency.
# Customers who do have ACGR see the audit checks light up any gaps.
# ---------------------------------------------------------------------------


_ACGR_DOCS_URL = (
    "https://docs.aws.amazon.com/connect/latest/adminguide/setup-connect-global-resiliency.html"
)

_ACGR_REALITY_CHECK = (
    "**Before treating any `res-acgr-*` finding as a quick fix:** ACGR is "
    "not a self-service toggle, it requires ongoing replica capacity, and "
    "it does not automatically replicate every dependency. Lex resiliency, "
    "matching Lambda deployments, region-aware resource references, Customer "
    "Profiles, Cases, and S3 recording storage require separate review and "
    "configuration."
)


class ACGRConfigurationCheck(BaseCheck):
    """Discover whether ACGR is configured; always informational."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-config-001",
            name="Amazon Connect Global Resiliency Configuration",
            pillar=Pillar.RESILIENCE,
            # Discovery-only. This never fails, and doesn't nag customers who
            # don't need Regional resilience (roughly 95% of deployments).
            severity=Severity.LOW,
            description=(
                "Reports whether the Connect instance is associated with a "
                "traffic distribution group (Amazon Connect Global Resiliency). "
                "ACGR is an optional capability for Regional (cross-region) "
                "resilience and is not required for every deployment. When "
                "ACGR is configured, the res-acgr-* audit checks verify it "
                "is set up per AWS guidance."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)

        evidence: Dict[str, Any] = {
            "traffic_distribution_groups": len(acgr.tdgs),
            "instance_id": instance.instance_id,
        }

        if not acgr.tdgs:
            # ACGR absence is not a deficiency — it's an architectural choice
            # that ~95% of deployments legitimately don't need. Emit
            # NOT_APPLICABLE so instances without ACGR see nothing about
            # ACGR at all in the report (the audit sub-checks
            # res-acgr-identity-001, res-acgr-tdg-status-001, etc. do the
            # same). Users who want to know whether their instance has
            # ACGR configured can check the evidence dict.
            return self.not_applicable(
                context,
                reason=(
                    "Amazon Connect Global Resiliency (ACGR) is not configured "
                    "on this instance. ACGR is an optional cross-region "
                    "resilience capability and is not required for every "
                    "deployment; if this workload does need Regional "
                    "resilience, engage your AWS account team — ACGR is not "
                    "a self-service configuration."
                ),
                evidence=evidence,
            )

        evidence["tdg_names"] = [t.get("Name") for t in acgr.tdgs]
        evidence["tdg_ids"] = [t.get("Id") for t in acgr.tdgs]
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Amazon Connect Global Resiliency (ACGR) is configured for "
                f"instance {_instance_name(instance)} with {len(acgr.tdgs)} traffic "
                "distribution group(s). The `res-acgr-*` audit checks verify each "
                "aspect of the configuration.\n\n"
                f"{_ACGR_REALITY_CHECK}"
            ),
            evidence=evidence,
        )


class ACGRIdentityManagementCheck(BaseCheck):
    """Verify SAML identity when ACGR is configured (agent Global Sign-in)."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-identity-001",
            name="ACGR Identity Management (SAML required)",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "When ACGR is configured, verifies the Connect instance uses "
                "SAML 2.0 identity management. Agents can only fail over "
                "between paired regions via Global Sign-in, which requires "
                "SAML — CONNECT_MANAGED and EXISTING_DIRECTORY identity types "
                "leave agents stranded when the primary region is unavailable."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if not acgr.tdgs:
            return self.not_applicable(
                context,
                reason=(
                    "ACGR is not configured on this instance. See "
                    "res-acgr-config-001 for the discovery result."
                ),
                evidence={"traffic_distribution_groups": 0},
            )

        idm = instance.identity_management_type or ""
        evidence = {
            "identity_management_type": idm,
            "traffic_distribution_groups": len(acgr.tdgs),
        }

        if idm in _ACGR_ELIGIBLE_IDENTITY_TYPES:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Instance {_instance_name(instance)} uses SAML identity "
                    "management, which supports ACGR agent Global Sign-in."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Instance {_instance_name(instance)} has ACGR configured but "
                f"uses '{idm}' identity management. ACGR agent failover "
                "requires SAML 2.0 — with the current identity type, agents "
                "cannot sign in to the standby region and calls will route "
                "to a region with no available workforce.\n\n"
                "This identity migration is a significant, non-self-service "
                "change; review the enablement, cost, and dependency context "
                "in `res-acgr-config-001` before planning it."
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary=(
                    "Migrate the instance to SAML 2.0 identity management "
                    "before relying on ACGR for agent failover."
                ),
                target_resources=[instance.instance_id],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "Identity management type is set at instance "
                            "creation and cannot be changed in place. Plan a "
                            "migration: create a new instance with SAML 2.0, "
                            "re-provision resources (flows, queues, routing "
                            "profiles, users) into it, then repoint the TDG "
                            "and phone numbers. Engage your AWS account team "
                            "to plan the cutover — this is a significant "
                            "change and warrants specialist support."
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Amazon Connect Global Resiliency prerequisites",
                        url=_ACGR_DOCS_URL,
                    ),
                    RemediationReference(
                        title="Configure SAML with IAM for Amazon Connect",
                        url="https://docs.aws.amazon.com/connect/latest/adminguide/configure-saml.html",
                    ),
                ],
            ),
        )


class ACGRTrafficDistributionGroupStatusCheck(BaseCheck):
    """Verify each TDG is in ACTIVE status."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-tdg-status-001",
            name="ACGR Traffic Distribution Group Status",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "When ACGR is configured, verifies each traffic distribution "
                "group is in ACTIVE status. A TDG in CREATION_IN_PROGRESS, "
                "CREATION_FAILED, UPDATE_IN_PROGRESS, or PENDING_DELETION "
                "cannot serve failover traffic."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if not acgr.tdgs:
            return self.not_applicable(
                context,
                reason=(
                    "ACGR is not configured on this instance. See "
                    "res-acgr-config-001 for the discovery result."
                ),
                evidence={"traffic_distribution_groups": 0},
            )
        if acgr.tdg_details_denied and not acgr.tdg_details:
            return self.skipped_for_access_denied(context, acgr.tdg_details_denied_permission)

        # Prefer the detailed Status from DescribeTrafficDistributionGroup;
        # fall back to the summary Status if Describe wasn't available.
        tdg_status_map: Dict[str, str] = {}
        for tdg in acgr.tdgs:
            tdg_id = tdg.get("Id")
            detail = acgr.tdg_details.get(tdg_id) if tdg_id else None
            status = (detail or {}).get("Status") or tdg.get("Status") or "UNKNOWN"
            tdg_status_map[tdg.get("Name") or tdg_id or "unnamed"] = status

        non_active = {name: status for name, status in tdg_status_map.items() if status != "ACTIVE"}
        evidence = {
            "tdg_status": tdg_status_map,
            "non_active_tdgs": non_active,
        }

        if not non_active:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"All {len(tdg_status_map)} traffic distribution group(s) "
                    "for this instance are in ACTIVE status."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="TrafficDistributionGroup",
            description=(
                f"{len(non_active)} traffic distribution group(s) are not in "
                f"ACTIVE status: "
                + ", ".join(f"'{n}' ({s})" for n, s in non_active.items())
                + ". Failover through these TDGs will not work until they "
                "reach ACTIVE. Review `res-acgr-config-001` for the remaining "
                "dependency and coverage requirements; ACTIVE status alone "
                "does not prove end-to-end failover readiness."
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary="Resolve the non-ACTIVE TDG state(s).",
                target_resources=list(non_active.keys()),
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "For CREATION_IN_PROGRESS or UPDATE_IN_PROGRESS: "
                            "wait for the operation to complete and re-run "
                            "the assessment. For CREATION_FAILED: delete the "
                            "failed TDG and recreate it, then repoint phone "
                            "numbers. For PENDING_DELETION: confirm the "
                            "deletion is intended; if not, recreate the TDG."
                        ),
                        console_path=(
                            "Connect console -> Instance -> Global "
                            "resiliency -> Traffic distribution groups"
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Amazon Connect Global Resiliency",
                        url=_ACGR_DOCS_URL,
                    )
                ],
            ),
        )


class ACGRTrafficDistributionCheck(BaseCheck):
    """Verify traffic distribution is active-active, not passive-only (100/0)."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-traffic-dist-001",
            name="ACGR Active-Active Traffic Distribution",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "When ACGR is configured, verifies traffic is distributed "
                "across regions rather than pinned 100% to one region. A "
                "100/0 split leaves the standby region unexercised — the "
                "first real test of the failover path becomes the incident "
                "itself, which frequently surfaces latent issues."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if not acgr.tdgs:
            return self.not_applicable(
                context,
                reason=(
                    "ACGR is not configured on this instance. See "
                    "res-acgr-config-001 for the discovery result."
                ),
                evidence={"traffic_distribution_groups": 0},
            )
        if acgr.traffic_denied and not acgr.traffic_distributions:
            return self.skipped_for_access_denied(context, acgr.traffic_denied_permission)

        # For each TDG, check if any region holds 100% of telephony traffic.
        passive_tdgs: List[Dict[str, Any]] = []
        distribution_summary: Dict[str, Any] = {}

        for tdg in acgr.tdgs:
            tdg_id = tdg.get("Id")
            tdg_name = tdg.get("Name") or tdg_id
            if not tdg_id:
                continue
            dist = acgr.traffic_distributions.get(tdg_id)
            if not dist:
                continue

            telephony = (dist.get("TelephonyConfig") or {}).get("Distributions") or []
            per_region = {d.get("Region", "unknown"): d.get("Percentage", 0) for d in telephony}
            distribution_summary[tdg_name] = per_region

            # Passive-only: any single region at 100% (and thus every other
            # region at 0%). Also flag the degenerate case of a single-region
            # distribution list, which means only one region is participating.
            if telephony and (
                any(d.get("Percentage") == 100 for d in telephony) or len(telephony) < 2
            ):
                passive_tdgs.append(
                    {
                        "tdg_name": tdg_name,
                        "distribution": per_region,
                    }
                )

        evidence = {
            "distribution_by_tdg": distribution_summary,
            "passive_only_tdg_count": len(passive_tdgs),
        }

        if not passive_tdgs:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "Traffic is distributed across regions for every TDG — "
                    "the standby region is actively serving traffic and the "
                    "failover path is continuously exercised."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="TrafficDistributionGroup",
            description=(
                f"{len(passive_tdgs)} of {len(acgr.tdgs)} TDG(s) route 100% "
                "of traffic to a single region. The standby region is not "
                "exercised, so the failover path is unverified until the "
                "next incident forces a cutover — a moment when latent "
                "issues surface with the highest impact.\n\n"
                "Serving traffic from the standby region is what exercises "
                "the path, but it also requires provisioned capacity and "
                "separately prepared dependencies. See `res-acgr-config-001` "
                "for that cost and coverage context."
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary=(
                    "Move to an active-active split (e.g. 80/20 or 60/40) "
                    "so both regions serve real traffic continuously."
                ),
                target_resources=[t["tdg_name"] for t in passive_tdgs],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "Update the traffic distribution to a non-100/0 "
                            "split. Start conservatively (90/10 or 80/20) "
                            "and adjust as you build confidence."
                        ),
                        console_path=(
                            "Connect console -> Instance -> Global "
                            "resiliency -> Traffic distribution groups -> "
                            "<tdg> -> Edit traffic distribution"
                        ),
                        command=(
                            "aws connect update-traffic-distribution "
                            "--id <tdg-id> --telephony-config "
                            "'Distributions=[{Region=<primary>,Percentage=80},"
                            "{Region=<standby>,Percentage=20}]'"
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Amazon Connect Global Resiliency",
                        url=_ACGR_DOCS_URL,
                    )
                ],
                applies_if=(
                    "the standby region is provisioned with capacity to serve "
                    "its share of traffic (Lambda, Lex, and other integrations "
                    "replicated cross-region)."
                ),
                placeholders=["<tdg-id>", "<primary>", "<standby>"],
            ),
        )


class ACGRFailoverTestCheck(BaseCheck):
    """Verify failover has been tested via CloudTrail lookup for UpdateTrafficDistribution."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-failover-test-001",
            name="ACGR Failover Testing Evidence",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "When ACGR is configured, verifies failover has been tested "
                f"in the last {_FAILOVER_TEST_LOOKBACK_DAYS} days by looking "
                "for UpdateTrafficDistribution CloudTrail events. An "
                "untested failover plan is a plan on paper only."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if not acgr.tdgs:
            return self.not_applicable(
                context,
                reason=(
                    "ACGR is not configured on this instance. See "
                    "res-acgr-config-001 for the discovery result."
                ),
                evidence={"traffic_distribution_groups": 0},
            )

        start_time = datetime.now(timezone.utc) - timedelta(days=_FAILOVER_TEST_LOOKBACK_DAYS)
        try:
            resp = factory.call_api_with_resilience(
                factory.get_cloudtrail_client(),
                "lookup_events",
                "cloudtrail",
                LookupAttributes=[
                    {"AttributeKey": "EventName", "AttributeValue": "UpdateTrafficDistribution"},
                ],
                StartTime=start_time,
                MaxResults=50,
            )
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "cloudtrail:LookupEvents")
            # CloudTrail not queryable (unusual). Report as ERROR via safe_execute.
            raise

        events = resp.get("Events", []) or []
        evidence = {
            "lookback_days": _FAILOVER_TEST_LOOKBACK_DAYS,
            "update_traffic_distribution_event_count": len(events),
        }

        if events:
            # Include a small sample of event timestamps for the report.
            evidence["most_recent_event_time"] = str(events[0].get("EventTime", ""))
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Failover has been exercised: {len(events)} "
                    f"UpdateTrafficDistribution event(s) in the last "
                    f"{_FAILOVER_TEST_LOOKBACK_DAYS} days."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                "ACGR is configured but no UpdateTrafficDistribution events "
                f"were recorded in the last {_FAILOVER_TEST_LOOKBACK_DAYS} "
                "days. The failover mechanism has not been tested — plans "
                "that have never run in anger routinely fail on first use.\n\n"
                "Use the exercise to validate dependencies that ACGR does not "
                "prepare automatically, including Lex resiliency, matching "
                "Lambda deployments, and region-aware resource references."
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary=("Schedule a controlled failover exercise at least once per quarter."),
                target_resources=[instance.instance_id],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "Plan a controlled failover: shift 100% of "
                            "traffic to the standby region during a low-"
                            "volume window, verify calls route and agents "
                            "handle them, then restore the intended "
                            "distribution. Repeat quarterly."
                        ),
                        command=(
                            "aws connect update-traffic-distribution "
                            "--id <tdg-id> --telephony-config "
                            "'Distributions=[{Region=<standby>,Percentage=100},"
                            "{Region=<primary>,Percentage=0}]'"
                        ),
                    ),
                    RemediationStep(
                        order=2,
                        instruction=(
                            "Verify dependencies in the standby region "
                            "during the exercise: Lambda functions invoked "
                            "by flows, Lex bots, Kinesis streams for CTRs, "
                            "and S3 buckets for recordings must all be "
                            "available cross-region."
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Amazon Connect Global Resiliency",
                        url=_ACGR_DOCS_URL,
                    )
                ],
                placeholders=["<tdg-id>", "<primary>", "<standby>"],
            ),
        )


class ACGRPhoneNumberBindingCheck(BaseCheck):
    """Verify phone numbers are claimed against the TDG (not just the instance)."""

    def __init__(self):
        super().__init__(
            check_id="res-acgr-numbers-001",
            name="ACGR Phone Number Binding",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "When ACGR is configured, verifies inbound phone numbers "
                "are claimed against a traffic distribution group ARN "
                "rather than the instance ARN. Numbers bound directly to "
                "the instance do not fail over — they continue routing to "
                "the primary region even when the TDG has shifted traffic."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        acgr = _get_acgr_context(context)

        if acgr.tdgs_denied:
            return self.skipped_for_access_denied(context, acgr.tdgs_denied_permission)
        if not acgr.tdgs:
            return self.not_applicable(
                context,
                reason=(
                    "ACGR is not configured on this instance. See "
                    "res-acgr-config-001 for the discovery result."
                ),
                evidence={"traffic_distribution_groups": 0},
            )

        # Count numbers claimed against each TDG and against the instance.
        try:
            instance_numbers = _list_all_phone_numbers(factory, instance.instance_arn)
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListPhoneNumbersV2")
            instance_numbers = []

        tdg_number_counts: Dict[str, int] = {}
        tdgs_denied = False
        for tdg in acgr.tdgs:
            tdg_arn = tdg.get("Arn")
            tdg_name = tdg.get("Name") or tdg.get("Id") or "unnamed"
            if not tdg_arn:
                continue
            try:
                tdg_number_counts[tdg_name] = len(_list_all_phone_numbers(factory, tdg_arn))
            except Exception as e:
                if factory.is_access_denied(e):
                    tdgs_denied = True
                    break
                tdg_number_counts[tdg_name] = 0

        if tdgs_denied and not tdg_number_counts:
            return self.skipped_for_access_denied(context, "connect:ListPhoneNumbersV2")

        total_on_tdgs = sum(tdg_number_counts.values())
        instance_direct = len(instance_numbers)

        evidence = {
            "numbers_on_tdgs": tdg_number_counts,
            "total_numbers_on_tdgs": total_on_tdgs,
            "numbers_directly_on_instance": instance_direct,
        }

        # Case 1: TDG has no numbers at all — ACGR won't route anything.
        if total_on_tdgs == 0:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "ACGR is configured but no phone numbers are claimed "
                    "against any traffic distribution group. Inbound calls "
                    "will not benefit from failover — they route to whichever "
                    "target the number is bound to, which is not the TDG.\n\n"
                    "Phone-number binding is necessary but not sufficient; "
                    "review `res-acgr-config-001` for dependencies ACGR does "
                    "not replicate automatically."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        "Repoint inbound phone numbers from the instance ARN "
                        "to the TDG ARN so failover routing takes effect."
                    ),
                    target_resources=[t.get("Name") for t in acgr.tdgs if t.get("Name")],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each inbound number that should benefit "
                                "from failover, update its TargetArn to point "
                                "at the TDG."
                            ),
                            command=(
                                "aws connect update-phone-number "
                                "--phone-number-id <number-id> "
                                "--target-arn <tdg-arn>"
                            ),
                            console_path=(
                                "Connect console -> Telephony -> Phone numbers -> <number> -> Edit"
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Associating phone numbers with a TDG",
                            url=_ACGR_DOCS_URL,
                        )
                    ],
                    placeholders=["<number-id>", "<tdg-arn>"],
                ),
            )

        # Case 2: Some numbers on TDG, but some still directly on the instance
        # — the ones on the instance won't fail over.
        if instance_direct > 0:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"{instance_direct} phone number(s) are claimed directly "
                    f"against the instance rather than a TDG ({total_on_tdgs} "
                    "are on TDGs). Numbers bound to the instance will not "
                    "fail over when the TDG shifts traffic — those calls "
                    "will keep going to the primary region.\n\n"
                    "Phone-number binding is necessary but not sufficient; "
                    "review `res-acgr-config-001` for dependencies ACGR does "
                    "not replicate automatically."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        "Repoint the instance-bound numbers to a TDG so all "
                        "inbound traffic benefits from failover."
                    ),
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Enumerate the instance-bound numbers and, "
                                "for any that should participate in failover, "
                                "update their TargetArn to a TDG ARN."
                            ),
                            command=(
                                "aws connect list-phone-numbers-v2 "
                                f"--target-arn {instance.instance_arn} "
                                "&& aws connect update-phone-number "
                                "--phone-number-id <number-id> "
                                "--target-arn <tdg-arn>"
                            ),
                        ),
                    ],
                    applies_if=(
                        "the instance-bound numbers are intended to failover. "
                        "Some numbers may be region-specific by design (e.g. "
                        "an in-region test line) — those can stay on the "
                        "instance."
                    ),
                    placeholders=["<number-id>", "<tdg-arn>"],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"All {total_on_tdgs} inbound phone number(s) are claimed "
                "against a traffic distribution group and will benefit from "
                "ACGR failover routing."
            ),
            evidence=evidence,
        )


class CloudWatchAlarmMonitoringCheck(BaseCheck):
    """Verify CloudWatch alarms cover critical Connect metrics (Req 2)."""

    def __init__(self):
        super().__init__(
            check_id="res-cloudwatch-001",
            name="CloudWatch Alarm Coverage",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            description=(
                "Verifies that CloudWatch alarms exist for critical Amazon "
                "Connect operational metrics."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.describe_alarms_resilient(
                MaxRecords=100,
            )
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "cloudwatch:DescribeAlarms")
            raise

        all_alarms = resp.get("MetricAlarms", []) or []
        # Filter to alarms in the AWS/Connect namespace.
        connect_alarms = [
            a for a in all_alarms if (a.get("Namespace") or "").startswith("AWS/Connect")
        ]
        covered_metrics = {a.get("MetricName") for a in connect_alarms if a.get("MetricName")}
        missing = [m for m in _REQUIRED_ALARM_METRICS if m not in covered_metrics]

        evidence = {
            "connect_alarm_count": len(connect_alarms),
            "covered_metrics": sorted(covered_metrics),
            "missing_metrics": missing,
        }
        metric_impact = {
            "ConcurrentCalls": "concurrent-call quota consumption",
            "ConcurrentCallsPercentage": "quota headroom across differently sized instances",
            "ThrottledCalls": "calls rejected because the instance was over capacity",
            "MissedCalls": "queued calls that were not answered",
            "CallsPerInterval": "unexpected call-volume spikes or drops",
        }

        if not connect_alarms:
            missing_lines = "\n".join(
                f"* **{metric}** — {metric_impact[metric]}" for metric in _REQUIRED_ALARM_METRICS
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"No CloudWatch alarms exist for {instance.display_name} "
                    "in the AWS/Connect namespace. CloudWatch may still collect "
                    "these metrics, but without alarms the listed conditions do "
                    "not have an automated notification path:\n\n"
                    f"{missing_lines}"
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Create CloudWatch alarms for critical Connect metrics.",
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Create alarms for: ConcurrentCalls (>80% capacity), "
                                "ThrottledCalls (>0), MissedCalls (threshold per queue), "
                                "CallsPerInterval (anomaly detection)."
                            ),
                            console_path=(
                                "CloudWatch console -> Alarms -> Create alarm -> "
                                "AWS/Connect namespace"
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Monitoring Connect with CloudWatch",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/monitoring-cloudwatch.html",  # noqa: E501
                        )
                    ],
                ),
            )

        if missing:
            missing_lines = "\n".join(
                f"* **{metric}** — {metric_impact[metric]}" for metric in missing
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"CloudWatch alarms cover {len(covered_metrics)} of "
                    f"{len(_REQUIRED_ALARM_METRICS)} recommended metrics for "
                    f"{instance.display_name}. The missing metrics leave these "
                    "specific conditions without an automated notification path:\n\n"
                    f"{missing_lines}"
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=f"Add alarms for missing metrics: {', '.join(missing)}.",
                    target_resources=[instance.instance_id] + missing,
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                f"Create CloudWatch alarms for the following "
                                f"uncovered metrics: {', '.join(missing)}."
                            ),
                            console_path="CloudWatch console -> Alarms -> Create",
                        ),
                    ],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"CloudWatch alarms cover all {len(_REQUIRED_ALARM_METRICS)} "
                "recommended Connect metrics, providing notification paths "
                "for capacity, throttling, missed-call, and volume conditions."
            ),
            evidence=evidence,
        )


class CarrierDiversityCheck(BaseCheck):
    """Assess phone number geographic / carrier diversity (Req 19)."""

    def __init__(self):
        super().__init__(
            check_id="res-carrier-diversity-001",
            name="Phone Number Carrier Diversity",
            pillar=Pillar.RESILIENCE,
            severity=Severity.MEDIUM,
            description=(
                "Checks phone number distribution by country; flags "
                "single-country deployments without a traffic distribution group."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.call_api_with_resilience(
                factory.get_connect_client(),
                "list_phone_numbers_v2",
                "connect",
                TargetArn=instance.instance_arn,
                MaxResults=50,
            )
        except Exception as e:
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListPhoneNumbersV2")
            # Fallback: API may not exist pre-2022; treat as no numbers.
            resp = {"ListPhoneNumbersSummaryList": []}

        numbers = resp.get("ListPhoneNumbersSummaryList", []) or []
        if not numbers:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description="No phone numbers claimed; carrier diversity N/A.",
                evidence={"phone_number_count": 0},
            )

        # Count by country code.
        country_counts: dict = {}
        for num in numbers:
            cc = num.get("PhoneNumberCountryCode", "UNKNOWN")
            country_counts[cc] = country_counts.get(cc, 0) + 1

        evidence = {
            "phone_number_count": len(numbers),
            "country_distribution": country_counts,
        }

        if len(country_counts) == 1:
            only_country = next(iter(country_counts))
            return self.not_applicable(
                context,
                reason=(
                    f"All {len(numbers)} phone number(s) on "
                    f"{instance.display_name} are claimed in a single country "
                    f"({only_country}). This is the expected shape for a "
                    "domestic-only operation, so there is nothing to fix by "
                    "default.\n\n"
                    "Additional country numbers are relevant only when the "
                    "business directly serves callers in those countries. "
                    "Region-level failover is a separate concern addressed by "
                    "Traffic Distribution Groups and Amazon Connect Global "
                    "Resiliency (`res-acgr-*`); adding countries does not prove "
                    "regional resilience."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Phone numbers on {instance.display_name} span "
                f"{len(country_counts)} countries "
                f"({', '.join(sorted(country_counts))}). This provides local "
                "number presence where those countries are intentionally served; "
                "it does not by itself establish regional failover."
            ),
            evidence=evidence,
        )


class HardcodedRoutingCheck(BaseCheck):
    """Detect hardcoded routing values in customer-authored contact flows (Req 38)."""

    def __init__(self):
        super().__init__(
            check_id="res-hardcoded-routing-001",
            name="Hardcoded Routing Configuration",
            pillar=Pillar.RESILIENCE,
            severity=Severity.LOW,
            description=(
                "Notes contact flows that use literal phone numbers, queue "
                "ARNs, or flow ARNs instead of a contact attribute reference. "
                "Hardcoded destinations are a normal, common pattern in "
                "contact center flows — this is an observation to help you "
                "decide whether externalizing a specific destination is "
                "worth it for your operation, not a defect to fix."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        hardcoded_all = []
        # AWS's built-in sample flows (see is_default_sample_flow) ship
        # with literal phone numbers and ARNs by design — they are demo
        # content, not the customer's production routing configuration.
        # Reviewer feedback: including them here just reports on AWS's
        # own flows back to the customer, which is noise. Only look at
        # flows the customer actually authored.
        customer_flows = [f for f in instance.contact_flows if not is_default_sample_flow(f)]

        for flow in customer_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type not in _ROUTING_ACTION_TYPES:
                    continue
                params = action.parameters or {}
                dest = (
                    params.get("PhoneNumber")
                    or params.get("QueueId")
                    or params.get("ContactFlowId")
                    or (params.get("Endpoint", {}) or {}).get("Address")
                )
                if dest and not _is_dynamic_reference(dest):
                    hardcoded_all.append(
                        {
                            "flow": flow.name,
                            "flow_id": flow.id,
                            "action_id": action.action_id,
                            "action_type": action.action_type,
                            "hardcoded_value": (
                                _mask_phone(dest) if "Phone" in action.action_type else dest[:60]
                            ),
                        }
                    )

        evidence = {
            "hardcoded_count": len(hardcoded_all),
            "flows_analyzed": len(customer_flows),
            "sample_flows_excluded": len(instance.contact_flows) - len(customer_flows),
        }

        if len(hardcoded_all) > 3:
            evidence["hardcoded_details"] = hardcoded_all[:10]  # cap evidence size
            detail_lines = "\n".join(
                f"* `{item['flow']}` → `{item['action_type']}` (action `{item['action_id']}`)"
                for item in hardcoded_all[:5]
            )
            more_note = (
                f"\n\n_+ {len(hardcoded_all) - 5} more; see JSON evidence._"
                if len(hardcoded_all) > 5
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description=(
                    f"{len(hardcoded_all)} hardcoded routing destination(s) "
                    f"found across {evidence['flows_analyzed']} customer-authored "
                    "flow(s) (AWS's default sample flows are excluded from this "
                    "count).\n\n"
                    "**This is an observation, not a defect.** Hardcoding a "
                    "phone number, queue, or flow destination directly in a "
                    "transfer action is a normal and common pattern in "
                    "contact center flows — plenty of routing decisions "
                    "genuinely never change (a permanent escalation queue, a "
                    "fixed after-hours voicemail line) and don't need "
                    "externalized configuration. The only time this is worth "
                    "acting on is when a specific destination changes "
                    "**across environments** (dev/test/prod use different "
                    "queues) or **over time** (a vendor number that gets "
                    "renegotiated periodically) — in those cases, editing and "
                    "republishing the flow for every change is real "
                    "operational overhead. Each change requires editing, "
                    "saving, publishing, and re-testing the affected flow.\n\n"
                    "**Where it was found:**\n\n"
                    f"{detail_lines}{more_note}"
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        "Only for destinations that actually vary by "
                        "environment or change over time: replace the "
                        "literal value with a contact attribute reference."
                    ),
                    target_resources=[h["action_id"] for h in hardcoded_all[:5]],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Review the flagged destinations and identify "
                                "which ones actually change across environments "
                                "or over time. Leave genuinely static ones "
                                "(permanent fallback numbers, fixed escalation "
                                "queues) as-is — hardcoding those is fine."
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "For destinations that do change, replace the "
                                "literal value with a contact attribute "
                                "reference ($.Attributes.destination) set "
                                "earlier in the flow with a Set contact "
                                "attributes block, or populated dynamically by "
                                "an upstream Lambda if the value needs to come "
                                "from an external source (a config store, a "
                                "database, etc). Which of these fits depends "
                                "on how the value needs to be sourced and "
                                "updated — there is no single AWS-recommended "
                                "storage backend for this."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Best practices for flows in Amazon Connect",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/bp-contact-flows.html",  # noqa: E501
                        ),
                        RemediationReference(
                            title="Set contact attributes",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-attrib-list.html",  # noqa: E501
                        ),
                    ],
                    applies_if=(
                        "the flagged destination(s) actually change across "
                        "environments or over time — otherwise no action is "
                        "needed."
                    ),
                ),
            )

        # PASS description explains what was checked and why in plain
        # language, since most readers won't know what "hardcoded routing
        # destinations" means in a Connect context.
        analyzed = evidence["flows_analyzed"]
        hardcoded = len(hardcoded_all)
        sample_note = (
            f" ({evidence['sample_flows_excluded']} AWS default sample "
            "flow(s) were excluded from this check.)"
            if evidence["sample_flows_excluded"]
            else ""
        )
        if hardcoded == 0:
            description = (
                f"None of your {analyzed} customer-authored contact flow(s) "
                "contain hardcoded phone numbers, queue ARNs, or flow ARNs as "
                "transfer destinations — every transfer action uses a "
                "contact attribute reference.{sample_note} Hardcoding is a "
                "normal pattern for destinations that never change, so this "
                "isn't a requirement — it just means every routing "
                "destination in your flows happens to be externalized "
                "already."
            ).format(sample_note=sample_note)
        else:
            description = (
                f"{hardcoded} hardcoded routing destination(s) noted across "
                f"{analyzed} customer-authored flow(s){sample_note} — below "
                "the threshold this check uses to flag it for a closer look. "
                "Hardcoded destinations are a normal, common pattern in "
                "contact center flows and are not a defect by themselves; "
                "worth externalizing only if a specific destination changes "
                "across environments or over time."
            )
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=description,
            evidence=evidence,
        )


def _static_lambda_reference(parameters: Dict[str, Any]) -> Optional[str]:
    """Resolve a static Lambda ARN or name from supported Connect export shapes."""
    value: Any = None
    for name in ("FunctionArn", "LambdaFunctionARN"):
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
        return None

    if not isinstance(value, str) or not value.strip():
        return None
    reference = value.strip()
    if reference.startswith("$.") or reference.startswith("$["):
        return None
    return reference


class LambdaDependencyRiskCheck(BaseCheck):
    """Find reachable VPC Lambda call sites without an error fallback."""

    def __init__(self):
        super().__init__(
            check_id="res-lambda-dependency-001",
            name="Lambda Dependency Network Risk",
            pillar=Pillar.RESILIENCE,
            severity=Severity.MEDIUM,
            description=(
                "Inspects each reachable Lambda call site and flags VPC-attached functions "
                "when that specific action has no error transition."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        customer_flows = sorted(
            (flow for flow in instance.contact_flows if not is_default_sample_flow(flow)),
            key=lambda flow: ((flow.name or "").casefold(), flow.id),
        )
        call_sites_by_reference: Dict[str, List[Dict[str, Any]]] = {}
        seen_call_sites: set[tuple[str, str, str]] = set()
        unresolved_call_sites: List[Dict[str, Any]] = []
        skipped_flows: List[Dict[str, str]] = []
        flows_analyzed = 0
        authored_lambda_blocks = 0
        unreachable_lambda_blocks = 0

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
            reachable = reachable_from_entry(graph)
            lambda_actions = sorted(
                (
                    action
                    for action in graph.actions.values()
                    if action.action_type == "InvokeLambdaFunction"
                ),
                key=lambda action: action.action_id,
            )
            authored_lambda_blocks += len(lambda_actions)
            unreachable_lambda_blocks += sum(
                action.action_id not in reachable for action in lambda_actions
            )

            for action in lambda_actions:
                if action.action_id not in reachable:
                    continue
                call_site = {
                    "flow": flow.name,
                    "flow_id": flow.id,
                    "action_id": action.action_id,
                    "has_error_branch": bool(action.error_transitions),
                    "error_targets": sorted(
                        transition.target_action_id for transition in action.error_transitions
                    ),
                }
                reference = _static_lambda_reference(action.parameters or {})
                if reference is None:
                    unresolved_call_sites.append(
                        {**call_site, "reason": "Lambda reference is missing or dynamic"}
                    )
                    continue
                key = (flow.id, action.action_id, reference)
                if key in seen_call_sites:
                    continue
                seen_call_sites.add(key)
                call_sites_by_reference.setdefault(reference, []).append(call_site)

        for call_sites in call_sites_by_reference.values():
            call_sites.sort(
                key=lambda row: (
                    str(row["flow"]).casefold(),
                    str(row["flow_id"]),
                    str(row["action_id"]),
                )
            )
        unresolved_call_sites.sort(
            key=lambda row: (
                str(row["flow"]).casefold(),
                str(row["flow_id"]),
                str(row["action_id"]),
            )
        )

        checked_functions = 0
        denied_functions: List[str] = []
        lookup_failures: List[Dict[str, str]] = []
        risky_call_sites: List[Dict[str, Any]] = []

        for reference in sorted(call_sites_by_reference):
            try:
                response = factory.get_lambda_function_resilient(reference)
            except Exception as error:  # noqa: BLE001
                if factory.is_access_denied(error):
                    denied_functions.append(reference)
                else:
                    lookup_failures.append(
                        {
                            "function_reference": reference,
                            "error_type": type(error).__name__,
                            "error": str(error),
                        }
                    )
                continue

            checked_functions += 1
            configuration = response.get("Configuration") or {}
            vpc_config = configuration.get("VpcConfig") or {}
            subnet_ids = sorted(vpc_config.get("SubnetIds") or [])
            security_group_ids = sorted(vpc_config.get("SecurityGroupIds") or [])
            is_vpc_attached = bool(vpc_config.get("VpcId") or subnet_ids or security_group_ids)
            if not is_vpc_attached:
                continue

            for call_site in call_sites_by_reference[reference]:
                if call_site["has_error_branch"]:
                    continue
                risky_call_sites.append(
                    {
                        **call_site,
                        "function_reference": reference,
                        "function_name": configuration.get("FunctionName") or reference,
                        "vpc_id": vpc_config.get("VpcId") or "",
                        "subnet_ids": subnet_ids,
                        "security_group_ids": security_group_ids,
                    }
                )

        risky_call_sites.sort(
            key=lambda row: (
                str(row["flow"]).casefold(),
                str(row["flow_id"]),
                str(row["action_id"]),
                str(row["function_reference"]),
            )
        )
        limitations = []
        if skipped_flows:
            limitations.append(f"{len(skipped_flows)} flow(s) could not be analyzed")
        if unresolved_call_sites:
            limitations.append(
                f"{len(unresolved_call_sites)} reachable call site(s) use an unresolved reference"
            )
        if denied_functions:
            limitations.append(
                f"lambda:GetFunction was denied for {len(denied_functions)} function(s)"
            )
        if lookup_failures:
            limitations.append(f"{len(lookup_failures)} function lookup(s) failed")

        reachable_call_sites = sum(len(sites) for sites in call_sites_by_reference.values()) + len(
            unresolved_call_sites
        )
        evidence = {
            "flows_discovered": len(instance.contact_flows),
            "customer_flows_discovered": len(customer_flows),
            "sample_flows_excluded": len(instance.contact_flows) - len(customer_flows),
            "flows_analyzed": flows_analyzed,
            "flows_skipped": len(skipped_flows),
            "skipped_flow_details": skipped_flows,
            "authored_lambda_blocks": authored_lambda_blocks,
            "unreachable_lambda_blocks": unreachable_lambda_blocks,
            "reachable_lambda_call_sites": reachable_call_sites,
            "lambda_functions_invoked": len(call_sites_by_reference),
            "lambda_functions_checked": checked_functions,
            "lambda_functions_access_denied": denied_functions,
            "lambda_function_lookup_failures": lookup_failures,
            "unresolved_call_sites": unresolved_call_sites,
            "vpc_attached_without_error_branch": len(risky_call_sites),
            "risky_function_count": len({row["function_reference"] for row in risky_call_sites}),
            "analysis_complete": not limitations,
            "limitations": limitations,
        }

        if risky_call_sites:
            evidence["details"] = risky_call_sites[:20]
            limitation_note = (
                " The result is additionally limited because " + "; ".join(limitations) + "."
                if limitations
                else ""
            )
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="LambdaFunction",
                description=(
                    f"**{len(risky_call_sites)} reachable Lambda call site(s) invoke a "
                    "VPC-attached function without an error transition.** Each listed action "
                    "is reported independently; a guarded call elsewhere does not hide it."
                    f"{limitation_note}"
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Wire an error fallback on every listed VPC Lambda call site.",
                    target_resources=[row["action_id"] for row in risky_call_sites[:10]],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Open each listed Lambda action and connect its red Error output "
                                "to an apology prompt and fallback queue or disconnect path."
                            ),
                            console_path="Connect console -> Routing -> Flows",
                        )
                    ],
                    references=[
                        RemediationReference(
                            title="Invoke Lambda from a contact flow",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-lambda-functions.html",  # noqa: E501
                        )
                    ],
                ),
            )

        if limitations:
            if denied_functions:
                evidence["required_permission"] = "lambda:GetFunction"
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="LambdaFunction",
                description=(
                    "Lambda dependency analysis was incomplete and cannot report PASS: "
                    + "; ".join(limitations)
                    + "."
                ),
                evidence=evidence,
            )

        if reachable_call_sites == 0:
            return self.not_applicable(
                context,
                "no reachable Lambda call site was found in customer-authored contact flows",
                resource_type="LambdaFunction",
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="LambdaFunction",
            description=(
                f"Checked {reachable_call_sites} reachable call site(s) for "
                f"{checked_functions} Lambda function(s); no VPC-attached function is called "
                "without an error transition."
            ),
            evidence=evidence,
        )


def register_advanced_resilience_checks(registry, *, include_flow_checks: bool = True) -> None:
    """Register all advanced resilience checks."""
    # ACGR set — discovery + five audit sub-checks.
    registry.register_check(ACGRConfigurationCheck())
    registry.register_check(ACGRIdentityManagementCheck())
    registry.register_check(ACGRTrafficDistributionGroupStatusCheck())
    registry.register_check(ACGRTrafficDistributionCheck())
    registry.register_check(ACGRFailoverTestCheck())
    registry.register_check(ACGRPhoneNumberBindingCheck())
    # Other resilience checks.
    registry.register_check(CloudWatchAlarmMonitoringCheck())
    registry.register_check(CarrierDiversityCheck())
    registry.register_check(HardcodedRoutingCheck())
    if include_flow_checks:
        registry.register_check(LambdaDependencyRiskCheck())
