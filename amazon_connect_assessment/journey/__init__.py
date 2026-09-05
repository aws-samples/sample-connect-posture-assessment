"""
Caller Journey Mapping and Scoring.

Stitches individual contact flow graphs into an instance-wide super-graph,
enumerates all caller journeys from DID/toll-free entry points, and scores
them for security/containment/resilience/CX gaps. Produces the
``journey-*`` findings that surface in the assessment report.

Diagram rendering for the top-N flows lives in :mod:`journey.renderer`
(Mermaid ``flowchart TD``) and is invoked separately by the engine.

Usage:
    from amazon_connect_assessment.journey import run_journey_mapping
    output = run_journey_mapping(instance, parsed_flows, factory, config)
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List

from ..aws_client_factory import AWSClientFactory
from ..models import ConnectInstance, ContactFlowGraph, Finding
from .models import JourneyMapResult


@dataclass
class JourneyMappingOutput:
    """Output container for journey mapping results + findings."""

    result: JourneyMapResult
    findings: List[Finding] = field(default_factory=list)


def run_journey_mapping(
    instance: ConnectInstance,
    parsed_flows: Dict[str, ContactFlowGraph],
    factory: AWSClientFactory,
    config: Dict[str, Any],
) -> JourneyMappingOutput:
    """
    Execute the full journey mapping pipeline.

    Steps:
    1. Resolve topology (phone numbers → flows, tier classification)
    2. Build super-graph (stitch flows at transfer boundaries)
    3. Enumerate paths (bounded DFS from each entry point)
    4. Score journeys (security, containment, resilience, CX)
    5. Generate findings

    Returns:
        JourneyMappingOutput with findings and result data for reporting.
    """
    from .journey_scorer import generate_journey_findings, score_journeys
    from .path_enumerator import enumerate_journeys
    from .super_graph import build_super_graph
    from .topology import resolve_topology

    # Step 1: Topology resolution
    phone_entries, tier_assignments = resolve_topology(
        instance_id=instance.instance_id,
        instance_arn=instance.instance_arn,
        factory=factory,
        parsed_flows=parsed_flows,
        config=config,
    )

    # Step 2: Build super-graph (tier 1 + tier 2 only)
    super_graph = build_super_graph(parsed_flows, tier_assignments)

    # Step 3: Enumerate paths
    max_paths = config.get("journey_map", {}).get("max_paths_per_did", 200)
    max_depth = config.get("journey_map", {}).get("max_depth", 50)
    journeys = enumerate_journeys(
        super_graph=super_graph,
        phone_entries=phone_entries,
        max_paths=max_paths,
        max_depth=max_depth,
    )

    # Step 4: Score journeys
    scores = score_journeys(journeys, config)

    # Step 5: Assemble result
    dormant_flows = [t.flow_id for t in tier_assignments if t.tier == "tier3_dormant"]
    containment_scores = _compute_containment_scores(phone_entries, journeys, scores)

    result = JourneyMapResult(
        phone_entries=phone_entries,
        tier_assignments=tier_assignments,
        journeys=journeys,
        scores=scores,
        dormant_flows=dormant_flows,
        dynamic_edges=super_graph.dynamic_references,
        containment_scores=containment_scores,
    )

    # Step 6: Generate findings
    findings = generate_journey_findings(result)

    return JourneyMappingOutput(result=result, findings=findings)


def _compute_containment_scores(
    phone_entries: List, journeys: List, scores: Dict
) -> Dict[str, float]:
    """Compute per-number containment score (% paths resolving without agent)."""
    result: Dict[str, float] = {}
    for entry in phone_entries:
        entry_journeys = [j for j in journeys if j.entry_number == entry.phone_number]
        if not entry_journeys:
            result[entry.phone_number] = 0.0
            continue
        non_agent = sum(1 for j in entry_journeys if j.terminal_type != "agent_queue")
        result[entry.phone_number] = non_agent / len(entry_journeys) * 100
    return result
