"""
Contact flow parsing package.

Public surface for parsing Amazon Connect contact flow JSON into a structured,
analyzable graph and running graph, pattern, and structural analysis over it.

Each concern is a separate module so it can evolve independently:
- ``contact_flow_parser``: JSON <-> ContactFlowGraph (round-trip)
- ``flow_graph``: cycle detection, paths, route length, reachability
- ``flow_patterns``: auth / personalization / transfer / self-service detection
- ``flow_complexity``: descriptive structural metrics (not a compliance score)
"""

from .contact_flow_parser import ContactFlowParseError, ContactFlowParser
from .flow_complexity import calculate_flow_metrics
from .flow_graph import (
    count_paths,
    count_paths_bounded,
    detect_cycles,
    longest_simple_path_analysis,
    longest_simple_path_length,
    reachable_from_entry,
    successors,
)
from .flow_patterns import (
    detect_authentication,
    detect_patterns,
    detect_personalization,
    detect_self_service,
    detect_transfers,
    is_default_sample_flow,
)

__all__ = [
    "ContactFlowParser",
    "ContactFlowParseError",
    "detect_cycles",
    "count_paths",
    "count_paths_bounded",
    "longest_simple_path_analysis",
    "longest_simple_path_length",
    "reachable_from_entry",
    "successors",
    "detect_patterns",
    "detect_authentication",
    "detect_personalization",
    "detect_transfers",
    "detect_self_service",
    "is_default_sample_flow",
    "calculate_flow_metrics",
]
