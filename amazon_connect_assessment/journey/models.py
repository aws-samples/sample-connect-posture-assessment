"""
Data models for Caller Journey Mapping.

These represent the telephony topology, cross-flow super-graph, enumerated
paths, and per-journey scoring used by the journey mapping pipeline.
"""

import hashlib
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PhoneNumberEntry:
    """A phone number (DID or toll-free) mapped to its entry flow."""

    phone_number: str
    number_type: str  # "DID" | "TOLL_FREE"
    country_code: str
    contact_flow_id: Optional[str] = None
    contact_flow_name: Optional[str] = None
    target_arn: Optional[str] = None


@dataclass
class TierAssignment:
    """Tier classification for a flow with rationale."""

    flow_id: str
    flow_name: str
    tier: str  # "tier1_did" | "tier1_tollfree" | "tier2_traffic" | "tier3_dormant"
    rationale: str
    contact_count_30d: Optional[int] = None


@dataclass
class JourneyNode:
    """A node in the super-graph, referencing both its source flow and action."""

    flow_id: str
    flow_name: str
    action_id: str
    action_type: str
    parameters: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> str:
        """Unique key combining flow and action for graph lookups."""
        return f"{self.flow_id}::{self.action_id}"


@dataclass
class JourneyPath:
    """A complete caller journey from phone number entry to terminal outcome."""

    entry_number: str
    entry_number_type: str  # "DID" | "TOLL_FREE"
    nodes: List[JourneyNode] = field(default_factory=list)
    terminal_type: str = ""
    # "agent_queue" | "disconnect" | "callback" | "bot_resolved" |
    # "external_transfer" | "voicemail"
    terminal_details: Dict[str, Any] = field(default_factory=dict)
    flows_traversed: List[str] = field(default_factory=list)

    @property
    def path_hash(self) -> str:
        """Deterministic hash for deduplication and scoring lookup."""
        key = "|".join(n.key for n in self.nodes)
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    @property
    def depth(self) -> int:
        return len(self.nodes)


@dataclass
class JourneyScore:
    """Scoring results for a single journey path."""

    # Security
    has_authentication: bool = False
    auth_position: Optional[int] = None

    # Self-service / containment
    has_self_service: bool = False
    self_service_actions: List[str] = field(default_factory=list)

    # Resilience
    has_callback_offering: bool = False
    dead_end_count: int = 0
    consecutive_no_error_max: int = 0
    single_queue_funnel: bool = False

    # CX
    has_personalization: bool = False
    has_returning_caller_detection: bool = False
    has_dynamic_prompt: bool = False
    has_nlu_bot: bool = False

    # Aggregate
    cx_maturity: str = "Basic"  # "Basic" | "Intermediate" | "Advanced"
    deficiencies: List[str] = field(default_factory=list)

    @property
    def cx_feature_count(self) -> int:
        return sum(
            [
                self.has_personalization,
                self.has_callback_offering,
                self.has_returning_caller_detection,
                self.has_dynamic_prompt,
                self.has_nlu_bot,
            ]
        )


@dataclass
class SuperGraph:
    """
    Instance-wide directed graph spanning multiple contact flows.

    Nodes are JourneyNodes; edges cross flow boundaries at transfer points.
    """

    nodes: Dict[str, JourneyNode] = field(default_factory=dict)
    adjacency: Dict[str, List[str]] = field(default_factory=dict)
    entry_points: Dict[str, str] = field(default_factory=dict)
    # flow_id → entry node key
    dynamic_references: List[Dict[str, Any]] = field(default_factory=list)

    def successors(self, node_key: str) -> List[str]:
        return self.adjacency.get(node_key, [])

    def get_node(self, node_key: str) -> Optional[JourneyNode]:
        return self.nodes.get(node_key)


@dataclass
class JourneyMapResult:
    """Complete journey mapping results for the instance."""

    phone_entries: List[PhoneNumberEntry] = field(default_factory=list)
    tier_assignments: List[TierAssignment] = field(default_factory=list)
    journeys: List[JourneyPath] = field(default_factory=list)
    scores: Dict[str, JourneyScore] = field(default_factory=dict)
    dormant_flows: List[str] = field(default_factory=list)
    dynamic_edges: List[Dict[str, Any]] = field(default_factory=list)
    containment_scores: Dict[str, float] = field(default_factory=dict)

    @property
    def total_journeys(self) -> int:
        return len(self.journeys)

    @property
    def journeys_without_auth(self) -> int:
        return sum(
            1
            for j in self.journeys
            if j.terminal_type == "agent_queue"
            and not self.scores.get(j.path_hash, JourneyScore()).has_authentication
        )

    @property
    def journeys_without_self_service(self) -> int:
        return sum(
            1
            for j in self.journeys
            if not self.scores.get(j.path_hash, JourneyScore()).has_self_service
        )
