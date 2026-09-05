"""
Assessment engine for orchestrating Amazon Connect evaluations.

The AssessmentEngine coordinates the entire assessment process including
instance discovery, component analysis, check execution, and result collection.
"""

import json
import logging
import os
import platform
import sys
import time
import uuid
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional, Tuple

from .analyzers import BaseAnalyzer
from .aws_client_factory import AWSClientFactory
from .checks import CheckContext, CheckRegistry
from .checks.mvp_remediation_enricher import enrich_finding
from .models import (
    AssessmentMetadata,
    AssessmentResult,
    AssessmentSummary,
    CheckStatus,
    ConnectInstance,
    ContactFlowGraph,
    Finding,
)


class _AccessDeniedListingPhoneNumbers(Exception):
    """
    Internal sentinel for the Caller Journey Map pipeline. Raised by
    :meth:`AssessmentEngine._list_phone_numbers_for_instance` when the
    ListPhoneNumbersV2 call is rejected as unauthorized. The empty-state
    diagnostic distinguishes this from other listing errors so it can
    tell the reader exactly which IAM permission is missing.
    """


class _AccessDeniedListingFlowAssociations(Exception):
    """
    Internal sentinel for the Caller Journey Map pipeline. Raised by
    :meth:`AssessmentEngine._list_flow_associations_for_instance` when the
    ListFlowAssociations call is rejected as unauthorized. Kept distinct
    from :class:`_AccessDeniedListingPhoneNumbers` because it names a
    different IAM permission (``connect:ListFlowAssociations``) in the
    empty-state diagnostic.
    """


class AssessmentEngine:
    def __init__(
        self,
        aws_client_factory: AWSClientFactory,
        config: Dict[str, Any] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
        checkpoint_dir: Optional[str] = None,
    ):
        """
        Initialize the assessment engine.

        Args:
            aws_client_factory: AWSClientFactory instance for AWS service clients
            config: Optional configuration dictionary
            progress_callback: Optional callback function for progress updates
            checkpoint_dir: Optional directory for checkpoint storage
        """
        self.aws_client_factory = aws_client_factory
        self.config = config or {}
        self.check_registry = CheckRegistry()
        self.analyzers: List[BaseAnalyzer] = []
        self.logger = logging.getLogger("assessment_engine")

        # Progress tracking
        self.progress_callback = progress_callback
        self._current_step = 0
        self._total_steps = 0
        self._step_descriptions = []

        # Checkpoint recovery — use a user-private directory by default
        if checkpoint_dir:
            self.checkpoint_dir = checkpoint_dir
        else:
            default_dir = os.path.join(
                os.path.expanduser("~"), ".amazon-connect-assessment", "checkpoints"
            )
            os.makedirs(default_dir, mode=0o700, exist_ok=True)
            self.checkpoint_dir = default_dir
        self._checkpoint_enabled = True
        self._current_checkpoint_file: Optional[str] = None

        # Assessment state
        self._start_time: Optional[float] = None
        self._execution_errors: List[str] = []
        self._assessment_id: Optional[str] = None

    def add_analyzer(self, analyzer: BaseAnalyzer) -> None:
        self.analyzers.append(analyzer)
        self.logger.debug(f"Added analyzer: {analyzer}")

    def enable_checkpoints(self, enabled: bool = True) -> None:
        self._checkpoint_enabled = enabled
        self.logger.debug(f"Checkpoint recovery {'enabled' if enabled else 'disabled'}")

    def _update_progress(self, description: str) -> None:
        self._current_step += 1
        self.logger.info(f"Workflow step {self._current_step}/{self._total_steps}: {description}")

        if self.progress_callback:
            try:
                self.progress_callback(description, self._current_step, self._total_steps)
            except Exception as e:
                self.logger.warning(f"Progress callback failed: {str(e)}")

    def _initialize_progress_tracking(self, instance_count: int) -> None:
        # Calculate total steps: discovery + (analysis + checks) per instance + finalization
        self._total_steps = 1 + (instance_count * 2) + 1
        # Discovery has already completed before this method is called.
        self._current_step = 1
        self._step_descriptions = [
            "Discovering Connect instances",
            *[f"Analyzing instance {i + 1}" for i in range(instance_count)],
            *[f"Executing checks for instance {i + 1}" for i in range(instance_count)],
            "Generating final results",
        ]

    def _save_checkpoint(self, checkpoint_data: Dict[str, Any]) -> None:
        """Save assessment progress to a checkpoint file with restricted permissions."""
        if not self._checkpoint_enabled or not self._assessment_id:
            return

        try:
            checkpoint_file = os.path.join(
                self.checkpoint_dir, f"assessment_checkpoint_{self._assessment_id}.json"
            )

            checkpoint_data.update(
                {
                    "assessment_id": self._assessment_id,
                    "timestamp": datetime.now().isoformat(),
                    "current_step": self._current_step,
                    "total_steps": self._total_steps,
                    "execution_errors": self._execution_errors,
                }
            )

            # Write with restrictive permissions (owner read/write only)
            fd = os.open(checkpoint_file, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(checkpoint_data, f, indent=2, default=str)

            self._current_checkpoint_file = checkpoint_file
            self.logger.debug(f"Checkpoint saved: {checkpoint_file}")

        except Exception as e:
            self.logger.warning(f"Failed to save checkpoint: {str(e)}")

    def _load_checkpoint(self, assessment_id: str) -> Optional[Dict[str, Any]]:
        """
        Load assessment progress from checkpoint file.

        Args:
            assessment_id: Assessment ID to load checkpoint for

        Returns:
            Checkpoint data if found, None otherwise
        """
        if not self._checkpoint_enabled:
            return None

        try:
            checkpoint_file = os.path.join(
                self.checkpoint_dir, f"assessment_checkpoint_{assessment_id}.json"
            )

            if not os.path.exists(checkpoint_file):
                return None

            with open(checkpoint_file, "r") as f:
                checkpoint_data = json.load(f)

            self.logger.info(f"Loaded checkpoint: {checkpoint_file}")
            return checkpoint_data

        except Exception as e:
            self.logger.warning(f"Failed to load checkpoint: {str(e)}")
            return None

    def _cleanup_checkpoint(self) -> None:
        if self._current_checkpoint_file and os.path.exists(self._current_checkpoint_file):
            try:
                os.remove(self._current_checkpoint_file)
                self.logger.debug(f"Cleaned up checkpoint: {self._current_checkpoint_file}")
            except Exception as e:
                self.logger.warning(f"Failed to cleanup checkpoint: {str(e)}")

    def resume_assessment(self, assessment_id: str) -> Optional[AssessmentResult]:
        """
        Resume a previously interrupted assessment from checkpoint.

        Currently restarts the assessment with the same ID. True incremental
        resume (skipping already-completed instances) is not yet implemented.

        Returns:
            AssessmentResult if checkpoint found, None if no checkpoint exists.
        """
        checkpoint_data = self._load_checkpoint(assessment_id)
        if not checkpoint_data:
            self.logger.info(f"No checkpoint found for assessment {assessment_id}")
            return None

        self.logger.warning(
            f"Resuming assessment {assessment_id} — note: this re-runs the full "
            f"assessment with the same ID (incremental resume not yet supported)"
        )
        self._assessment_id = assessment_id
        self._execution_errors = checkpoint_data.get("execution_errors", [])
        return self.run_assessment()

    def run_assessment(self) -> AssessmentResult:
        """
        Execute a complete Amazon Connect assessment.

        Orchestrates the entire assessment process including:
        1. Instance discovery
        2. Component analysis
        3. Check execution
        4. Result collection and summarization

        Returns:
            AssessmentResult: Complete assessment results
        """
        self._start_time = time.time()
        self._execution_errors.clear()

        # Generate assessment ID if not resuming
        if not self._assessment_id:
            self._assessment_id = str(uuid.uuid4())

        assessment_id = self._assessment_id
        self.logger.info(f"Starting assessment {assessment_id}")

        try:
            # Discover Connect instances
            # The instance count is needed to calculate the workflow-step
            # denominator, so discovery cannot be emitted as a numbered step
            # until after it completes.
            self.logger.info("Discovering Connect instances")
            instances = self.discover_instances()
            self.logger.info(f"Discovered {len(instances)} Connect instances")

            # Initialize progress tracking based on discovered instances
            if self._total_steps == 0:  # Only initialize if not resuming
                self._initialize_progress_tracking(len(instances))

            # Save initial checkpoint
            self._save_checkpoint(
                {
                    "phase": "discovery_complete",
                    "instances_discovered": len(instances),
                    "instance_ids": [inst.instance_id for inst in instances],
                }
            )

            # Analyze components for each instance
            analyzed_instances = []
            for i, instance in enumerate(instances):
                try:
                    self._update_progress(f"Analyzing instance {instance.instance_id}")
                    analyzed_instance = self.analyze_instance(instance)
                    analyzed_instances.append(analyzed_instance)

                    # Save checkpoint after each instance analysis
                    self._save_checkpoint(
                        {
                            "phase": "analysis_in_progress",
                            "analyzed_instances": i + 1,
                            "total_instances": len(instances),
                        }
                    )

                except Exception as e:
                    error_msg = f"Failed to analyze instance {instance.instance_id}: {str(e)}"
                    self.logger.error(error_msg)
                    self._execution_errors.append(error_msg)
                    # Include the instance even if analysis failed
                    analyzed_instances.append(instance)

            # Execute checks for all instances
            all_findings = []
            for i, instance in enumerate(analyzed_instances):
                try:
                    self._update_progress(f"Executing checks for instance {instance.instance_id}")
                    findings = self.execute_checks(instance)
                    all_findings.extend(findings)
                    self.logger.info(
                        f"Executed {len(findings)} checks for instance {instance.instance_id}"
                    )

                    # Save checkpoint after each instance's checks
                    self._save_checkpoint(
                        {
                            "phase": "checks_in_progress",
                            "checked_instances": i + 1,
                            "total_instances": len(analyzed_instances),
                            "findings_count": len(all_findings),
                        }
                    )

                except Exception as e:
                    error_msg = (
                        f"Failed to execute checks for instance {instance.instance_id}: {str(e)}"
                    )
                    self.logger.error(error_msg)
                    self._execution_errors.append(error_msg)

            # Caller Journey Mapping findings (journey-sec-001,
            # journey-cost-001, journey-res-001, journey-scope-001). This
            # is a separate pipeline from the check registry — it stitches
            # per-flow graphs into an instance-wide super-graph, enumerates
            # bounded caller paths from each phone number, and scores them.
            # These findings were previously documented in
            # docs/check-catalog.md and fully implemented in
            # journey.run_journey_mapping(), but no execution path ever
            # called it, so they never appeared in a report despite being
            # advertised. See _compute_journey_findings for the per-
            # instance error handling.
            all_findings.extend(self._compute_journey_findings(analyzed_instances))

            # Generate summary and metadata
            self._update_progress("Generating final results")
            summary = self._generate_summary(all_findings)
            # Generate metadata first to get account info
            metadata = self._generate_metadata()

            # Get account ID and region from metadata or extract from instances
            account_id = metadata.aws_account_id
            region = metadata.aws_region

            # If still unknown, try to extract from Connect instance ARNs
            if account_id == "unknown" and analyzed_instances:
                try:
                    # Extract account ID from first instance ARN
                    # ARN format: arn:aws:connect:region:account-id:instance/instance-id
                    first_instance_arn = analyzed_instances[0].instance_arn
                    if first_instance_arn:
                        arn_parts = first_instance_arn.split(":")
                        if len(arn_parts) >= 5:
                            account_id = arn_parts[4]
                            self.logger.debug(
                                f"Extracted account ID from instance ARN: {account_id}"
                            )
                except Exception as e:
                    self.logger.debug(f"Could not extract account ID from instance ARN: {str(e)}")

            # If region still unknown, try to extract from instances
            if region == "unknown" and analyzed_instances:
                try:
                    # Extract region from first instance ARN
                    first_instance_arn = analyzed_instances[0].instance_arn
                    if first_instance_arn:
                        arn_parts = first_instance_arn.split(":")
                        if len(arn_parts) >= 4:
                            region = arn_parts[3]
                            self.logger.debug(f"Extracted region from instance ARN: {region}")
                except Exception as e:
                    self.logger.debug(f"Could not extract region from instance ARN: {str(e)}")

            # Build the Caller Journey Map — one entry per inbound phone
            # number that targets a contact flow. Runs after checks so
            # anything the checks fetched (phone-number caches, etc.)
            # is available. Never fails the assessment on its own
            # errors.
            journey_map_entries, journey_map_status = self._compute_journey_map(analyzed_instances)

            # Create final result
            result = AssessmentResult(
                assessment_id=assessment_id,
                timestamp=datetime.now(),
                account_id=account_id,
                region=region,
                instances=analyzed_instances,
                findings=all_findings,
                summary=summary,
                metadata=metadata,
                execution_errors=self._execution_errors.copy(),
                journey_map_entries=journey_map_entries,
                journey_map_status=journey_map_status,
            )

            execution_time = time.time() - self._start_time
            self.logger.info(
                f"Assessment {assessment_id} completed in {execution_time:.2f} seconds"
            )
            self.logger.info(
                f"Results: {summary.total_checks} checks, {summary.failed_checks} failures"
            )

            # Clean up checkpoint on successful completion
            self._cleanup_checkpoint()

            return result

        except Exception as e:
            error_msg = f"Assessment failed: {str(e)}"
            self.logger.error(error_msg)
            self._execution_errors.append(error_msg)

            # Save error checkpoint for potential debugging
            self._save_checkpoint(
                {
                    "phase": "failed",
                    "error": error_msg,
                    "execution_errors": self._execution_errors,
                }
            )

            raise

    def discover_instances(self) -> List[ConnectInstance]:
        """
        Discover Amazon Connect instances in the target account.

        Paginates through all results to ensure no instances are missed.
        If config contains aws.instance_id, only that instance is assessed.
        """
        self.logger.debug("Starting Connect instance discovery")

        try:
            # Paginate through all instances
            instance_summaries = []
            next_token = None
            while True:
                kwargs = {}
                if next_token:
                    kwargs["NextToken"] = next_token
                response = self.aws_client_factory.list_connect_instances_resilient(**kwargs)
                instance_summaries.extend(response.get("InstanceSummaryList", []))
                next_token = response.get("NextToken")
                if not next_token:
                    break

            # Filter to a single instance if --instance-id was provided
            target_instance_id = self.config.get("aws", {}).get("instance_id")
            if target_instance_id:
                instance_summaries = [
                    s for s in instance_summaries if s["Id"] == target_instance_id
                ]
                if not instance_summaries:
                    self.logger.warning(f"Instance {target_instance_id} not found in account")

            instances = []
            for instance_summary in instance_summaries:
                try:
                    # Get detailed instance information
                    instance_id = instance_summary["Id"]
                    detail_response = self.aws_client_factory.describe_connect_instance_resilient(
                        instance_id
                    )
                    instance_detail = detail_response["Instance"]

                    # Create ConnectInstance object
                    instance = ConnectInstance(
                        instance_id=instance_id,
                        instance_arn=instance_detail["Arn"],
                        identity_management_type=instance_detail["IdentityManagementType"],
                        inbound_calls_enabled=instance_detail["InboundCallsEnabled"],
                        outbound_calls_enabled=instance_detail["OutboundCallsEnabled"],
                        instance_alias=instance_detail.get("InstanceAlias"),
                        service_role=instance_detail.get("ServiceRole"),
                        status=instance_detail.get("InstanceStatus"),
                    )

                    instances.append(instance)
                    self.logger.debug(f"Discovered instance: {instance_id}")

                except Exception as e:
                    error_msg = f"Failed to get details for instance {instance_summary.get('Id', 'unknown')}: {str(e)}"
                    self.logger.error(error_msg)
                    self._execution_errors.append(error_msg)

            return instances

        except Exception as e:
            self.logger.error(f"Instance discovery failed: {str(e)}")
            raise

    def analyze_instance(self, instance: ConnectInstance) -> ConnectInstance:
        """
        Analyze all components of a Connect instance.

        Args:
            instance: ConnectInstance to analyze

        Returns:
            ConnectInstance: Instance with populated component data
        """
        self.logger.debug(f"Analyzing instance {instance.instance_id}")

        analyzed_instance = instance
        for analyzer in self.analyzers:
            analyzed_instance = analyzer.safe_analyze(analyzed_instance)
            if analyzer.last_error:
                self._execution_errors.append(analyzer.last_error)

        return analyzed_instance

    def execute_checks(self, instance: ConnectInstance) -> List[Finding]:
        """
        Execute all registered checks against a Connect instance.

        Args:
            instance: ConnectInstance to check

        Returns:
            List[Finding]: Results from all check executions
        """
        self.logger.debug(f"Executing checks for instance {instance.instance_id}")

        checks = self.check_registry.get_all_checks()
        findings = []

        # Create check context
        context = CheckContext(
            instance=instance,
            aws_client_factory=self.aws_client_factory,
            config=self.config,
            logger=self.logger,
        )

        for check in checks:
            try:
                finding = check.safe_execute(context)
                findings.append(finding)
            except Exception as e:
                error_msg = (
                    f"Check {check.check_id} failed for instance {instance.instance_id}: {str(e)}"
                )
                self.logger.error(error_msg)
                self._execution_errors.append(error_msg)

        for finding in findings:
            enrich_finding(finding)

        return findings

    def _compute_journey_findings(self, instances: List[ConnectInstance]) -> List[Finding]:
        """
        Run the Caller Journey Mapping pipeline and return its findings.

        This is the wiring that was missing entirely: ``journey.
        run_journey_mapping()`` builds a per-instance super-graph, walks
        bounded caller paths from each phone number, scores them, and
        produces ``journey-sec-001`` / ``journey-cost-001`` /
        ``journey-res-001`` / ``journey-scope-001`` findings — but no
        engine ever called it, so those findings never reached a report
        despite being documented in the check catalog and having
        ``--skip-flow-analysis`` semantics baked in already
        (``run_journey_mapping`` is only meaningful when flow content was
        fetched, which it isn't when flow analysis is skipped).

        Respects ``skip_flow_analysis`` the same way ``_compute_journey_map``
        does (checks both the top-level and ``config["cli"]`` locations —
        see that method's docstring for why). Fails open per instance: an
        error building the super-graph or scoring paths for one instance
        logs a warning and moves on rather than failing the assessment.
        """
        if self.config.get("skip_flow_analysis") or self.config.get("cli", {}).get(
            "skip_flow_analysis"
        ):
            return []

        if not instances:
            return []

        from . import journey
        from .parsers import ContactFlowParser

        parser = ContactFlowParser()
        findings: List[Finding] = []

        for instance in instances:
            if not instance.contact_flows:
                continue

            parsed_flows: Dict[str, Any] = {}
            for flow in instance.contact_flows:
                if not flow.content:
                    continue
                try:
                    graph = parser.parse(flow.content)
                    # ContactFlowParser reads flow_id/flow_name from the
                    # parsed JSON's "Identifier"/"Name" keys, but the raw
                    # Content blob returned by DescribeContactFlow never
                    # carries those fields — Id and Name live on the outer
                    # ContactFlow API object, not inside Content. Left
                    # unset, graph.flow_id is "" for every flow, which
                    # collapses every flow's nodes onto the same
                    # "::action_id" key in the super-graph (a real
                    # cross-flow collision, not just a cosmetic label
                    # gap) and makes every flow's entry point overwrite
                    # the same "" dict key. Backfill both from the
                    # ContactFlow object we already have.
                    graph.flow_id = flow.id
                    graph.flow_name = flow.name
                    parsed_flows[flow.id] = graph
                except Exception as e:  # noqa: BLE001
                    self.logger.debug(
                        "Journey mapping: skipping unparseable flow %s (%s): %s",
                        flow.id,
                        flow.name,
                        e,
                    )

            if not parsed_flows:
                continue

            try:
                output = journey.run_journey_mapping(
                    instance=instance,
                    parsed_flows=parsed_flows,
                    factory=self.aws_client_factory,
                    config=self.config,
                )
                findings.extend(output.findings)
                self.logger.info(
                    "Journey mapping for %s: %d journey(s) enumerated, %d finding(s)",
                    instance.display_name,
                    output.result.total_journeys,
                    len(output.findings),
                )
            except Exception as e:  # noqa: BLE001
                error_msg = f"Journey mapping failed for instance {instance.instance_id}: {e}"
                self.logger.warning(error_msg)
                self._execution_errors.append(error_msg)

        return findings

    def _compute_journey_map(
        self, instances: List[ConnectInstance]
    ) -> Tuple[List[Dict[str, Any]], Optional[Dict[str, str]]]:
        """
        Build the Caller Journey Map entries the HTML report renders.

        This is a **phone-number-first** view: we only surface flows
        that a real DID or toll-free number actually terminates on.
        Rationale: those are the flows a caller can reach from outside,
        so those are the flows worth walking through when reviewing
        the customer experience. Flows that exist in the instance but
        aren't wired to any inbound number (subflows, test flows,
        internal transfer targets, AWS-provided defaults) are
        deliberately excluded — they're not entry points.

        Flow association is resolved via ``connect:ListFlowAssociations``
        across every phone-number resource type it supports (voice, SMS,
        WhatsApp), matched to each number by its ``PhoneNumberArn``. This
        is *not* the same as checking
        ``ListPhoneNumbersV2``'s ``TargetArn`` field for a
        ``/contact-flow/`` substring — AWS documents ``TargetArn`` as
        "the ARN for Connect instances or traffic distribution groups
        that phone number inbound traffic is routed through", i.e. it
        is always an instance/TDG ARN, never a contact-flow ARN,
        regardless of what flow is assigned in the console. An earlier
        version of this method checked ``TargetArn`` for
        ``/contact-flow/`` and so never matched a single real-world
        number, producing an empty map even when every number was
        correctly bound to a flow. ``ListFlowAssociations`` is the API
        that actually returns the phone-number -> flow mapping the
        Connect console's "Contact flow / IVR" field reflects.

        Returns ``(entries, status)``:

          * ``entries`` — one dict per (instance, phone number) pair
            with a flow association on any voice/SMS/WhatsApp channel.
            Shape::

                {
                    "instance_id":            "…",
                    "instance_display_name":  "sushant-cc",
                    "phone_number":           "+18005551234",
                    "phone_type":             "DID" | "TOLL_FREE" | "SHORT_CODE" | …,
                    "phone_country_code":     "US",
                    "phone_description":      "…" (may be empty),
                    "flow_id":                "…",
                    "flow_name":              "Main IVR",
                    "flow_type":              "CONTACT_FLOW",
                    "diagram_html":           "<div class=\\"jm-canvas\\">…",
                    "diagram_model":          {
                        "schema_version": 1,
                        "nodes": {"node-0": {…}},
                        "edges": {"edge-0": {…}},
                        "primary_path": ["node-0", …],
                    },
                    "exports": {
                        "schema_version": 1,
                        "formats": {
                            "svg": {
                                "content": "<svg …>…</svg>",
                                "media_type": "image/svg+xml",
                                "width": 1234,
                                "height": 567,
                            },
                            "drawio": {
                                "content": "<mxfile>…</mxfile>",
                                "media_type": "application/vnd.jgraph.mxfile",
                            },
                        },
                    },
                }

            Sorted deterministically: instance display name, then
            phone number, so the report's dropdown order is stable.

          * ``status`` — ``None`` when ``entries`` is non-empty. When
            empty, a ``{reason, message, hint}`` dict that explains
            *why* the map is empty, in plain English (matching the
            Batch 3 empty-state pattern).

        Fail-open: no error inside this method fails the assessment.
        Config knob: ``skip_flow_analysis`` skips the whole section.
        """
        # NOTE: the CLI stores this flag under config["cli"]["skip_flow_analysis"]
        # (see cli.py merge_cli_args_with_config), not at the top level. Check
        # both so --skip-flow-analysis actually disables the Journey Map's
        # ListPhoneNumbersV2 + flow-render API path, and config-file callers
        # that set a top-level key keep working too.
        if self.config.get("skip_flow_analysis") or self.config.get("cli", {}).get(
            "skip_flow_analysis"
        ):
            return [], {
                "reason": "skipped_by_config",
                "message": (
                    "The Caller Journey Map was skipped because "
                    "`skip_flow_analysis` is set in your run "
                    "configuration."
                ),
                "hint": (
                    "Re-run without `--skip-flow-analysis` (CLI) or "
                    "with `skip_flow_analysis: false` (config) to "
                    "draw the map."
                ),
            }

        if not instances:
            return [], {
                "reason": "no_instances",
                "message": (
                    "No Amazon Connect instances were discovered in "
                    "this account/region, so there is nothing to draw "
                    "a caller journey for."
                ),
                "hint": (
                    "Verify the AWS credentials and region point to "
                    "the account that owns your Connect instance."
                ),
            }

        # Deferred imports keep the sequential-engine startup path
        # lean and let unit tests that never invoke this method run
        # without the renderer/parser dependencies loaded.
        from .journey.renderer import flow_to_diagram_artifacts
        from .parsers import ContactFlowParser

        parser = ContactFlowParser()
        entries: List[Dict[str, Any]] = []

        # Diagnostic accumulators so we can produce a useful empty-
        # state explanation instead of a silent empty section.
        list_denied_permission: Optional[str] = None
        list_error_first: Optional[str] = None
        instances_seen_numbers = 0
        instances_with_flow_bound_numbers = 0
        numbers_bound_to_non_flow = 0  # Point at queues/etc, not flows

        # Optional read-only identity enrichment is cached across every flow in
        # the run. A cached None records a failed/denied lookup so one missing
        # permission never causes repeated calls or suppresses the diagram.
        lex_bot_cache: Dict[str, Optional[Dict[str, Any]]] = {}
        lex_alias_cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]] = {}
        q_assistant_cache: Dict[str, Optional[Dict[str, Any]]] = {}
        queue_cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]] = {}

        for instance in instances:
            try:
                numbers = self._list_phone_numbers_for_instance(instance)
            except _AccessDeniedListingPhoneNumbers:
                list_denied_permission = "connect:ListPhoneNumbersV2"
                continue
            except Exception as e:  # noqa: BLE001
                list_error_first = list_error_first or f"{instance.display_name}: {e}"
                self.logger.warning(
                    "ListPhoneNumbersV2 failed for %s: %s",
                    instance.display_name,
                    e,
                )
                continue

            if not numbers:
                continue
            instances_seen_numbers += 1

            # ListPhoneNumbersV2's TargetArn is the instance/TDG ARN the
            # number is claimed to, not the flow it's assigned to — see
            # the docstring above. The number -> flow mapping comes from
            # ListFlowAssociations, keyed by the number's PhoneNumberArn.
            try:
                flow_id_by_phone_arn = self._list_flow_associations_for_instance(instance)
            except _AccessDeniedListingFlowAssociations:
                list_denied_permission = "connect:ListFlowAssociations"
                continue
            except Exception as e:  # noqa: BLE001
                list_error_first = list_error_first or f"{instance.display_name}: {e}"
                self.logger.warning(
                    "ListFlowAssociations failed for %s: %s",
                    instance.display_name,
                    e,
                )
                continue

            flow_by_id = {f.id: f for f in instance.contact_flows}
            # Render each targeted flow only once per instance — many
            # numbers can share a flow (main line + spillover + toll-
            # free all pointing at "Main IVR").
            rendered: Dict[str, Any] = {}
            instance_has_flow_bound_number = False

            for num in numbers:
                phone_arn = num.get("PhoneNumberArn") or ""
                flow_id = flow_id_by_phone_arn.get(phone_arn)
                if not flow_id:
                    # No VOICE_PHONE_NUMBER flow association — points at
                    # a queue, agent, or is unassigned. Still counted so
                    # the empty-state reason is honest.
                    numbers_bound_to_non_flow += 1
                    continue

                instance_has_flow_bound_number = True
                flow = flow_by_id.get(flow_id)
                if flow is None or not flow.content:
                    self.logger.debug(
                        "Phone %s targets flow %s but flow content is unavailable; skipping entry.",
                        num.get("PhoneNumber"),
                        flow_id,
                    )
                    continue

                if flow_id not in rendered:
                    try:
                        graph = parser.parse(flow.content)
                        # See _compute_journey_findings for why this
                        # backfill is needed — Content never carries
                        # Identifier/Name, so the parser can't set these
                        # itself. flow_to_diagram_html uses graph.flow_name
                        # in diagram placeholder text on render errors,
                        # so keep it populated here too.
                        graph.flow_id = flow_id
                        graph.flow_name = flow.name
                        self._enrich_journey_resource_details(
                            graph,
                            instance.instance_id,
                            lex_bot_cache,
                            lex_alias_cache,
                            q_assistant_cache,
                            queue_cache,
                        )
                        if graph.action_count == 0:
                            # AWS-provided template flows sometimes
                            # ship with an empty Actions array; skip
                            # rather than render an empty diagram.
                            self.logger.debug(
                                "Skipping journey-map diagram for %s (%s): graph has no actions",
                                flow_id,
                                flow.name,
                            )
                            continue
                        rendered[flow_id] = flow_to_diagram_artifacts(graph)
                    except Exception as e:  # noqa: BLE001
                        self.logger.warning(
                            "Diagram render failed for flow %s (%s): %s",
                            flow_id,
                            flow.name,
                            e,
                        )
                        continue

                if flow_id not in rendered:
                    continue

                artifacts = rendered[flow_id]
                entry = {
                    "instance_id": instance.instance_id,
                    "instance_display_name": instance.display_name,
                    "phone_number": num.get("PhoneNumber", "") or "",
                    "phone_type": num.get("PhoneNumberType", "") or "",
                    "phone_country_code": (num.get("PhoneNumberCountryCode", "") or ""),
                    "phone_description": num.get("PhoneNumberDescription", "") or "",
                    "flow_id": flow_id,
                    "flow_name": flow.name,
                    "flow_type": flow.type,
                    "diagram_html": artifacts.diagram_html,
                    "diagram_model": artifacts.diagram_model,
                    "exports": artifacts.export_payload(),
                }
                entries.append(entry)

            if instance_has_flow_bound_number:
                instances_with_flow_bound_numbers += 1

        # Deterministic order: instance name, then phone number.
        entries.sort(key=lambda e: (e["instance_display_name"], e["phone_number"]))

        if entries:
            return entries, None

        status = self._diagnose_empty_journey_map(
            list_denied_permission=list_denied_permission,
            list_error_first=list_error_first,
            instances_seen_numbers=instances_seen_numbers,
            instances_with_flow_bound_numbers=instances_with_flow_bound_numbers,
            numbers_bound_to_non_flow=numbers_bound_to_non_flow,
        )
        return entries, status

    def _enrich_journey_resource_details(
        self,
        graph: ContactFlowGraph,
        instance_id: str,
        lex_bot_cache: Dict[str, Optional[Dict[str, Any]]],
        lex_alias_cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]],
        q_assistant_cache: Dict[str, Optional[Dict[str, Any]]],
        queue_cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]],
    ) -> None:
        """Resolve optional reader-facing names without coupling rendering to AWS."""
        for action in graph.actions.values():
            if action.action_type in ("ConnectToLexBot", "ConnectParticipantWithLexBot"):
                details = self._resolve_journey_lex_details(
                    action.parameters,
                    lex_bot_cache,
                    lex_alias_cache,
                )
                if details:
                    action.resource_details["ai"] = details
            elif action.action_type == "CreateWisdomSession":
                details = self._resolve_journey_q_assistant_details(
                    action.parameters,
                    q_assistant_cache,
                )
                if details:
                    action.resource_details["q_connect_assistant"] = details
            elif action.action_type in (
                "UpdateContactTargetQueue",
                "TransferToQueue",
                "TransferContactToQueue",
            ):
                details = self._resolve_journey_queue_details(
                    instance_id,
                    action.parameters,
                    queue_cache,
                )
                if details:
                    action.resource_details["queue"] = details

    def _resolve_journey_lex_details(
        self,
        params: Dict[str, Any],
        bot_cache: Dict[str, Optional[Dict[str, Any]]],
        alias_cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]],
    ) -> Dict[str, str]:
        """Resolve Lex V2 names, retaining useful parameter-derived fallbacks."""
        nested = params.get("LexV2Bot") if isinstance(params, dict) else None
        if not isinstance(nested, dict):
            name = params.get("BotName") if isinstance(params, dict) else None
            alias = None
            if isinstance(params, dict):
                alias = params.get("BotAlias") or params.get("Alias")
            details = {
                "technology": "Amazon Lex",
                "identity": str(name or "Configured Lex bot"),
                "subtype": "V1 bot",
            }
            if alias:
                details["alias"] = str(alias)
            return details

        bot_id, alias_id = self._lex_v2_ids(nested)
        parameter_name = nested.get("Name") or nested.get("BotName")
        parameter_alias = nested.get("AliasName") or nested.get("BotAlias")
        details = {
            "technology": "Amazon Lex",
            "identity": str(parameter_name or "Configured Lex V2 bot"),
            "subtype": "V2 bot",
        }
        if parameter_alias:
            details["alias"] = str(parameter_alias)

        if bot_id:
            if bot_id not in bot_cache:
                try:
                    bot_cache[bot_id] = self.aws_client_factory.describe_lex_v2_bot_resilient(
                        bot_id
                    )
                except Exception as exc:  # noqa: BLE001
                    bot_cache[bot_id] = None
                    self.logger.debug("Lex V2 bot identity lookup failed for %s: %s", bot_id, exc)
            bot = bot_cache.get(bot_id) or {}
            name = bot.get("botName")
            if isinstance(name, str) and name.strip():
                details["identity"] = name.strip()

        if bot_id and alias_id:
            cache_key = (bot_id, alias_id)
            if cache_key not in alias_cache:
                try:
                    alias_cache[cache_key] = (
                        self.aws_client_factory.describe_lex_v2_bot_alias_resilient(
                            bot_id,
                            alias_id,
                        )
                    )
                except Exception as exc:  # noqa: BLE001
                    alias_cache[cache_key] = None
                    self.logger.debug(
                        "Lex V2 alias identity lookup failed for %s/%s: %s",
                        bot_id,
                        alias_id,
                        exc,
                    )
            alias = alias_cache.get(cache_key) or {}
            alias_name = alias.get("botAliasName")
            if isinstance(alias_name, str) and alias_name.strip():
                details["alias"] = alias_name.strip()
        return details

    def _resolve_journey_q_assistant_details(
        self,
        params: Dict[str, Any],
        assistant_cache: Dict[str, Optional[Dict[str, Any]]],
    ) -> Dict[str, str]:
        """Resolve the Amazon Q in Connect assistant used by a Wisdom session."""
        arn = params.get("WisdomAssistantArn") if isinstance(params, dict) else None
        if not isinstance(arn, str) or not arn.strip():
            return {"technology": "Amazon Q in Connect"}
        assistant_id = arn.rsplit("/", 1)[-1]
        details = {
            "technology": "Amazon Q in Connect",
            "identity": "Configured assistant",
        }
        if assistant_id not in assistant_cache:
            try:
                assistant_cache[assistant_id] = (
                    self.aws_client_factory.get_qconnect_assistant_resilient(assistant_id)
                )
            except Exception as exc:  # noqa: BLE001
                assistant_cache[assistant_id] = None
                self.logger.debug(
                    "Amazon Q in Connect assistant lookup failed for %s: %s",
                    assistant_id,
                    exc,
                )
        response = assistant_cache.get(assistant_id) or {}
        assistant = response.get("assistant") or {}
        name = assistant.get("name")
        if isinstance(name, str) and name.strip():
            details["identity"] = name.strip()
        assistant_type = assistant.get("type")
        if isinstance(assistant_type, str) and assistant_type.strip():
            details["subtype"] = assistant_type.replace("_", " ").title()
        return details

    def _resolve_journey_queue_details(
        self,
        instance_id: str,
        params: Dict[str, Any],
        queue_cache: Dict[Tuple[str, str], Optional[Dict[str, Any]]],
    ) -> Dict[str, str]:
        """Resolve a queue name while keeping queue IDs out of reader-facing output."""
        queue_ref: Any = params.get("QueueId") if isinstance(params, dict) else None
        nested = params.get("Queue") if isinstance(params, dict) else None
        if not queue_ref and isinstance(nested, dict):
            queue_ref = nested.get("Arn") or nested.get("Id")
        if not isinstance(queue_ref, str) or not queue_ref.strip():
            return {}
        queue_ref = queue_ref.strip()
        if queue_ref.startswith("$"):
            return {"identity": "Queue selected from contact data", "selection": "dynamic"}

        queue_id = queue_ref.rsplit("/", 1)[-1]
        try:
            uuid.UUID(queue_id)
        except (ValueError, AttributeError):
            return {"identity": "Configured queue"}

        cache_key = (instance_id, queue_id)
        if cache_key not in queue_cache:
            try:
                queue_cache[cache_key] = self.aws_client_factory.describe_queue_resilient(
                    instance_id,
                    queue_id,
                )
            except Exception as exc:  # noqa: BLE001
                queue_cache[cache_key] = None
                self.logger.debug("Queue identity lookup failed for %s: %s", queue_id, exc)

        response = queue_cache.get(cache_key) or {}
        queue = response.get("Queue") or {}
        name = queue.get("Name")
        if isinstance(name, str) and name.strip():
            return {"identity": name.strip(), "selection": "configured"}
        return {"identity": "Configured queue", "selection": "configured"}

    @staticmethod
    def _lex_v2_ids(params: Dict[str, Any]) -> Tuple[str, str]:
        """Extract bot and alias IDs from a Lex V2 parameter object."""
        bot_id = params.get("BotId") or params.get("botId") or ""
        alias_id = params.get("BotAliasId") or params.get("botAliasId") or ""
        alias_arn = params.get("AliasArn") or params.get("AliasArnV2")
        if isinstance(alias_arn, str) and "bot-alias/" in alias_arn:
            parts = alias_arn.split("bot-alias/", 1)[1].split("/")
            if parts:
                bot_id = bot_id or parts[0]
            if len(parts) > 1:
                alias_id = alias_id or parts[1]
        return str(bot_id), str(alias_id)

    def _list_phone_numbers_for_instance(self, instance: ConnectInstance) -> List[Dict[str, Any]]:
        """
        Paginate ``connect:ListPhoneNumbersV2`` for one instance and
        return every claimed number (raw API dicts).

        Raises :class:`_AccessDeniedListingPhoneNumbers` if the API
        rejects the request as unauthorized so the caller can bucket it
        into a specific empty-state reason. Any other exception
        propagates.
        """
        factory = self.aws_client_factory
        all_numbers: List[Dict[str, Any]] = []
        next_token: Optional[str] = None
        for _ in range(20):  # Bounded page pull — 20 * 100 = 2000 numbers
            kwargs: Dict[str, Any] = {
                "TargetArn": instance.instance_arn,
                "MaxResults": 100,
            }
            if next_token:
                kwargs["NextToken"] = next_token
            try:
                resp = factory.call_api_with_resilience(
                    factory.get_connect_client(),
                    "list_phone_numbers_v2",
                    "connect",
                    **kwargs,
                )
            except Exception as e:  # noqa: BLE001
                if factory.is_access_denied(e):
                    raise _AccessDeniedListingPhoneNumbers() from e
                raise
            batch = resp.get("ListPhoneNumbersSummaryList") or []
            all_numbers.extend(batch)
            next_token = resp.get("NextToken")
            if not next_token:
                break
        return all_numbers

    # Resource types ListFlowAssociations supports that represent a phone
    # number (as opposed to INBOUND_EMAIL / OUTBOUND_EMAIL / ANALYTICS_CONNECTOR,
    # which aren't phone-number-shaped). A single Connect number can be
    # channel-bound under more than one of these — e.g. a toll-free number
    # claimed for voice and separately wired for SMS replies via AWS End
    # User Messaging — so all three are queried and merged.
    _FLOW_ASSOCIATION_PHONE_RESOURCE_TYPES = (
        "VOICE_PHONE_NUMBER",
        "SMS_PHONE_NUMBER",
        "WHATSAPP_MESSAGING_PHONE_NUMBER",
    )

    def _list_flow_associations_for_instance(self, instance: ConnectInstance) -> Dict[str, str]:
        """
        Paginate ``connect:ListFlowAssociations`` across every phone-number
        resource type (voice, SMS, WhatsApp) for one instance and return a
        merged mapping of phone number ARN -> contact flow ID.

        This is the API that actually reflects the Connect console's
        "Contact flow / IVR" field on a phone number — see the
        ``_compute_journey_map`` docstring for why ``ListPhoneNumbersV2``'s
        ``TargetArn`` cannot be used for this. ``FlowId`` in the response
        is a full flow ARN (``…/contact-flow/{id}``); this method returns
        just the trailing ID so callers can look it up directly in
        ``instance.contact_flows``.

        Raises :class:`_AccessDeniedListingFlowAssociations` if the API
        rejects the request as unauthorized so the caller can bucket it
        into a specific empty-state reason. Any other exception
        propagates.
        """
        factory = self.aws_client_factory
        flow_id_by_phone_arn: Dict[str, str] = {}
        for resource_type in self._FLOW_ASSOCIATION_PHONE_RESOURCE_TYPES:
            next_token: Optional[str] = None
            for _ in range(20):  # Bounded page pull — 20 * 1000 = 20000 associations
                kwargs: Dict[str, Any] = {
                    "InstanceId": instance.instance_id,
                    "ResourceType": resource_type,
                    "MaxResults": 1000,
                }
                if next_token:
                    kwargs["NextToken"] = next_token
                try:
                    resp = factory.call_api_with_resilience(
                        factory.get_connect_client(),
                        "list_flow_associations",
                        "connect",
                        **kwargs,
                    )
                except Exception as e:  # noqa: BLE001
                    if factory.is_access_denied(e):
                        raise _AccessDeniedListingFlowAssociations() from e
                    raise
                for assoc in resp.get("FlowAssociationSummaryList") or []:
                    phone_arn = assoc.get("ResourceId") or ""
                    flow_arn = assoc.get("FlowId") or ""
                    if phone_arn and flow_arn:
                        flow_id_by_phone_arn[phone_arn] = flow_arn.rsplit("/", 1)[-1]
                next_token = resp.get("NextToken")
                if not next_token:
                    break
        return flow_id_by_phone_arn

    def _diagnose_empty_journey_map(
        self,
        list_denied_permission: Optional[str],
        list_error_first: Optional[str],
        instances_seen_numbers: int,
        instances_with_flow_bound_numbers: int,
        numbers_bound_to_non_flow: int,
    ) -> Dict[str, str]:
        """Pick a plain-English explanation for an empty Journey Map."""
        if list_denied_permission is not None:
            return {
                "reason": "list_phone_numbers_denied",
                "message": (
                    "The Caller Journey Map is phone-number driven — "
                    "it walks the flow each DID or toll-free number "
                    "terminates on. The tool couldn't list phone "
                    "numbers or their flow assignments on your "
                    f"instance because `{list_denied_permission}` "
                    "isn't permitted for the assessing IAM role."
                ),
                "hint": (
                    f"Grant `{list_denied_permission}` to the role, "
                    "then re-run. The Journey Map will populate "
                    "automatically."
                ),
            }
        if list_error_first is not None:
            return {
                "reason": "list_phone_numbers_error",
                "message": (
                    "The Caller Journey Map is phone-number driven, "
                    "and the tool hit an error listing phone numbers "
                    "on every instance."
                ),
                "hint": ("First error observed: " + list_error_first),
            }
        if instances_seen_numbers == 0:
            return {
                "reason": "no_phone_numbers_claimed",
                "message": (
                    "No inbound phone numbers (DID or toll-free) are "
                    "claimed on any of the discovered Connect "
                    "instances. The Journey Map needs at least one "
                    "number pointing at a contact flow to have "
                    "something to walk through."
                ),
                "hint": (
                    "Claim at least one number in the Connect console "
                    "(Channels -> Phone numbers -> Claim a number), "
                    "point it at your main inbound flow, then re-run."
                ),
            }
        if instances_with_flow_bound_numbers == 0:
            return {
                "reason": "numbers_do_not_target_flows",
                "message": (
                    f"Every phone number the tool found "
                    f"({numbers_bound_to_non_flow} total) is pointed "
                    "somewhere other than a contact flow — a queue, "
                    "an agent, or unassigned. The Journey Map only "
                    "renders flows, so there's nothing to draw."
                ),
                "hint": (
                    "In the Connect console, edit each inbound number "
                    "you want visualized (Channels -> Phone numbers) "
                    "and change 'Contact flow / IVR' to the flow the "
                    "caller should land in."
                ),
            }
        # Numbers exist and target flows, but every render was skipped
        # (empty flow content, parse errors on every entry). This is
        # unusual — surface as a generic message.
        return {
            "reason": "no_renderable_flows",
            "message": (
                "Phone numbers on this instance target contact flows, "
                "but every targeted flow either has no readable content "
                "or produced an empty diagram. This is almost always a "
                "permissions or data-shape issue."
            ),
            "hint": (
                "Confirm `connect:DescribeContactFlow` is granted for "
                "the flows those numbers target, and re-run."
            ),
        }

    def _generate_summary(self, findings: List[Finding]) -> AssessmentSummary:
        total_checks = len(findings)
        journey_findings = sum(1 for finding in findings if finding.check_id.startswith("journey-"))
        registered_checks = total_checks - journey_findings
        passed_checks = sum(1 for f in findings if f.status == CheckStatus.PASS)
        failed_checks = sum(1 for f in findings if f.status == CheckStatus.FAIL)
        error_checks = sum(1 for f in findings if f.status == CheckStatus.ERROR)
        skipped_checks = sum(1 for f in findings if f.status == CheckStatus.SKIPPED)
        not_applicable_checks = sum(1 for f in findings if f.status == CheckStatus.NOT_APPLICABLE)

        # Count findings by severity (only failed checks)
        failed_findings = [f for f in findings if f.status == CheckStatus.FAIL]
        critical_findings = sum(1 for f in failed_findings if f.severity.value == "critical")
        high_findings = sum(1 for f in failed_findings if f.severity.value == "high")
        medium_findings = sum(1 for f in failed_findings if f.severity.value == "medium")
        low_findings = sum(1 for f in failed_findings if f.severity.value == "low")

        return AssessmentSummary(
            total_checks=total_checks,
            passed_checks=passed_checks,
            failed_checks=failed_checks,
            error_checks=error_checks,
            skipped_checks=skipped_checks,
            critical_findings=critical_findings,
            high_findings=high_findings,
            medium_findings=medium_findings,
            low_findings=low_findings,
            not_applicable_checks=not_applicable_checks,
            registered_checks=registered_checks,
            journey_findings=journey_findings,
        )

    def _generate_metadata(self) -> AssessmentMetadata:
        execution_time = time.time() - self._start_time if self._start_time else 0.0

        # Get AWS account information from credentials if available.
        #
        # NOTE: the CLI stores the region under config["aws"]["region"] (see
        # ConfigurationManager._get_default_config / merge_cli_args_with_config),
        # not at the top level. Check both so a --region flag or config-file
        # aws.region setting actually reaches the report metadata instead of
        # falling through to the ARN-extraction fallback (or "unknown") every
        # time. account_id has the same top-level/nested split for consistency,
        # though in practice it's almost always populated from
        # validate_credentials() below.
        account_id = self.config.get("account_id") or self.config.get("aws", {}).get(
            "account_id", "unknown"
        )
        region = self.config.get("region") or self.config.get("aws", {}).get("region", "unknown")
        if not region:
            region = "unknown"
        if not account_id:
            account_id = "unknown"

        # Try to get account info from AWS if not in config
        if account_id == "unknown":
            try:
                cred_result = self.aws_client_factory.validate_credentials()
                if cred_result.is_valid and cred_result.account_id:
                    account_id = cred_result.account_id
            except Exception as e:
                self.logger.debug(f"Could not retrieve account ID: {str(e)}")

        return AssessmentMetadata(
            tool_version=self._get_tool_version(),
            execution_time_seconds=execution_time,
            aws_account_id=account_id,
            aws_region=region,
            execution_environment=self._get_execution_environment(),
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )

    def _get_tool_version(self) -> str:
        """Get the tool version from package metadata."""
        try:
            from importlib.metadata import version

            return version("amazon-connect-assessment")
        except Exception:
            return "0.1.0"

    def _get_execution_environment(self) -> str:
        """Determine the execution environment with enhanced detection."""
        # Check for AWS environments first
        if "AWS_EXECUTION_ENV" in os.environ:
            if "lambda" in os.environ.get("AWS_EXECUTION_ENV", "").lower():
                return "AWS Lambda"
            else:
                return f"AWS {os.environ['AWS_EXECUTION_ENV']}"
        elif "AWS_CLOUD9_USER" in os.environ:
            return "AWS Cloud9"
        elif "CLOUDSHELL" in os.environ or "AWS_CLOUDSHELL" in os.environ:
            return "AWS CloudShell"
        elif "AWS_BATCH_JOB_ID" in os.environ:
            return "AWS Batch"
        elif "ECS_CONTAINER_METADATA_URI" in os.environ:
            return "AWS ECS"
        elif "AWS_LAMBDA_FUNCTION_NAME" in os.environ:
            return "AWS Lambda"
        else:
            # Local environment detection
            system_info = f"{platform.system()} {platform.release()}"
            if "microsoft" in platform.release().lower():
                return f"WSL ({system_info})"
            elif "Darwin" in platform.system():
                return f"macOS {platform.mac_ver()[0]}"
            else:
                return system_info

    def get_assessment_statistics(self) -> Dict[str, Any]:
        return {
            "assessment_id": self._assessment_id,
            "current_step": self._current_step,
            "total_steps": self._total_steps,
            "progress_percentage": (
                (self._current_step / self._total_steps * 100) if self._total_steps > 0 else 0
            ),
            "execution_errors_count": len(self._execution_errors),
            "execution_time_seconds": time.time() - self._start_time if self._start_time else 0,
            "analyzers_count": len(self.analyzers),
            "registered_checks_count": len(self.check_registry),
            "checkpoint_enabled": self._checkpoint_enabled,
            "checkpoint_file": self._current_checkpoint_file,
        }

    def get_execution_errors(self) -> List[str]:
        return self._execution_errors.copy()

    def clear_execution_errors(self) -> None:
        self._execution_errors.clear()

    def validate_configuration(self) -> Dict[str, Any]:
        validation_result = {
            "is_valid": True,
            "errors": [],
            "warnings": [],
            "aws_credentials": None,
            "aws_permissions": None,
        }

        try:
            # Validate AWS credentials
            cred_result = self.aws_client_factory.validate_credentials()
            validation_result["aws_credentials"] = {
                "is_valid": cred_result.is_valid,
                "source": (
                    cred_result.credential_source.value
                    if cred_result.credential_source
                    else "unknown"
                ),
                "account_id": cred_result.account_id,
                "error": cred_result.error_message,
            }

            if not cred_result.is_valid:
                validation_result["is_valid"] = False
                validation_result["errors"].append(
                    f"Invalid AWS credentials: {cred_result.error_message}"
                )

            # Validate AWS permissions
            perm_result = self.aws_client_factory.validate_permissions()
            validation_result["aws_permissions"] = {
                "is_valid": perm_result.is_valid,
                "missing_permissions": perm_result.missing_permissions,
                "tested_permissions": perm_result.tested_permissions,
                "error": perm_result.error_message,
            }

            if not perm_result.is_valid:
                validation_result["is_valid"] = False
                validation_result["errors"].append(
                    f"Missing AWS permissions: {', '.join(perm_result.missing_permissions)}"
                )

            # Validate analyzers
            if not self.analyzers:
                validation_result["warnings"].append(
                    "No analyzers registered - component analysis will be limited"
                )

            # Validate checks
            if len(self.check_registry) == 0:
                validation_result["warnings"].append(
                    "No checks registered - assessment will not generate findings"
                )

            # Validate checkpoint directory
            if self._checkpoint_enabled:
                try:
                    os.makedirs(self.checkpoint_dir, exist_ok=True)
                    if not os.access(self.checkpoint_dir, os.W_OK):
                        validation_result["warnings"].append(
                            f"Checkpoint directory not writable: {self.checkpoint_dir}"
                        )
                except Exception as e:
                    validation_result["warnings"].append(f"Checkpoint directory issue: {str(e)}")

        except Exception as e:
            validation_result["is_valid"] = False
            validation_result["errors"].append(f"Configuration validation failed: {str(e)}")

        return validation_result
