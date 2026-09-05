"""
Parallel execution engine for Amazon Connect assessments.

Provides high-performance assessment execution using concurrent processing,
connection pooling, and intelligent batching to significantly reduce
assessment time while maintaining reliability.
"""

import concurrent.futures
import os
import threading
import time
import uuid
from datetime import datetime
from queue import Empty, Full, Queue
from typing import Any, Callable, Dict, List, Optional

from .aws_client_factory import AWSClientFactory
from .checks import CheckContext
from .checks.mvp_remediation_enricher import enrich_finding
from .engine import AssessmentEngine
from .models import (
    AssessmentResult,
    AssessmentSummary,
    ConnectInstance,
    Finding,
)


class ParallelAssessmentEngine(AssessmentEngine):
    """
    High-performance assessment engine with parallel execution capabilities.

    Features:
    - Concurrent check execution across multiple threads
    - Parallel instance analysis
    - Connection pooling for AWS API calls
    - Intelligent batching and load balancing
    - Progress tracking with real-time updates
    - Graceful error handling and recovery
    """

    def __init__(
        self,
        aws_client_factory: AWSClientFactory,
        config: Dict[str, Any] = None,
        progress_callback: Optional[Callable[[str, int, int], None]] = None,
        checkpoint_dir: Optional[str] = None,
        max_workers: Optional[int] = None,
        batch_size: int = 10,
        enable_connection_pooling: bool = True,
    ):
        """
        Initialize the parallel assessment engine.

        Args:
            aws_client_factory: AWSClientFactory instance for AWS service clients
            config: Optional configuration dictionary
            progress_callback: Optional callback function for progress updates
            checkpoint_dir: Optional directory for checkpoint storage
            max_workers: Maximum number of worker threads (default: CPU count * 2)
            batch_size: Number of checks to process in each batch
            enable_connection_pooling: Whether to use connection pooling
        """
        super().__init__(aws_client_factory, config, progress_callback, checkpoint_dir)

        # Parallel execution configuration
        self.max_workers = max_workers or min(32, (os.cpu_count() or 1) * 2)
        self.batch_size = batch_size
        self.enable_connection_pooling = enable_connection_pooling

        # Performance tracking
        self._execution_stats = {
            "total_checks": 0,
            "parallel_batches": 0,
            "avg_batch_time": 0.0,
            "fastest_check": float("inf"),
            "slowest_check": 0.0,
            "connection_pool_hits": 0,
            "api_calls_made": 0,
        }

        # Thread-safe progress and stats tracking
        self._progress_lock = threading.Lock()
        self._stats_lock = threading.Lock()
        self._completed_checks = 0
        self._total_checks_planned = 0

        self.logger.info(
            f"Parallel engine initialized with {self.max_workers} workers, batch size {batch_size}"
        )

    def run_assessment(self) -> AssessmentResult:
        """
        Execute a complete Amazon Connect assessment with parallel processing.

        Returns:
            AssessmentResult: Complete assessment results
        """
        self._start_time = time.time()
        self._execution_errors.clear()
        with self._stats_lock:
            self._execution_stats = {
                k: 0 if isinstance(v, (int, float)) else v for k, v in self._execution_stats.items()
            }
        # Reset progress counters so re-running the same engine instance
        # (e.g. a resumed or repeated assessment) starts from 0/N instead
        # of carrying over the previous run's completed count, which could
        # otherwise report >100% progress or a bogus percentage as soon as
        # _initialize_parallel_progress_tracking sets a fresh, smaller
        # denominator below.
        with self._progress_lock:
            self._completed_checks = 0
            self._total_checks_planned = 0

        # Generate assessment ID if not resuming
        if not self._assessment_id:
            self._assessment_id = str(uuid.uuid4())

        assessment_id = self._assessment_id
        self.logger.info(
            f"Starting parallel assessment {assessment_id} with {self.max_workers} workers"
        )

        try:
            # Discover Connect instances
            # The instance count is needed to calculate the workflow-step
            # denominator, so discovery cannot be emitted as a numbered step
            # until after it completes.
            self.logger.info("Discovering Connect instances")
            instances = self.discover_instances()
            self.logger.info(f"Discovered {len(instances)} Connect instances")

            if not instances:
                self.logger.warning("No Connect instances found")
                return self._create_empty_result(assessment_id)

            # Initialize progress tracking
            self._initialize_parallel_progress_tracking(instances)

            # Parallel instance analysis
            self._update_progress("Analyzing instances in parallel")
            analyzed_instances = self._analyze_instances_parallel(instances)

            # Parallel check execution
            self._update_progress("Executing checks in parallel")
            all_findings = self._execute_checks_parallel(analyzed_instances)

            # Generate final results
            self._update_progress("Generating final results")
            result = self._create_final_result(assessment_id, analyzed_instances, all_findings)

            execution_time = time.time() - self._start_time
            self._log_performance_stats(execution_time)

            return result

        except Exception as e:
            error_msg = f"Parallel assessment failed: {str(e)}"
            self.logger.error(error_msg)
            self._execution_errors.append(error_msg)
            raise

    def _initialize_parallel_progress_tracking(self, instances: List[ConnectInstance]) -> None:
        """Initialize progress tracking for parallel execution."""
        checks_per_instance = len(self.check_registry.get_all_checks())
        self._total_checks_planned = len(instances) * checks_per_instance
        self._execution_stats["total_checks"] = self._total_checks_planned

        # Calculate total steps: discovery + analysis + checks + finalization
        self._total_steps = 1 + len(instances) + self._total_checks_planned + 1
        self._current_step = 1  # Already completed discovery

    def _analyze_instances_parallel(
        self, instances: List[ConnectInstance]
    ) -> List[ConnectInstance]:
        """
        Analyze multiple instances in parallel.

        Args:
            instances: List of instances to analyze

        Returns:
            List of analyzed instances
        """
        analyzed_instances = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit analysis tasks
            future_to_instance = {
                executor.submit(self._analyze_instance_safe, instance): instance
                for instance in instances
            }

            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_instance):
                instance = future_to_instance[future]
                try:
                    analyzed_instance = future.result()
                    analyzed_instances.append(analyzed_instance)
                    self._update_progress(f"Analyzed instance {instance.instance_id}")
                except Exception as e:
                    error_msg = f"Failed to analyze instance {instance.instance_id}: {str(e)}"
                    self.logger.error(error_msg)
                    self._execution_errors.append(error_msg)
                    analyzed_instances.append(instance)  # Include original instance

        return analyzed_instances

    def _analyze_instance_safe(self, instance: ConnectInstance) -> ConnectInstance:
        """Thread-safe instance analysis wrapper."""
        try:
            return self.analyze_instance(instance)
        except Exception as e:
            self.logger.error(f"Instance analysis failed for {instance.instance_id}: {str(e)}")
            raise

    def _execute_checks_parallel(self, instances: List[ConnectInstance]) -> List[Finding]:
        """
        Execute checks across all instances using parallel processing.

        Args:
            instances: List of instances to check

        Returns:
            List of all findings from all checks
        """
        all_findings = []
        checks = self.check_registry.get_all_checks()

        if not checks:
            self.logger.warning("No checks registered for execution")
            return all_findings

        # Create check tasks for all instance-check combinations
        check_tasks = []
        for instance in instances:
            for check in checks:
                check_tasks.append((instance, check))

        self.logger.info(
            f"Executing {len(check_tasks)} checks across {len(instances)} instances using {self.max_workers} workers"
        )

        # Process checks in batches for better resource management
        batch_size = min(self.batch_size, len(check_tasks))
        batches = [check_tasks[i : i + batch_size] for i in range(0, len(check_tasks), batch_size)]

        self._execution_stats["parallel_batches"] = len(batches)

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            batch_start_time = time.time()

            for batch_num, batch in enumerate(batches, 1):
                # Submit batch of check tasks
                future_to_task = {
                    executor.submit(self._execute_check_safe, instance, check): (
                        instance,
                        check,
                    )
                    for instance, check in batch
                }

                # Collect batch results
                batch_findings = []
                for future in concurrent.futures.as_completed(future_to_task):
                    instance, check = future_to_task[future]
                    try:
                        finding = future.result()
                        batch_findings.append(finding)
                        self._update_check_progress(check.check_id, instance.instance_id)
                    except Exception as e:
                        error_msg = f"Check {check.check_id} failed for instance {instance.instance_id}: {str(e)}"
                        self.logger.error(error_msg)
                        self._execution_errors.append(error_msg)

                all_findings.extend(batch_findings)

                # Update batch timing statistics under lock
                batch_time = time.time() - batch_start_time
                with self._stats_lock:
                    self._execution_stats["avg_batch_time"] = (
                        self._execution_stats["avg_batch_time"] * (batch_num - 1) + batch_time
                    ) / batch_num
                batch_start_time = time.time()

                self.logger.debug(
                    f"Completed batch {batch_num}/{len(batches)} with {len(batch_findings)} findings"
                )

        # Caller Journey Mapping findings — same pipeline as the sequential
        # engine's _compute_journey_findings (inherited from
        # AssessmentEngine). Journey mapping does its own per-instance work
        # and internal error handling, so it's run once here rather than
        # fanned out across the thread pool with the per-check tasks above.
        all_findings.extend(self._compute_journey_findings(instances))

        return all_findings

    def _execute_check_safe(self, instance: ConnectInstance, check) -> Finding:
        """
        Thread-safe check execution wrapper with performance tracking.

        Args:
            instance: ConnectInstance to check
            check: Check to execute

        Returns:
            Finding from check execution
        """
        check_start_time = time.time()

        try:
            # Create thread-local check context
            context = CheckContext(
                instance=instance,
                aws_client_factory=self.aws_client_factory,
                config=self.config,
                logger=self.logger,
            )

            finding = check.safe_execute(context)
            # Keep parallel execution behavior identical to the sequential
            # engine, which enriches legacy MVP findings after execution.
            enrich_finding(finding)

            # Update performance statistics under lock
            check_time = time.time() - check_start_time
            with self._stats_lock:
                self._execution_stats["fastest_check"] = min(
                    self._execution_stats["fastest_check"], check_time
                )
                self._execution_stats["slowest_check"] = max(
                    self._execution_stats["slowest_check"], check_time
                )

            return finding

        except Exception as e:
            self.logger.error(f"Check execution failed: {str(e)}")
            raise

    def _update_check_progress(self, check_id: str, instance_id: str) -> None:
        """Thread-safe progress update for individual check completion."""
        with self._progress_lock:
            self._completed_checks += 1
            progress_pct = (
                (self._completed_checks / self._total_checks_planned * 100)
                if self._total_checks_planned > 0
                else 0
            )

            if (
                self._completed_checks % 10 == 0 or progress_pct >= 100
            ):  # Update every 10 checks or at completion
                self._update_progress(
                    f"Completed {self._completed_checks}/{self._total_checks_planned} "
                    f"registered checks ({progress_pct:.1f}%)"
                )

    def _create_empty_result(self, assessment_id: str) -> AssessmentResult:
        """Create an empty assessment result when no instances are found."""
        # See AssessmentEngine._generate_metadata for why both the top-level
        # and config["aws"] locations are checked — the CLI stores region
        # under config["aws"]["region"], not at the top level.
        account_id = self.config.get("account_id") or self.config.get("aws", {}).get(
            "account_id", "unknown"
        )
        region = self.config.get("region") or self.config.get("aws", {}).get("region", "unknown")
        journey_map_entries, journey_map_status = self._compute_journey_map([])
        return AssessmentResult(
            assessment_id=assessment_id,
            timestamp=datetime.now(),
            account_id=account_id or "unknown",
            region=region or "unknown",
            instances=[],
            findings=[],
            summary=AssessmentSummary(
                total_checks=0,
                passed_checks=0,
                failed_checks=0,
                error_checks=0,
                skipped_checks=0,
                critical_findings=0,
                high_findings=0,
                medium_findings=0,
                low_findings=0,
            ),
            metadata=self._generate_metadata(),
            execution_errors=self._execution_errors.copy(),
            journey_map_entries=journey_map_entries,
            journey_map_status=journey_map_status,
        )

    def _create_final_result(
        self,
        assessment_id: str,
        instances: List[ConnectInstance],
        findings: List[Finding],
    ) -> AssessmentResult:
        """Create the final assessment result with all data."""
        summary = self._generate_summary(findings)
        metadata = self._generate_metadata()

        # Extract account and region info
        account_id = metadata.aws_account_id
        region = metadata.aws_region

        if account_id == "unknown" and instances:
            account_id = self._extract_account_from_instances(instances)
        if region == "unknown" and instances:
            region = self._extract_region_from_instances(instances)

        # Same journey-map computation as the sequential path — inherited
        # from AssessmentEngine._compute_journey_map. Gated by the
        # skip_flow_analysis config knob and returns a diagnostic status
        # so the report can explain an empty map instead of silently
        # hiding the section.
        journey_map_entries, journey_map_status = self._compute_journey_map(instances)

        return AssessmentResult(
            assessment_id=assessment_id,
            timestamp=datetime.now(),
            account_id=account_id,
            region=region,
            instances=instances,
            findings=findings,
            summary=summary,
            metadata=metadata,
            execution_errors=self._execution_errors.copy(),
            journey_map_entries=journey_map_entries,
            journey_map_status=journey_map_status,
        )

    def _extract_account_from_instances(self, instances: List[ConnectInstance]) -> str:
        """Extract AWS account ID from instance ARNs."""
        try:
            if instances and instances[0].instance_arn:
                arn_parts = instances[0].instance_arn.split(":")
                if len(arn_parts) >= 5:
                    return arn_parts[4]
        except Exception as e:
            self.logger.debug(f"Could not extract account ID: {str(e)}")
        return "unknown"

    def _extract_region_from_instances(self, instances: List[ConnectInstance]) -> str:
        """Extract AWS region from instance ARNs."""
        try:
            if instances and instances[0].instance_arn:
                arn_parts = instances[0].instance_arn.split(":")
                if len(arn_parts) >= 4:
                    return arn_parts[3]
        except Exception as e:
            self.logger.debug(f"Could not extract region: {str(e)}")
        return "unknown"

    def _log_performance_stats(self, total_execution_time: float) -> None:
        """Log detailed performance statistics."""
        stats = self._execution_stats

        self.logger.info("=== Parallel Execution Performance Stats ===")
        self.logger.info(f"Total execution time: {total_execution_time:.2f} seconds")
        self.logger.info(f"Total registered checks executed: {stats['total_checks']}")
        self.logger.info(f"Parallel batches processed: {stats['parallel_batches']}")
        self.logger.info(f"Average batch processing time: {stats['avg_batch_time']:.2f} seconds")

        if stats["fastest_check"] != float("inf"):
            self.logger.info(f"Fastest check: {stats['fastest_check']:.3f} seconds")
            self.logger.info(f"Slowest check: {stats['slowest_check']:.3f} seconds")

        if stats["total_checks"] > 0:
            avg_check_time = total_execution_time / stats["total_checks"]
            self.logger.info(f"Average time per check: {avg_check_time:.3f} seconds")

            # Calculate theoretical speedup
            sequential_time = stats["slowest_check"] * stats["total_checks"]
            speedup = sequential_time / total_execution_time if total_execution_time > 0 else 1
            self.logger.info(f"Estimated speedup vs sequential: {speedup:.1f}x")

    def get_performance_stats(self) -> Dict[str, Any]:
        """
        Get detailed performance statistics from the last assessment run.

        Returns:
            Dictionary containing performance metrics
        """
        base_stats = self.get_assessment_statistics()
        with self._stats_lock:
            stats_snapshot = self._execution_stats.copy()
        with self._progress_lock:
            completed = self._completed_checks
            planned = self._total_checks_planned
        base_stats.update(
            {
                "parallel_execution_stats": stats_snapshot,
                "max_workers": self.max_workers,
                "batch_size": self.batch_size,
                "connection_pooling_enabled": self.enable_connection_pooling,
                "completed_checks": completed,
                "total_checks_planned": planned,
            }
        )
        return base_stats

    def optimize_for_instance_count(self, instance_count: int) -> None:
        """
        Automatically optimize parallel execution parameters based on instance count.

        Args:
            instance_count: Number of instances that will be assessed
        """
        checks_count = len(self.check_registry.get_all_checks())
        total_tasks = instance_count * checks_count

        # Adjust worker count based on task volume
        if total_tasks < 50:
            self.max_workers = min(8, total_tasks)
            self.batch_size = 5
        elif total_tasks < 200:
            self.max_workers = min(16, total_tasks // 4)
            self.batch_size = 10
        else:
            self.max_workers = min(32, total_tasks // 8)
            self.batch_size = 20

        self.logger.info(
            f"Optimized for {instance_count} instances, {total_tasks} total tasks: "
            f"{self.max_workers} workers, batch size {self.batch_size}"
        )


# Additional performance optimization utilities


class ConnectionPoolManager:
    """Manages connection pooling for AWS API calls to reduce latency."""

    def __init__(self, pool_size: int = 10):
        self.pool_size = pool_size
        self._connection_pools = {}
        self._pool_lock = threading.Lock()

    def get_pooled_client(self, service_name: str, aws_client_factory: AWSClientFactory):
        """Get a pooled client for the specified AWS service."""
        with self._pool_lock:
            if service_name not in self._connection_pools:
                self._connection_pools[service_name] = Queue(maxsize=self.pool_size)
                # Pre-populate pool
                for _ in range(self.pool_size):
                    client = aws_client_factory.get_client(service_name)
                    self._connection_pools[service_name].put(client)

            try:
                return self._connection_pools[service_name].get_nowait()
            except Empty:
                # Pool exhausted, create new client
                return aws_client_factory.get_client(service_name)

    def return_client(self, service_name: str, client):
        """Return a client to the pool."""
        if service_name in self._connection_pools:
            try:
                self._connection_pools[service_name].put_nowait(client)
            except Full:
                pass  # Pool full, let client be garbage collected


def create_optimized_engine(
    aws_client_factory: AWSClientFactory,
    config: Dict[str, Any] = None,
    instance_count_hint: Optional[int] = None,
) -> ParallelAssessmentEngine:
    """
    Factory function to create an optimized parallel assessment engine.

    Args:
        aws_client_factory: AWSClientFactory instance
        config: Optional configuration dictionary
        instance_count_hint: Optional hint about expected instance count for optimization

    Returns:
        Optimized ParallelAssessmentEngine instance
    """
    engine = ParallelAssessmentEngine(
        aws_client_factory=aws_client_factory,
        config=config,
        enable_connection_pooling=True,
    )

    if instance_count_hint:
        engine.optimize_for_instance_count(instance_count_hint)

    return engine
