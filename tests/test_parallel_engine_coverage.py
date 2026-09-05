"""
Coverage test for ParallelAssessmentEngine.run_assessment() pipeline.

Mocks discover_instances and analyze_instance to exercise the full parallel
check-execution, batch processing, progress tracking, and result-generation
paths without hitting real AWS.
"""

from unittest.mock import Mock, patch

from amazon_connect_assessment.checks.registration import register_all_checks
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import ConnectInstance
from amazon_connect_assessment.parallel_engine import (
    ParallelAssessmentEngine,
    create_optimized_engine,
)


def _make_instances(n=2):
    return [
        ConnectInstance(
            instance_id=f"inst-{i}",
            instance_arn=f"arn:aws:connect:us-east-1:123456789012:instance/inst-{i}",
            identity_management_type="CONNECT_MANAGED",
            inbound_calls_enabled=True,
            outbound_calls_enabled=True,
            status="ACTIVE",
        )
        for i in range(n)
    ]


def _factory():
    factory = Mock()
    factory.is_access_denied = lambda e: False
    factory.get_connect_client.return_value = Mock()
    factory.get_cloudwatch_client.return_value = Mock()
    factory.get_s3_client.return_value = Mock()
    factory.get_client.return_value = Mock()
    factory.call_api_with_resilience.return_value = {
        "Attribute": {"Value": "false"},
        "TrafficDistributionGroupSummaryList": [],
        "ListPhoneNumbersSummaryList": [],
        "MetricAlarms": [],
        "trailList": [],
        "Datapoints": [],
        "HoursOfOperationSummaryList": [],
        "Origins": [],
        "StorageConfigs": [],
        "SecurityProfileSummaryList": [],
    }
    factory.describe_alarms_resilient.return_value = {"MetricAlarms": []}
    factory.describe_trails_resilient.return_value = {"trailList": []}
    factory.list_approved_origins_resilient.return_value = {"Origins": []}
    factory.list_instance_storage_configs_resilient.return_value = {"StorageConfigs": []}
    factory.list_security_profiles_resilient.return_value = {"SecurityProfileSummaryList": []}
    factory.list_role_policies_resilient.return_value = {"PolicyNames": []}
    factory.list_attached_role_policies_resilient.return_value = {"AttachedPolicies": []}
    factory.list_connect_instances_resilient.return_value = {"InstanceSummaryList": []}
    return factory


class TestParallelEngineRunAssessment:
    def test_discovery_does_not_log_zero_progress_denominator(self, caplog):
        factory = _factory()
        engine = ParallelAssessmentEngine(factory, max_workers=2, batch_size=5)
        engine.enable_checkpoints(False)
        registry = CheckRegistry()
        register_all_checks(registry, skip_flow_analysis=True)
        engine.check_registry = registry

        with caplog.at_level("INFO", logger="assessment_engine"):
            with patch.object(engine, "discover_instances", return_value=_make_instances(1)):
                with patch.object(engine, "analyze_instance", side_effect=lambda i: i):
                    engine.run_assessment()

        assert "Step 1/0" not in caplog.text
        assert "Workflow step 2/" in caplog.text

    def test_run_assessment_end_to_end(self):
        """Full pipeline: discover → analyze → check → result."""
        factory = _factory()
        instances = _make_instances(2)

        engine = ParallelAssessmentEngine(
            factory,
            config={"account_id": "123456789012", "region": "us-east-1"},
            max_workers=2,
            batch_size=5,
        )
        engine.enable_checkpoints(False)

        # Register all checks.
        registry = CheckRegistry()
        register_all_checks(registry, skip_flow_analysis=True)
        engine.check_registry = registry

        # Mock discovery and analysis to return our test instances.
        with patch.object(engine, "discover_instances", return_value=instances):
            with patch.object(engine, "analyze_instance", side_effect=lambda i: i):
                result = engine.run_assessment()

        assert result.assessment_id
        assert len(result.instances) == 2
        assert result.summary.total_checks > 0
        assert result.account_id == "123456789012"
        assert result.region == "us-east-1"

    def test_empty_instance_list(self):
        """Pipeline with no instances returns empty result."""
        factory = _factory()
        engine = ParallelAssessmentEngine(factory, max_workers=2)
        engine.enable_checkpoints(False)
        engine.check_registry = CheckRegistry()

        with patch.object(engine, "discover_instances", return_value=[]):
            result = engine.run_assessment()

        assert result.summary.total_checks == 0
        assert result.instances == []
        assert result.journey_map_status["reason"] == "no_instances"

    def test_performance_stats_populated(self):
        """Performance stats are filled after a run."""
        factory = _factory()
        instances = _make_instances(1)
        engine = ParallelAssessmentEngine(factory, max_workers=2, batch_size=5)
        engine.enable_checkpoints(False)
        registry = CheckRegistry()
        register_all_checks(registry, skip_flow_analysis=True)
        engine.check_registry = registry

        with patch.object(engine, "discover_instances", return_value=instances):
            with patch.object(engine, "analyze_instance", side_effect=lambda i: i):
                engine.run_assessment()

        stats = engine.get_performance_stats()
        assert stats["parallel_execution_stats"]["total_checks"] > 0
        assert stats["max_workers"] == 2

    def test_progress_counters_reset_between_runs(self):
        # Regression test: _completed_checks / _total_checks_planned used
        # to persist across calls to run_assessment() on the same engine
        # instance. Re-running with fewer planned checks (e.g. a smaller
        # instance list) would leave _completed_checks from the previous,
        # larger run in place, making progress percentages exceed 100% or
        # be computed against a stale denominator.
        factory = _factory()
        engine = ParallelAssessmentEngine(factory, max_workers=2, batch_size=5)
        engine.enable_checkpoints(False)
        registry = CheckRegistry()
        register_all_checks(registry, skip_flow_analysis=True)
        engine.check_registry = registry

        with patch.object(engine, "discover_instances", return_value=_make_instances(3)):
            with patch.object(engine, "analyze_instance", side_effect=lambda i: i):
                engine.run_assessment()

        first_run_completed = engine._completed_checks
        first_run_planned = engine._total_checks_planned
        assert first_run_completed == first_run_planned
        assert first_run_completed > 0

        # Re-run with a fresh assessment id but a smaller instance list.
        engine._assessment_id = None
        with patch.object(engine, "discover_instances", return_value=_make_instances(1)):
            with patch.object(engine, "analyze_instance", side_effect=lambda i: i):
                engine.run_assessment()

        # Second run's completed count must reflect only the second run,
        # not the first run's leftover count plus the second run's checks.
        assert engine._completed_checks == engine._total_checks_planned
        assert engine._total_checks_planned < first_run_planned

    def test_optimize_for_instance_count(self):
        factory = _factory()
        engine = create_optimized_engine(factory, config={}, instance_count_hint=50)
        # Register checks so optimize has a nonzero task count.
        registry = CheckRegistry()
        register_all_checks(registry, skip_flow_analysis=True)
        engine.check_registry = registry
        engine.optimize_for_instance_count(50)
        assert engine.max_workers > 1
        assert engine.batch_size > 1
