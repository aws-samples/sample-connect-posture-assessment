#!/usr/bin/env python3
"""
Performance testing and optimization script for Amazon Connect Assessment Tool.

This script demonstrates how to use the parallel execution engine and provides
performance benchmarking capabilities to measure improvement gains.
"""

import json
import sys
import time
from pathlib import Path

# Add the project root to Python path
sys.path.insert(0, str(Path(__file__).parent.parent))

from amazon_connect_assessment.analyzers import (
    ConnectInstanceAnalyzer,
    ContactFlowAnalyzer,
    IntegrationAnalyzer,
    QueueAnalyzer,
    SecurityProfileAnalyzer,
)
from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.mvp_checks import register_mvp_checks
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.engine import AssessmentEngine
from amazon_connect_assessment.parallel_engine import (
    ParallelAssessmentEngine,
    create_optimized_engine,
)


def setup_assessment_components():
    """Set up all assessment components (analyzers and checks)."""
    # Create AWS client factory
    aws_factory = AWSClientFactory()

    # Create check registry and register all MVP checks
    check_registry = CheckRegistry()
    register_mvp_checks(check_registry)

    # Create analyzers
    analyzers = [
        ConnectInstanceAnalyzer(aws_factory),
        ContactFlowAnalyzer(aws_factory),
        QueueAnalyzer(aws_factory),
        SecurityProfileAnalyzer(aws_factory),
        IntegrationAnalyzer(aws_factory),
    ]

    return aws_factory, check_registry, analyzers


def create_sequential_engine(aws_factory, check_registry, analyzers):
    """Create a traditional sequential assessment engine."""
    engine = AssessmentEngine(aws_factory)

    # Add analyzers
    for analyzer in analyzers:
        engine.add_analyzer(analyzer)

    # Set the check registry
    engine.check_registry = check_registry

    return engine


def create_parallel_engine(aws_factory, check_registry, analyzers, max_workers=None):
    """Create a parallel assessment engine."""
    engine = ParallelAssessmentEngine(
        aws_client_factory=aws_factory,
        max_workers=max_workers,
        batch_size=10,
        enable_connection_pooling=True,
    )

    # Add analyzers
    for analyzer in analyzers:
        engine.add_analyzer(analyzer)

    # Set the check registry
    engine.check_registry = check_registry

    return engine


def benchmark_assessment_performance():
    """
    Benchmark assessment performance comparing sequential vs parallel execution.
    """
    print("🚀 Amazon Connect Assessment Performance Benchmark")
    print("=" * 60)

    # Setup components
    print("Setting up assessment components...")
    aws_factory, check_registry, analyzers = setup_assessment_components()

    print(f"✅ Registered {len(check_registry)} checks")
    print(f"✅ Configured {len(analyzers)} analyzers")

    # Validate AWS credentials
    print("\nValidating AWS credentials...")
    cred_result = aws_factory.validate_credentials()
    if not cred_result.is_valid:
        print(f"❌ AWS credentials invalid: {cred_result.error_message}")
        return

    print(f"✅ AWS credentials valid (Account: {cred_result.account_id})")

    # Discover instances for optimization
    print("\nDiscovering Connect instances...")
    try:
        response = aws_factory.list_connect_instances_resilient()
        instance_count = len(response.get("InstanceSummaryList", []))
        print(f"✅ Found {instance_count} Connect instances")

        if instance_count == 0:
            print("⚠️  No Connect instances found. Cannot perform meaningful benchmark.")
            return

    except Exception as e:
        print(f"❌ Failed to discover instances: {str(e)}")
        return

    # Performance test configurations
    test_configs = [
        {"name": "Sequential", "engine_type": "sequential", "workers": 1},
        {"name": "Parallel (4 workers)", "engine_type": "parallel", "workers": 4},
        {"name": "Parallel (8 workers)", "engine_type": "parallel", "workers": 8},
        {
            "name": "Parallel (Auto-optimized)",
            "engine_type": "optimized",
            "workers": None,
        },
    ]

    results = []

    for config in test_configs:
        print(f"\n🔄 Running {config['name']} assessment...")
        print("-" * 40)

        try:
            # Create appropriate engine
            if config["engine_type"] == "sequential":
                engine = create_sequential_engine(aws_factory, check_registry, analyzers)
            elif config["engine_type"] == "parallel":
                engine = create_parallel_engine(
                    aws_factory, check_registry, analyzers, config["workers"]
                )
            else:  # optimized
                engine = create_optimized_engine(aws_factory, instance_count_hint=instance_count)
                # Add analyzers and registry
                for analyzer in analyzers:
                    engine.add_analyzer(analyzer)
                engine.check_registry = check_registry

            # Run assessment with timing
            start_time = time.time()
            result = engine.run_assessment()
            execution_time = time.time() - start_time

            # Collect results
            test_result = {
                "config": config,
                "execution_time": execution_time,
                "total_checks": result.summary.total_checks,
                "findings_count": len(result.findings),
                "instances_assessed": len(result.instances),
                "errors": len(result.execution_errors),
            }

            # Add parallel-specific stats if available
            if hasattr(engine, "get_performance_stats"):
                perf_stats = engine.get_performance_stats()
                test_result["parallel_stats"] = perf_stats.get("parallel_execution_stats", {})

            results.append(test_result)

            print(f"✅ Completed in {execution_time:.2f} seconds")
            print(f"   📊 {result.summary.total_checks} checks executed")
            print(f"   🔍 {len(result.findings)} findings generated")
            print(f"   ⚠️  {len(result.execution_errors)} errors encountered")

        except Exception as e:
            print(f"❌ Assessment failed: {str(e)}")
            results.append({"config": config, "execution_time": None, "error": str(e)})

    # Display performance comparison
    print("\n📈 Performance Comparison Results")
    print("=" * 60)

    successful_results = [r for r in results if r.get("execution_time") is not None]

    if len(successful_results) < 2:
        print("⚠️  Not enough successful runs for meaningful comparison")
        return

    # Find baseline (sequential) time
    baseline_time = None
    for result in successful_results:
        if result["config"]["engine_type"] == "sequential":
            baseline_time = result["execution_time"]
            break

    print(f"{'Configuration':<25} {'Time (s)':<10} {'Speedup':<10} {'Checks/s':<12}")
    print("-" * 65)

    for result in successful_results:
        config_name = result["config"]["name"]
        exec_time = result["execution_time"]
        checks_per_sec = result["total_checks"] / exec_time if exec_time > 0 else 0

        if baseline_time and baseline_time > 0:
            speedup = f"{baseline_time / exec_time:.1f}x"
        else:
            speedup = "N/A"

        print(f"{config_name:<25} {exec_time:<10.2f} {speedup:<10} {checks_per_sec:<12.1f}")

    # Save detailed results
    results_file = "performance_benchmark_results.json"
    with open(results_file, "w") as f:
        json.dump(
            {
                "timestamp": time.time(),
                "instance_count": instance_count,
                "total_checks": len(check_registry),
                "results": results,
            },
            f,
            indent=2,
        )

    print(f"\n💾 Detailed results saved to: {results_file}")

    # Performance recommendations
    print("\n💡 Performance Recommendations")
    print("-" * 40)

    if successful_results:
        best_result = min(successful_results, key=lambda x: x["execution_time"])
        best_config = best_result["config"]["name"]
        best_time = best_result["execution_time"]

        print(f"🏆 Best performance: {best_config} ({best_time:.2f}s)")

        if instance_count <= 5:
            print("📝 For small deployments (≤5 instances): Sequential execution may be sufficient")
        elif instance_count <= 20:
            print("📝 For medium deployments (6-20 instances): Use 4-8 parallel workers")
        else:
            print("📝 For large deployments (>20 instances): Use auto-optimized parallel execution")

        print("📝 Enable connection pooling for better AWS API performance")
        print("📝 Consider running assessments during off-peak hours for better performance")


def demonstrate_parallel_features():
    """Demonstrate specific parallel execution features."""
    print("\n🔧 Parallel Execution Features Demo")
    print("=" * 50)

    # Setup
    aws_factory, check_registry, analyzers = setup_assessment_components()

    # Create optimized engine
    engine = create_optimized_engine(aws_factory)
    for analyzer in analyzers:
        engine.add_analyzer(analyzer)
    engine.check_registry = check_registry

    # Show configuration
    print(f"🔧 Max workers: {engine.max_workers}")
    print(f"🔧 Batch size: {engine.batch_size}")
    print(f"🔧 Connection pooling: {engine.enable_connection_pooling}")

    # Progress callback demo
    def progress_callback(description, current, total):
        percentage = (current / total * 100) if total > 0 else 0
        print(f"📊 Progress: {description} ({current}/{total}, {percentage:.1f}%)")

    engine.progress_callback = progress_callback

    print("\n🚀 Running assessment with progress tracking...")
    try:
        engine.run_assessment()

        # Show performance stats
        perf_stats = engine.get_performance_stats()
        parallel_stats = perf_stats.get("parallel_execution_stats", {})

        print("\n📈 Performance Statistics:")
        print(f"   Total execution time: {perf_stats.get('execution_time_seconds', 0):.2f}s")
        print(f"   Parallel batches: {parallel_stats.get('parallel_batches', 0)}")
        print(f"   Average batch time: {parallel_stats.get('avg_batch_time', 0):.2f}s")
        print(f"   Fastest check: {parallel_stats.get('fastest_check', 0):.3f}s")
        print(f"   Slowest check: {parallel_stats.get('slowest_check', 0):.3f}s")

    except Exception as e:
        print(f"❌ Demo failed: {str(e)}")


if __name__ == "__main__":
    print("Amazon Connect Assessment - Performance Testing Tool")
    print("This script will benchmark sequential vs parallel execution performance.")
    print()

    # Check if running in virtual environment
    if not hasattr(sys, "real_prefix") and not (
        hasattr(sys, "base_prefix") and sys.base_prefix != sys.prefix
    ):
        print("⚠️  Warning: Not running in a virtual environment")
        print("   It's recommended to run this in a virtual environment")
        print()

    try:
        # Run benchmark
        benchmark_assessment_performance()

        # Run feature demo
        demonstrate_parallel_features()

    except KeyboardInterrupt:
        print("\n\n⏹️  Benchmark interrupted by user")
    except Exception as e:
        print(f"\n❌ Benchmark failed: {str(e)}")
        sys.exit(1)

    print("\n✅ Performance testing completed!")
