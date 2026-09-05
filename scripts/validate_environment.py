#!/usr/bin/env python3
"""
Environment validation script for Amazon Connect Assessment Tool.
Tests the tool's functionality in different execution environments.
"""

import os
import platform
import sys
from pathlib import Path

# Add the project root to the Python path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

try:
    import boto3

    from amazon_connect_assessment.aws_client_factory import AWSClientFactory
    from amazon_connect_assessment.checks.config import CheckConfigurationManager
    from amazon_connect_assessment.engine import AssessmentEngine

    print("✓ All required modules imported successfully")
except ImportError as e:
    print(f"✗ Import error: {e}")
    sys.exit(1)


def detect_environment():
    """Detect the execution environment."""
    if os.environ.get("AWS_EXECUTION_ENV") == "CloudShell":
        return "cloudshell"
    elif os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return "lambda"
    elif os.environ.get("ECS_CONTAINER_METADATA_URI"):
        return "ecs"
    elif os.path.exists("/proc/xen") or os.path.exists("/sys/hypervisor/uuid"):
        return "ec2"
    else:
        return "local"


def check_python_version():
    """Check Python version compatibility."""
    version = sys.version_info
    print(f"Python version: {version.major}.{version.minor}.{version.micro}")

    if version.major < 3 or (version.major == 3 and version.minor < 12):
        print("✗ Python 3.12+ required")
        return False
    else:
        print("✓ Python version compatible")
        return True


def check_dependencies():
    """Check required dependencies."""
    required_packages = [
        ("boto3", "boto3"),
        ("botocore", "botocore"),
        ("jinja2", "jinja2"),
        ("yaml", "pyyaml"),
        ("hypothesis", "hypothesis"),
        ("pytest", "pytest"),
    ]

    missing_packages = []
    for import_name, package_name in required_packages:
        try:
            __import__(import_name)
            print(f"✓ {package_name} available")
        except ImportError:
            print(f"✗ {package_name} missing")
            missing_packages.append(package_name)

    return len(missing_packages) == 0


def check_aws_credentials():
    """Check AWS credentials configuration."""
    try:
        session = boto3.Session()
        credentials = session.get_credentials()

        if credentials is None:
            print("✗ No AWS credentials found")
            return False

        # Test credentials by calling STS
        sts = session.client("sts")
        identity = sts.get_caller_identity()

        print("✓ AWS credentials valid")
        print(f"  Account ID: {identity.get('Account', 'Unknown')}")
        print(f"  User/Role: {identity.get('Arn', 'Unknown')}")

        return True

    except Exception as e:
        print(f"✗ AWS credentials error: {e}")
        return False


def check_aws_permissions():
    """Check basic AWS permissions."""
    try:
        factory = AWSClientFactory()

        # Test Connect permissions
        connect_client = factory.get_connect_client()
        try:
            instances = connect_client.list_instances(MaxResults=1)
            print("✓ Amazon Connect permissions available")

            instance_count = len(instances.get("InstanceSummaryList", []))
            print(f"  Found {instance_count} Connect instance(s)")

        except Exception as e:
            print(f"⚠ Amazon Connect permissions limited: {e}")

        # Test CloudWatch permissions
        try:
            cloudwatch_client = factory.get_cloudwatch_client()
            cloudwatch_client.list_metrics(Namespace="AWS/Connect")
            print("✓ CloudWatch permissions available")
        except Exception as e:
            print(f"⚠ CloudWatch permissions limited: {e}")

        return True

    except Exception as e:
        print(f"✗ AWS permissions error: {e}")
        return False


def test_core_functionality():
    """Test core assessment functionality."""
    try:
        # Test configuration manager
        config_manager = CheckConfigurationManager()
        print("✓ Configuration manager initialized")

        # Test assessment engine initialization
        factory = AWSClientFactory()
        AssessmentEngine(factory, config_manager._config)
        print("✓ Assessment engine initialized")

        # Test check registry
        from amazon_connect_assessment.checks.registry import CheckRegistry

        registry = CheckRegistry()

        # Register some basic checks for testing
        from amazon_connect_assessment.checks.mvp_checks import register_mvp_checks

        register_mvp_checks(registry)

        check_count = len(registry.get_all_checks())
        print(f"✓ Check registry loaded with {check_count} checks")

        return True

    except Exception as e:
        print(f"✗ Core functionality error: {e}")
        return False


def test_report_generation():
    """Test report generation functionality."""
    try:
        from datetime import datetime, timezone

        from amazon_connect_assessment.models import (
            AssessmentMetadata,
            AssessmentResult,
            AssessmentSummary,
        )
        from amazon_connect_assessment.report_generator import ReportGenerator

        # Create minimal test data
        summary = AssessmentSummary(
            total_checks=1,
            passed_checks=1,
            failed_checks=0,
            error_checks=0,
            skipped_checks=0,
            critical_findings=0,
            high_findings=0,
            medium_findings=0,
            low_findings=0,
        )

        metadata = AssessmentMetadata(
            tool_version="0.1.0",
            execution_time_seconds=1.0,
            aws_account_id="123456789012",
            aws_region="us-east-1",
            execution_environment=detect_environment(),
            python_version=f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
        )

        test_result = AssessmentResult(
            assessment_id="validation-test",
            timestamp=datetime.now(timezone.utc),
            account_id="123456789012",
            region="us-east-1",
            instances=[],
            findings=[],
            summary=summary,
            metadata=metadata,
            execution_errors=[],
        )

        # Test report generation
        generator = ReportGenerator()
        html_content = generator.generate_html_report(test_result)

        if len(html_content) > 1000:  # Basic sanity check
            print("✓ Report generation functional")
            return True
        else:
            print("✗ Report generation produced minimal output")
            return False

    except Exception as e:
        print(f"✗ Report generation error: {e}")
        return False


def run_validation():
    """Run complete environment validation."""
    print("Amazon Connect Assessment Tool - Environment Validation")
    print("=" * 60)

    environment = detect_environment()
    print(f"Detected environment: {environment}")
    print(f"Operating system: {platform.system()} {platform.release()}")
    print(f"Architecture: {platform.machine()}")
    print()

    checks = [
        ("Python Version", check_python_version),
        ("Dependencies", check_dependencies),
        ("AWS Credentials", check_aws_credentials),
        ("AWS Permissions", check_aws_permissions),
        ("Core Functionality", test_core_functionality),
        ("Report Generation", test_report_generation),
    ]

    results = []
    for check_name, check_func in checks:
        print(f"Checking {check_name}...")
        try:
            result = check_func()
            results.append((check_name, result))
        except Exception as e:
            print(f"✗ {check_name} failed with exception: {e}")
            results.append((check_name, False))
        print()

    # Summary
    print("Validation Summary")
    print("-" * 30)

    passed = 0
    for check_name, result in results:
        status = "PASS" if result else "FAIL"
        symbol = "✓" if result else "✗"
        print(f"{symbol} {check_name}: {status}")
        if result:
            passed += 1

    print()
    print(f"Overall: {passed}/{len(results)} checks passed")

    if passed == len(results):
        print("🎉 Environment validation successful! Tool is ready to use.")
        return True
    else:
        print("⚠ Some validation checks failed. Review the issues above.")
        return False


if __name__ == "__main__":
    success = run_validation()
    sys.exit(0 if success else 1)
