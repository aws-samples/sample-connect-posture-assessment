"""
Command-line interface for the Amazon Connect Assessment Tool.

Provides a comprehensive CLI with configuration management, verbose logging,
and flexible output options for running assessments across different environments.
"""

import argparse
import json
import logging
import os
import sys
from typing import Any, Dict, List, Optional

import yaml

from . import __author__, __version__
from .analyzers import (
    ConnectInstanceAnalyzer,
    ContactFlowAnalyzer,
    IntegrationAnalyzer,
    QueueAnalyzer,
    SecurityProfileAnalyzer,
)
from .aws_client_factory import AWSClientFactory
from .checks.registry import CheckRegistry
from .engine import AssessmentEngine
from .logging_config import configure_aws_logging, setup_logging
from .report_generator import ReportGenerator

REPORTS_DIRECTORY = "reports"


class ConfigurationManager:
    """
    Manages configuration loading and validation for the assessment tool.

    Supports both YAML and JSON configuration files with environment variable
    substitution and validation of configuration parameters.
    """

    def __init__(self):
        self.config: Dict[str, Any] = {}
        self.config_file_path: Optional[str] = None

    def load_config(self, config_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Load configuration from file with fallback to default locations.

        Args:
            config_path: Optional path to configuration file

        Returns:
            Dict containing merged configuration
        """
        # Default configuration
        self.config = self._get_default_config()

        # Try to load from specified path or default locations
        config_file = self._find_config_file(config_path)
        if config_file:
            self.config_file_path = config_file
            file_config = self._load_config_file(config_file)
            self.config = self._merge_configs(self.config, file_config)

        # Apply environment variable overrides
        self._apply_env_overrides()

        return self.config

    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration values."""
        return {
            "global_settings": {
                "timeout": 300,
                "retry_count": 3,
                "max_retry_attempts": 5,
                "retry_base_delay": 1.0,
                "retry_max_delay": 60.0,
                "enable_rate_limiting": True,
                "parallel_execution": True,
                "max_workers": None,  # Auto-detect
                "batch_size": 10,
                "log_level": "INFO",
            },
            "enabled_pillars": [
                "resilience",
                "security",
                "cost_optimization",
                "operational_excellence",
                "performance_efficiency",
            ],
            "enabled_severities": ["critical", "high", "medium", "low"],
            "output": {
                "format": ["html"],
                "directory": REPORTS_DIRECTORY,
                "filename_template": "connect_assessment_{timestamp}_{account_id}",
            },
            "aws": {
                "region": None,
                "profile": None,
            },
            "checks": {},
        }

    def _find_config_file(self, config_path: Optional[str] = None) -> Optional[str]:
        """
        Find configuration file in specified path or default locations.

        Args:
            config_path: Optional explicit path to config file

        Returns:
            Path to configuration file if found, None otherwise
        """
        if config_path:
            if os.path.exists(config_path):
                return config_path
            else:
                raise FileNotFoundError(f"Configuration file not found: {config_path}")

        # Default search locations
        search_paths = [
            "./assessment_config.yaml",
            "./assessment_config.json",
            "./config/assessment_config.yaml",
            "./config/assessment_config.json",
            os.path.expanduser("~/.amazon-connect-assessment/config.yaml"),
            os.path.expanduser("~/.amazon-connect-assessment/config.json"),
        ]

        for path in search_paths:
            if os.path.exists(path):
                return path

        return None

    def _load_config_file(self, config_path: str) -> Dict[str, Any]:
        """
        Load configuration from YAML or JSON file.

        Args:
            config_path: Path to configuration file

        Returns:
            Dictionary containing configuration data
        """
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                if config_path.endswith((".yaml", ".yml")):
                    return yaml.safe_load(f) or {}
                elif config_path.endswith(".json"):
                    return json.load(f) or {}
                else:
                    # Try to detect format by content
                    content = f.read()
                    f.seek(0)
                    try:
                        return json.loads(content)
                    except json.JSONDecodeError:
                        return yaml.safe_load(content) or {}
        except Exception as e:
            raise ValueError(f"Failed to load configuration file {config_path}: {str(e)}")

    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """
        Recursively merge configuration dictionaries.

        Args:
            base: Base configuration dictionary
            override: Override configuration dictionary

        Returns:
            Merged configuration dictionary
        """
        result = base.copy()

        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value

        return result

    def _apply_env_overrides(self) -> None:
        """Apply environment variable overrides to configuration."""
        env_mappings = {
            "CONNECT_ASSESSMENT_LOG_LEVEL": ["global_settings", "log_level"],
            "CONNECT_ASSESSMENT_TIMEOUT": ["global_settings", "timeout"],
            "CONNECT_ASSESSMENT_RETRY_COUNT": ["global_settings", "retry_count"],
            "CONNECT_ASSESSMENT_MAX_RETRY_ATTEMPTS": [
                "global_settings",
                "max_retry_attempts",
            ],
            "CONNECT_ASSESSMENT_RETRY_BASE_DELAY": [
                "global_settings",
                "retry_base_delay",
            ],
            "CONNECT_ASSESSMENT_RETRY_MAX_DELAY": [
                "global_settings",
                "retry_max_delay",
            ],
            "CONNECT_ASSESSMENT_PARALLEL_EXECUTION": [
                "global_settings",
                "parallel_execution",
            ],
            "CONNECT_ASSESSMENT_MAX_WORKERS": ["global_settings", "max_workers"],
            "CONNECT_ASSESSMENT_BATCH_SIZE": ["global_settings", "batch_size"],
            "CONNECT_ASSESSMENT_OUTPUT_DIR": ["output", "directory"],
            "AWS_REGION": ["aws", "region"],
            "AWS_PROFILE": ["aws", "profile"],
        }

        for env_var, config_path in env_mappings.items():
            value = os.environ.get(env_var)
            if value:
                # Navigate to the nested dictionary location
                current = self.config
                for key in config_path[:-1]:
                    if key not in current:
                        current[key] = {}
                    current = current[key]

                # Convert value to appropriate type
                if config_path[-1] in [
                    "timeout",
                    "retry_count",
                    "max_workers",
                    "batch_size",
                    "max_retry_attempts",
                ]:
                    try:
                        value = int(value)
                    except ValueError:
                        continue
                elif config_path[-1] in ["retry_base_delay", "retry_max_delay"]:
                    try:
                        value = float(value)
                    except ValueError:
                        continue
                elif config_path[-1] in ["enable_rate_limiting", "parallel_execution"]:
                    value = value.lower() in ("true", "1", "yes", "on")

                current[config_path[-1]] = value

    def validate_config(self) -> List[str]:
        """
        Validate configuration and return list of validation errors.

        Returns:
            List of validation error messages
        """
        errors = []

        # Validate global settings
        global_settings = self.config.get("global_settings", {})

        if (
            not isinstance(global_settings.get("timeout"), int)
            or global_settings.get("timeout") <= 0
        ):
            errors.append("global_settings.timeout must be a positive integer")

        if (
            not isinstance(global_settings.get("retry_count"), int)
            or global_settings.get("retry_count") < 0
        ):
            errors.append("global_settings.retry_count must be a non-negative integer")

        if (
            not isinstance(global_settings.get("max_retry_attempts"), int)
            or global_settings.get("max_retry_attempts") <= 0
        ):
            errors.append("global_settings.max_retry_attempts must be a positive integer")

        if (
            not isinstance(global_settings.get("retry_base_delay"), (int, float))
            or global_settings.get("retry_base_delay") < 0
        ):
            errors.append("global_settings.retry_base_delay must be a non-negative number")

        if not isinstance(
            global_settings.get("retry_max_delay"), (int, float)
        ) or global_settings.get("retry_max_delay") < global_settings.get("retry_base_delay", 1.0):
            errors.append("global_settings.retry_max_delay must be >= retry_base_delay")

        if not isinstance(global_settings.get("enable_rate_limiting"), bool):
            errors.append("global_settings.enable_rate_limiting must be a boolean")

        if not isinstance(global_settings.get("parallel_execution"), bool):
            errors.append("global_settings.parallel_execution must be a boolean")

        max_workers = global_settings.get("max_workers")
        if max_workers is not None and (not isinstance(max_workers, int) or max_workers <= 0):
            errors.append("global_settings.max_workers must be a positive integer or null")

        if (
            not isinstance(global_settings.get("batch_size"), int)
            or global_settings.get("batch_size") <= 0
        ):
            errors.append("global_settings.batch_size must be a positive integer")

        # Validate log level
        valid_log_levels = ["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]
        log_level = global_settings.get("log_level", "INFO").upper()
        if log_level not in valid_log_levels:
            errors.append(
                f"global_settings.log_level must be one of: {', '.join(valid_log_levels)}"
            )

        # Validate pillars
        valid_pillars = [
            "resilience",
            "security",
            "cost_optimization",
            "operational_excellence",
            "performance_efficiency",
        ]
        enabled_pillars = self.config.get("enabled_pillars", [])
        for pillar in enabled_pillars:
            if pillar not in valid_pillars:
                errors.append(
                    f"Invalid pillar '{pillar}'. Valid pillars: {', '.join(valid_pillars)}"
                )

        # Validate severities
        valid_severities = ["critical", "high", "medium", "low"]
        enabled_severities = self.config.get("enabled_severities", [])
        for severity in enabled_severities:
            if severity not in valid_severities:
                errors.append(
                    f"Invalid severity '{severity}'. Valid severities: {', '.join(valid_severities)}"
                )

        # Validate output configuration
        output_config = self.config.get("output", {})
        valid_formats = ["html", "json", "csv", "asff"]
        output_formats = output_config.get("format", [])
        if not isinstance(output_formats, list):
            output_formats = [output_formats]

        for fmt in output_formats:
            if fmt not in valid_formats:
                errors.append(
                    f"Invalid output format '{fmt}'. Valid formats: {', '.join(valid_formats)}"
                )

        return errors

    def get_config(self) -> Dict[str, Any]:
        """Get the current configuration."""
        return self.config.copy()

    def get_config_file_path(self) -> Optional[str]:
        """Get the path to the loaded configuration file."""
        return self.config_file_path


def create_argument_parser() -> argparse.ArgumentParser:
    """
    Create and configure the command-line argument parser.

    Returns:
        Configured ArgumentParser instance
    """
    parser = argparse.ArgumentParser(
        prog="amazon-connect-assessment",
        description="Amazon Connect Assessment Tool - Evaluate AWS Connect deployments against Well-Architected Framework best practices",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run assessment with default settings (parallel execution enabled)
  amazon-connect-assessment

  # Run assessment for specific region with verbose output
  amazon-connect-assessment --region us-east-1 --verbose

  # Run assessment with custom configuration file
  amazon-connect-assessment --config ./my-config.yaml --output-dir ./reports

  # Run assessment for specific pillars only
  amazon-connect-assessment --pillars security resilience --severity critical high

  # Generate multiple output formats
  amazon-connect-assessment --output-format html json csv

  # Run assessment with AWS profile
  amazon-connect-assessment --profile my-aws-profile --region us-west-2

  # Force sequential execution (disable parallel processing)
  amazon-connect-assessment --sequential

  # Customize parallel execution
  amazon-connect-assessment --max-workers 8 --batch-size 15

  # Resume interrupted assessment
  amazon-connect-assessment --resume-assessment 12345678-1234-1234-1234-123456789012

Environment Variables:
  CONNECT_ASSESSMENT_LOG_LEVEL              Set logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
  CONNECT_ASSESSMENT_TIMEOUT                Set operation timeout in seconds
  CONNECT_ASSESSMENT_RETRY_COUNT            Set number of retries for failed operations
  CONNECT_ASSESSMENT_MAX_RETRY_ATTEMPTS     Set maximum retry attempts for network operations
  CONNECT_ASSESSMENT_RETRY_BASE_DELAY       Set base delay between retries in seconds
  CONNECT_ASSESSMENT_RETRY_MAX_DELAY        Set maximum delay between retries in seconds
  CONNECT_ASSESSMENT_PARALLEL_EXECUTION     Enable/disable parallel execution (true/false)
  CONNECT_ASSESSMENT_MAX_WORKERS            Set number of parallel worker threads
  CONNECT_ASSESSMENT_BATCH_SIZE             Set batch size for parallel processing
  CONNECT_ASSESSMENT_OUTPUT_DIR             Set output directory for reports
  AWS_REGION                                Set AWS region
  AWS_PROFILE                               Set AWS profile

Configuration Files:
  The tool searches for configuration files in the following order:
  1. File specified with --config option
  2. ./assessment_config.yaml
  3. ./assessment_config.json
  4. ./config/assessment_config.yaml
  5. ./config/assessment_config.json
  6. ~/.amazon-connect-assessment/config.yaml
  7. ~/.amazon-connect-assessment/config.json
        """,
    )

    # Version information
    parser.add_argument(
        "--version",
        action="version",
        version=f"Amazon Connect Assessment Tool {__version__} by {__author__}",
    )

    # Configuration options
    config_group = parser.add_argument_group("Configuration")
    config_group.add_argument(
        "--config",
        "-c",
        metavar="FILE",
        help="Path to configuration file (YAML or JSON)",
    )
    config_group.add_argument(
        "--validate-config",
        action="store_true",
        help="Validate configuration file and exit",
    )

    # AWS options
    aws_group = parser.add_argument_group("AWS Configuration")
    aws_group.add_argument(
        "--region",
        "-r",
        metavar="REGION",
        help="AWS region to assess (overrides config file and AWS_REGION)",
    )
    aws_group.add_argument(
        "--profile",
        "-p",
        metavar="PROFILE",
        help="AWS profile to use (overrides config file and AWS_PROFILE)",
    )
    aws_group.add_argument(
        "--instance-id",
        metavar="ID",
        help="Assess only this specific Connect instance ID (skip discovery of others)",
    )

    # Assessment options
    assessment_group = parser.add_argument_group("Assessment Options")
    assessment_group.add_argument(
        "--pillars",
        nargs="+",
        choices=[
            "resilience",
            "security",
            "cost_optimization",
            "operational_excellence",
            "performance_efficiency",
        ],
        help="Pillars to assess (default: all)",
    )
    assessment_group.add_argument(
        "--severity",
        nargs="+",
        choices=["critical", "high", "medium", "low"],
        help="Severity levels to include (default: all)",
    )
    assessment_group.add_argument(
        "--checks",
        nargs="+",
        metavar="CHECK_ID",
        help="Specific check IDs to run (default: all enabled checks)",
    )
    assessment_group.add_argument(
        "--exclude-checks",
        nargs="+",
        metavar="CHECK_ID",
        help="Check IDs to exclude from assessment",
    )
    assessment_group.add_argument(
        "--timeout",
        type=int,
        metavar="SECONDS",
        help="Timeout for assessment operations in seconds",
    )
    assessment_group.add_argument(
        "--retry-count",
        type=int,
        metavar="COUNT",
        help="Number of retries for failed operations",
    )
    assessment_group.add_argument(
        "--max-retry-attempts",
        type=int,
        metavar="COUNT",
        help="Maximum retry attempts for network operations (default: 5)",
    )
    assessment_group.add_argument(
        "--retry-base-delay",
        type=float,
        metavar="SECONDS",
        help="Base delay between retries in seconds (default: 1.0)",
    )
    assessment_group.add_argument(
        "--retry-max-delay",
        type=float,
        metavar="SECONDS",
        help="Maximum delay between retries in seconds (default: 60.0)",
    )
    assessment_group.add_argument(
        "--disable-rate-limiting",
        action="store_true",
        help="Disable automatic rate limiting for AWS API calls",
    )
    assessment_group.add_argument(
        "--network-test",
        action="store_true",
        help="Test network connectivity to AWS services before assessment",
    )

    # Output options
    output_group = parser.add_argument_group("Output Options")
    output_group.add_argument(
        "--output-dir",
        "-o",
        metavar="DIR",
        help="Output directory for assessment reports (default: ./reports)",
    )
    output_group.add_argument(
        "--output-format",
        nargs="+",
        choices=["html", "json", "csv", "asff"],
        default=None,
        help="Output format(s) for reports (default: html). Use 'asff' for Security Hub.",
    )
    output_group.add_argument(
        "--output-filename",
        metavar="TEMPLATE",
        help="Filename template for reports (supports {timestamp}, {account_id}, {region})",
    )
    output_group.add_argument(
        "--diff",
        metavar="BASELINE_JSON",
        help="Compare results against a previous JSON report and show resolved/new findings",
    )
    output_group.add_argument(
        "--s3-output",
        action="store_true",
        help=(
            "After the assessment, upload the report(s) to an S3 bucket in the "
            "assessed account. The bucket "
            "(amazon-connect-assessment-report-<account_id> by default) is "
            "created hardened if it does not already exist."
        ),
    )
    output_group.add_argument(
        "--s3-bucket",
        metavar="NAME",
        help=(
            "Override the S3 bucket name used by --s3-output "
            "(default: amazon-connect-assessment-report-<account_id>)"
        ),
    )

    # Logging and verbosity options
    logging_group = parser.add_argument_group("Logging Options")
    logging_group.add_argument(
        "--verbose",
        "-v",
        action="count",
        default=0,
        help="Increase verbosity (-v for INFO, -vv for DEBUG)",
    )
    logging_group.add_argument(
        "--quiet",
        "-q",
        action="store_true",
        help="Suppress all output except errors",
    )
    logging_group.add_argument(
        "--log-file",
        metavar="FILE",
        help="Write logs to specified file",
    )
    logging_group.add_argument(
        "--log-format",
        choices=["standard", "detailed", "json"],
        default="standard",
        help="Log output format (default: standard)",
    )

    # Execution options
    execution_group = parser.add_argument_group("Execution Options")
    execution_group.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate configuration and permissions without running assessment",
    )
    execution_group.add_argument(
        "--resume-assessment",
        metavar="ASSESSMENT_ID",
        help="Resume a previously interrupted assessment",
    )
    execution_group.add_argument(
        "--checkpoint-dir",
        metavar="DIR",
        help="Directory for storing assessment checkpoints",
    )
    execution_group.add_argument(
        "--no-checkpoints",
        action="store_true",
        help="Disable checkpoint recovery functionality",
    )
    execution_group.add_argument(
        "--parallel",
        action="store_true",
        default=None,
        help=(
            "Force parallel execution. Parallel is already the default "
            "(from global_settings.parallel_execution in config, or true "
            "if unset) — this flag only matters when a config file has set "
            "parallel_execution: false and you want to override it back on "
            "for a single run."
        ),
    )
    execution_group.add_argument(
        "--sequential",
        action="store_true",
        help="Force sequential execution (disables parallel processing)",
    )
    execution_group.add_argument(
        "--max-workers",
        type=int,
        metavar="COUNT",
        help="Maximum number of parallel worker threads (default: auto-detect)",
    )
    execution_group.add_argument(
        "--batch-size",
        type=int,
        metavar="SIZE",
        help="Number of checks to process in each batch (default: 10)",
    )
    execution_group.add_argument(
        "--skip-flow-analysis",
        action="store_true",
        help="Skip checks that parse contact flow content (faster, fewer API calls)",
    )

    # Information options
    info_group = parser.add_argument_group("Information")
    info_group.add_argument(
        "--list-checks",
        action="store_true",
        help="List all available checks and exit",
    )
    info_group.add_argument(
        "--show-config",
        action="store_true",
        help="Show current configuration and exit",
    )
    info_group.add_argument(
        "--check-permissions",
        action="store_true",
        help="Check AWS permissions and exit",
    )

    return parser


def setup_logging_from_args(args: argparse.Namespace, config: Dict[str, Any]) -> None:
    """
    Configure logging based on command-line arguments and configuration.

    Args:
        args: Parsed command-line arguments
        config: Configuration dictionary
    """
    # Determine log level
    if args.quiet:
        log_level = "ERROR"
    elif args.verbose >= 2:
        log_level = "DEBUG"
    elif args.verbose >= 1:
        log_level = "INFO"
    else:
        log_level = config.get("global_settings", {}).get("log_level", "INFO")

    # Setup logging
    setup_logging(
        level=log_level,
        format_type=args.log_format,
        log_file=args.log_file,
    )

    # Configure AWS SDK logging to reduce noise
    aws_log_level = "ERROR" if args.quiet else "WARNING"
    configure_aws_logging(aws_log_level)


def merge_cli_args_with_config(args: argparse.Namespace, config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Merge command-line arguments with configuration file settings.
    CLI arguments take precedence over configuration file settings.

    Args:
        args: Parsed command-line arguments
        config: Configuration dictionary

    Returns:
        Merged configuration dictionary
    """
    # Create a copy to avoid modifying the original
    merged_config = config.copy()

    # Override AWS settings
    if args.region:
        merged_config.setdefault("aws", {})["region"] = args.region
    if args.profile:
        merged_config.setdefault("aws", {})["profile"] = args.profile
    if getattr(args, "instance_id", None):
        merged_config.setdefault("aws", {})["instance_id"] = args.instance_id

    # Override global settings
    global_settings = merged_config.setdefault("global_settings", {})
    if args.timeout is not None:
        global_settings["timeout"] = args.timeout
    if args.retry_count is not None:
        global_settings["retry_count"] = args.retry_count
    if args.max_retry_attempts is not None:
        global_settings["max_retry_attempts"] = args.max_retry_attempts
    if args.retry_base_delay is not None:
        global_settings["retry_base_delay"] = args.retry_base_delay
    if args.retry_max_delay is not None:
        global_settings["retry_max_delay"] = args.retry_max_delay
    if args.disable_rate_limiting:
        global_settings["enable_rate_limiting"] = False

    # Handle parallel execution settings.
    #
    # --parallel now defaults to None (not True) so it only overrides the
    # config file when the user actually passes it. Previously it defaulted
    # to True, meaning `elif args.parallel:` was truthy on every invocation
    # and silently forced global_settings["parallel_execution"] back to True
    # even when a config file explicitly set `parallel_execution: false` —
    # the only way to get sequential execution was --sequential, and the
    # config setting was pure noise. --sequential still wins if both are
    # passed (mirrors "the more specific/defensive flag wins").
    if args.sequential:
        global_settings["parallel_execution"] = False
    elif args.parallel:
        global_settings["parallel_execution"] = True
    # else: leave whatever the config file / default already set.

    if args.max_workers is not None:
        global_settings["max_workers"] = args.max_workers
    if args.batch_size is not None:
        global_settings["batch_size"] = args.batch_size

    # Override pillar and severity filters
    if args.pillars:
        merged_config["enabled_pillars"] = args.pillars
    if args.severity:
        merged_config["enabled_severities"] = args.severity

    # Override output settings
    output_settings = merged_config.setdefault("output", {})
    if args.output_dir:
        output_settings["directory"] = args.output_dir
    if args.output_format:
        output_settings["format"] = args.output_format
    if args.output_filename:
        output_settings["filename_template"] = args.output_filename
    if getattr(args, "s3_output", False):
        output_settings["s3_enabled"] = True
    if getattr(args, "s3_bucket", None):
        output_settings["s3_bucket"] = args.s3_bucket

    # Add CLI-specific settings
    merged_config["cli"] = {
        "checks": args.checks,
        "exclude_checks": args.exclude_checks,
        "dry_run": args.dry_run,
        "resume_assessment": args.resume_assessment,
        "checkpoint_dir": args.checkpoint_dir,
        "no_checkpoints": args.no_checkpoints,
        "skip_flow_analysis": getattr(args, "skip_flow_analysis", False),
        "diff_baseline": getattr(args, "diff", None),
    }

    return merged_config


def initialize_assessment_components(config: Dict[str, Any]) -> tuple:
    """
    Initialize assessment engine and related components.

    Args:
        config: Configuration dictionary

    Returns:
        Tuple of (AssessmentEngine, AWSClientFactory, CheckRegistry)
    """
    logger = logging.getLogger("cli")

    # Initialize AWS client factory
    aws_config = config.get("aws", {})
    global_settings = config.get("global_settings", {})

    # Import network resilience configuration
    from .network_resilience import RetryConfig

    network_resilience_config = RetryConfig(
        max_attempts=global_settings.get("max_retry_attempts", 5),
        base_delay=global_settings.get("retry_base_delay", 1.0),
        max_delay=global_settings.get("retry_max_delay", 60.0),
        timeout_seconds=global_settings.get("timeout", 300),
    )

    aws_client_factory = AWSClientFactory(
        region=aws_config.get("region"),
        profile_name=aws_config.get("profile"),
        network_resilience_config=network_resilience_config,
        enable_rate_limiting=global_settings.get("enable_rate_limiting", True),
        operation_timeout=global_settings.get("timeout", 300),
    )

    # Initialize check registry and load checks
    check_registry = CheckRegistry()

    # Register all checks using the central registration module.
    try:
        from .checks.registration import register_all_checks

        cli_opts = config.get("cli", {})
        pillar_filter = None
        enabled_pillars = config.get("enabled_pillars")
        if enabled_pillars:
            pillar_filter = set(enabled_pillars)

        # NOTE: enabled_severities always has a default value (all four
        # levels) from ConfigurationManager._get_default_config, so we
        # only treat it as an active filter when the CLI/config narrowed
        # it away from that default. Otherwise every run would silently
        # filter to the default list even without --severity, which
        # would be harmless today but fragile if the default set ever
        # changes independent of this check.
        severity_filter = None
        enabled_severities = config.get("enabled_severities")
        all_severities = {"critical", "high", "medium", "low"}
        if enabled_severities and set(enabled_severities) != all_severities:
            severity_filter = set(enabled_severities)

        check_ids_filter = set(cli_opts["checks"]) if cli_opts.get("checks") else None
        exclude_check_ids = (
            set(cli_opts["exclude_checks"]) if cli_opts.get("exclude_checks") else None
        )

        skip_flow = cli_opts.get("skip_flow_analysis", False)

        register_all_checks(
            check_registry,
            pillars=pillar_filter,
            severities=severity_filter,
            check_ids=check_ids_filter,
            exclude_check_ids=exclude_check_ids,
            skip_flow_analysis=skip_flow,
        )
        logger.info(f"Registered {len(check_registry)} checks")
    except Exception as e:
        logger.warning(f"Failed to load checks: {str(e)}")
        # Fallback to MVP checks only.
        from .checks.mvp_checks import get_mvp_checks

        for check in get_mvp_checks():
            try:
                check_registry.register_check(check)
            except ValueError:
                pass

    # Load additional configuration for checks
    check_registry.load_checks_from_config(config.get("checks", {}))

    # Initialize assessment engine - use parallel engine if enabled
    parallel_enabled = global_settings.get("parallel_execution", True)

    if parallel_enabled:
        logger.info("Initializing parallel assessment engine")
        from .parallel_engine import ParallelAssessmentEngine

        # Get parallel execution settings
        max_workers = global_settings.get("max_workers", None)  # None = auto-detect
        batch_size = global_settings.get("batch_size", 10)

        engine = ParallelAssessmentEngine(
            aws_client_factory=aws_client_factory,
            config=config,
            checkpoint_dir=config.get("cli", {}).get("checkpoint_dir"),
            max_workers=max_workers,
            batch_size=batch_size,
            enable_connection_pooling=True,
        )

        logger.info(
            f"Parallel engine configured with {engine.max_workers} workers, batch size {batch_size}"
        )
    else:
        logger.info("Initializing sequential assessment engine")
        engine = AssessmentEngine(
            aws_client_factory=aws_client_factory,
            config=config,
            checkpoint_dir=config.get("cli", {}).get("checkpoint_dir"),
        )

    # IMPORTANT: Set the populated check registry on the engine
    # The engine creates its own empty registry by default
    engine.check_registry = check_registry

    # Disable checkpoints if requested
    if config.get("cli", {}).get("no_checkpoints"):
        engine.enable_checkpoints(False)

    # Add analyzers
    engine.add_analyzer(ConnectInstanceAnalyzer(aws_client_factory))
    if skip_flow:
        logger.info("Skipping ContactFlowAnalyzer because flow analysis is disabled")
    else:
        engine.add_analyzer(ContactFlowAnalyzer(aws_client_factory))
    engine.add_analyzer(QueueAnalyzer(aws_client_factory))
    engine.add_analyzer(SecurityProfileAnalyzer(aws_client_factory))
    engine.add_analyzer(IntegrationAnalyzer(aws_client_factory))

    return engine, aws_client_factory, check_registry


def list_available_checks(check_registry: CheckRegistry) -> None:
    """
    Display all available checks organized by pillar and severity.

    Args:
        check_registry: CheckRegistry instance
    """
    print("Available Checks:")
    print("=" * 50)

    checks = check_registry.get_all_checks()
    if not checks:
        print("No checks registered.")
        return

    # Group checks by pillar
    pillars = {}
    for check in checks:
        pillar = check.pillar.value
        if pillar not in pillars:
            pillars[pillar] = []
        pillars[pillar].append(check)

    for pillar, pillar_checks in sorted(pillars.items()):
        print(f"\n{pillar.upper()} ({len(pillar_checks)} checks):")
        print("-" * 30)

        # Sort by severity (critical first)
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        pillar_checks.sort(key=lambda c: severity_order.get(c.severity.value, 4))

        for check in pillar_checks:
            status = "enabled" if getattr(check, "enabled", True) else "disabled"
            print(f"  {check.check_id:<25} [{check.severity.value.upper():<8}] ({status})")
            if hasattr(check, "description") and check.description:
                print(f"    {check.description}")


def show_current_config(config: Dict[str, Any], config_file_path: Optional[str]) -> None:
    """
    Display the current configuration.

    Args:
        config: Configuration dictionary
        config_file_path: Path to configuration file if loaded
    """
    print("Current Configuration:")
    print("=" * 50)

    if config_file_path:
        print(f"Configuration file: {config_file_path}")
    else:
        print("Configuration file: Using defaults (no config file found)")

    print("\nConfiguration:")
    print(json.dumps(config, indent=2, default=str))


def test_network_connectivity(aws_client_factory: AWSClientFactory) -> bool:
    """
    Test network connectivity to AWS services.

    Args:
        aws_client_factory: AWSClientFactory instance

    Returns:
        True if connectivity tests pass, False otherwise
    """
    print("Testing network connectivity to AWS services...")

    try:
        connectivity_result = aws_client_factory.test_network_connectivity()

        print(f"\nOverall Status: {connectivity_result['overall_status'].upper()}")
        print(f"Success Rate: {connectivity_result['success_rate']:.1%}")

        # Show individual test results
        print("\nService Tests:")
        for test_name, result in connectivity_result["tests"].items():
            status_icon = "✓" if result["status"] == "success" else "✗"
            if result["status"] == "success":
                response_time = result.get("response_time_seconds", 0)
                print(f"  {status_icon} {test_name}: {response_time:.2f}s")
            else:
                print(f"  {status_icon} {test_name}: {result['error']}")
                if result.get("retry_attempts", 0) > 0:
                    print(f"    (after {result['retry_attempts']} retry attempts)")

        # Show network resilience statistics
        resilience_stats = aws_client_factory.get_network_resilience_statistics()
        retry_stats = resilience_stats.get("retry_statistics", {})
        if retry_stats.get("total_attempts", 0) > 0:
            print("\nNetwork Resilience Statistics:")
            print(f"  Total retry attempts: {retry_stats['total_attempts']}")
            print(f"  Total delay time: {retry_stats['total_delay']:.2f}s")
            if retry_stats.get("error_types"):
                print("  Error types encountered:")
                for error_type, count in retry_stats["error_types"].items():
                    print(f"    {error_type}: {count}")

        # Show recommendations
        if connectivity_result.get("recommendations"):
            print("\nRecommendations:")
            for recommendation in connectivity_result["recommendations"]:
                print(f"  • {recommendation}")

        # Show recommended timeout settings
        timeout_recommendations = aws_client_factory.get_recommended_timeout_settings()
        print("\nRecommended Timeout Settings:")
        print(f"  Operation timeout: {timeout_recommendations['operation_timeout']:.0f}s")
        print(f"  Connect timeout: {timeout_recommendations['connect_timeout']:.0f}s")
        print(f"  Based on {timeout_recommendations['based_on_samples']} network samples")

        return connectivity_result["overall_status"] in ["healthy", "degraded"]

    except Exception as e:
        print(f"Network connectivity test failed: {str(e)}")
        return False


def check_aws_permissions(aws_client_factory: AWSClientFactory) -> bool:
    """
    Check AWS credentials and permissions.

    Args:
        aws_client_factory: AWSClientFactory instance

    Returns:
        True if permissions are valid, False otherwise
    """
    logger = logging.getLogger("cli")

    print("Checking AWS Credentials and Permissions:")
    print("=" * 50)

    try:
        # Check credentials
        cred_result = aws_client_factory.validate_credentials()
        print(f"Credentials: {'✓ Valid' if cred_result.is_valid else '✗ Invalid'}")
        if cred_result.is_valid:
            print(f"  Source: {cred_result.credential_source.value}")
            print(f"  Account ID: {cred_result.account_id}")
            print(f"  Region: {aws_client_factory.region}")
        else:
            print(f"  Error: {cred_result.error_message}")
            return False

        # Check permissions
        perm_result = aws_client_factory.validate_permissions()
        print(f"\nPermissions: {'✓ Valid' if perm_result.is_valid else '✗ Invalid'}")

        if perm_result.tested_permissions:
            print("  Tested permissions:")
            for perm in perm_result.tested_permissions:
                print(f"    ✓ {perm}")

        if perm_result.missing_permissions:
            print("  Missing permissions:")
            for perm in perm_result.missing_permissions:
                print(f"    ✗ {perm}")

        if perm_result.error_message:
            print(f"  Error: {perm_result.error_message}")

        return perm_result.is_valid

    except Exception as e:
        logger.error(f"Permission check failed: {str(e)}")
        print(f"✗ Permission check failed: {str(e)}")
        return False


def run_assessment(
    engine: AssessmentEngine,
    config: Dict[str, Any],
    aws_client_factory: Optional[AWSClientFactory] = None,
) -> bool:
    """
    Run the assessment and generate reports.

    Args:
        engine: AssessmentEngine instance
        config: Configuration dictionary
        aws_client_factory: Factory used for optional post-run actions such as
            publishing reports to S3.

    Returns:
        True if assessment completed successfully, False otherwise
    """
    logger = logging.getLogger("cli")

    try:
        # Show execution mode information
        from .parallel_engine import ParallelAssessmentEngine

        if isinstance(engine, ParallelAssessmentEngine):
            logger.info(
                f"Running assessment with parallel execution ({engine.max_workers} workers, batch size {engine.batch_size})"
            )
        else:
            logger.info("Running assessment with sequential execution")

        # Check if resuming assessment
        resume_id = config.get("cli", {}).get("resume_assessment")
        if resume_id:
            logger.info(f"Attempting to resume assessment {resume_id}")
            result = engine.resume_assessment(resume_id)
            if not result:
                logger.error(f"Could not resume assessment {resume_id}")
                return False
        else:
            # Run new assessment
            logger.info("Starting new assessment")
            result = engine.run_assessment()

        # Show performance statistics if available
        if hasattr(engine, "get_performance_stats"):
            perf_stats = engine.get_performance_stats()
            execution_time = perf_stats.get("execution_time_seconds", 0)
            parallel_stats = perf_stats.get("parallel_execution_stats", {})

            if parallel_stats:
                logger.info(f"Assessment completed in {execution_time:.2f} seconds")
                logger.info(
                    f"Processed {parallel_stats.get('parallel_batches', 0)} parallel batches"
                )
                if parallel_stats.get("fastest_check", 0) > 0:
                    logger.info(
                        f"Check time range: {parallel_stats.get('fastest_check', 0):.3f}s - {parallel_stats.get('slowest_check', 0):.3f}s"
                    )

        # Generate reports
        output_config = config.get("output", {})
        output_formats = output_config.get("format", ["html"])
        filename_template = output_config.get("filename_template")
        default_filename_template = "connect_assessment_{timestamp}_{account_id}"
        output_dir = output_config.get("directory") or REPORTS_DIRECTORY

        # Ensure output directory exists
        os.makedirs(output_dir, exist_ok=True)

        report_generator = ReportGenerator()

        generated_report_paths: List[str] = []

        for fmt in output_formats:
            if fmt == "html":
                # Generate proper filename for HTML report
                html_filename = report_generator._generate_filename(
                    filename_template or default_filename_template,
                    result,
                    "html",
                )
                html_path = os.path.join(output_dir, html_filename)

                # Generate HTML report (returns HTML content, saves to file)
                report_generator.generate_html_report(result, html_path)
                generated_report_paths.append(html_path)
                logger.info(f"HTML report generated: {html_path}")
            elif fmt == "json":
                report_path = report_generator.generate_json_report(
                    result,
                    output_dir,
                    filename_template=filename_template,
                )
                generated_report_paths.append(report_path)
                logger.info(f"JSON report generated: {report_path}")
            elif fmt == "csv":
                report_path = report_generator.generate_csv_report(
                    result,
                    output_dir,
                    filename_template=filename_template,
                )
                generated_report_paths.append(report_path)
                logger.info(f"CSV report generated: {report_path}")
            elif fmt == "asff":
                from .report.asff_export import export_asff

                asff_path = export_asff(
                    result,
                    output_dir,
                    filename_template=filename_template,
                )
                generated_report_paths.append(asff_path)
                logger.info(f"ASFF report generated: {asff_path}")

        # Run diff if a baseline was provided
        diff_baseline = config.get("cli", {}).get("diff_baseline")
        if diff_baseline:
            from .report.findings_diff import diff_from_files, print_diff

            # We need a current JSON to compare — generate one temporarily
            temp_json_path = report_generator.generate_json_report(
                result,
                output_dir,
                filename_template=filename_template,
            )
            diff_result = diff_from_files(diff_baseline, temp_json_path)
            print_diff(diff_result)

        # Print summary
        print("\nAssessment completed successfully!")
        print(f"Assessment ID: {result.assessment_id}")
        journey_findings = getattr(result.summary, "journey_findings", 0)
        registered_checks = getattr(result.summary, "registered_checks", None)
        if registered_checks is None:
            registered_checks = result.summary.total_checks - journey_findings
        print(f"Total findings: {result.summary.total_checks}")
        print(f"Registered checks executed: {registered_checks}")
        if journey_findings:
            print(f"Caller Journey findings: {journey_findings}")
        print(f"Passed: {result.summary.passed_checks}")
        print(f"Failed: {result.summary.failed_checks}")
        if result.summary.critical_findings > 0:
            print(f"Critical findings: {result.summary.critical_findings}")
        if result.summary.high_findings > 0:
            print(f"High severity findings: {result.summary.high_findings}")

        # Show performance information
        if hasattr(engine, "get_performance_stats"):
            perf_stats = engine.get_performance_stats()
            execution_time = perf_stats.get("execution_time_seconds", 0)
            if execution_time > 0:
                print(f"Execution time: {execution_time:.2f} seconds")
                if isinstance(engine, ParallelAssessmentEngine):
                    print(f"Parallel execution with {engine.max_workers} workers")

        print(f"\nReports generated in: {output_dir}")

        # Optionally publish reports to S3 in the assessed account.
        if output_config.get("s3_enabled") and aws_client_factory is not None:
            from .report.s3_publisher import publish_reports

            account_id = getattr(result, "account_id", None) or "unknown"
            region = config.get("aws", {}).get("region") or aws_client_factory.region
            publish = publish_reports(
                aws_client_factory,
                generated_report_paths,
                account_id=account_id,
                region=region,
                bucket_name=output_config.get("s3_bucket"),
            )
            if publish.succeeded:
                action = "created" if publish.bucket_created else "used existing"
                print(
                    f"\nUploaded {len(publish.uploaded_uris)} report(s) to S3 "
                    f"({action} bucket s3://{publish.bucket}):"
                )
                for uri in publish.uploaded_uris:
                    print(f"  {uri}")
                if publish.console_url:
                    print(f"  Console: {publish.console_url}")
            else:
                print(f"\nS3 upload did not complete: {publish.error}")

        return True

    except Exception as e:
        logger.error(f"Assessment failed: {str(e)}")
        print(f"Assessment failed: {str(e)}")
        return False


def main() -> int:
    """
    Main entry point for the CLI application.

    Returns:
        Exit code (0 for success, non-zero for failure)
    """
    try:
        # Parse command-line arguments
        parser = create_argument_parser()
        args = parser.parse_args()

        # Load configuration
        config_manager = ConfigurationManager()
        config = config_manager.load_config(args.config)

        # Validate configuration if requested
        if args.validate_config:
            errors = config_manager.validate_config()
            if errors:
                print("Configuration validation failed:")
                for error in errors:
                    print(f"  ✗ {error}")
                return 1
            else:
                print("✓ Configuration is valid")
                return 0

        # Merge CLI arguments with configuration
        config = merge_cli_args_with_config(args, config)

        # Setup logging
        setup_logging_from_args(args, config)
        logger = logging.getLogger("cli")

        # Show configuration if requested
        if args.show_config:
            show_current_config(config, config_manager.get_config_file_path())
            return 0

        # Initialize assessment components
        try:
            engine, aws_client_factory, check_registry = initialize_assessment_components(config)
        except Exception as e:
            logger.error(f"Failed to initialize assessment components: {str(e)}")
            print(f"Initialization failed: {str(e)}")
            return 1

        # List checks if requested
        if args.list_checks:
            list_available_checks(check_registry)
            return 0

        # Check permissions if requested
        if args.check_permissions:
            if check_aws_permissions(aws_client_factory):
                print("\n✓ All permission checks passed")
                return 0
            else:
                print("\n✗ Permission checks failed")
                return 1

        # Test network connectivity if requested
        if args.network_test:
            if test_network_connectivity(aws_client_factory):
                print("\n✓ Network connectivity test passed")
                return 0
            else:
                print("\n✗ Network connectivity test failed")
                return 1

        # Validate configuration and permissions
        validation_result = engine.validate_configuration()
        if not validation_result["is_valid"]:
            print("Configuration validation failed:")
            for error in validation_result["errors"]:
                print(f"  ✗ {error}")
            return 1

        # Show warnings if any
        if validation_result["warnings"]:
            print("Configuration warnings:")
            for warning in validation_result["warnings"]:
                print(f"  ⚠ {warning}")

        # Dry run mode
        if args.dry_run:
            print("✓ Dry run completed successfully - configuration and permissions are valid")
            return 0

        # Run assessment
        if run_assessment(engine, config, aws_client_factory):
            return 0
        else:
            return 1

    except KeyboardInterrupt:
        print("\nAssessment interrupted by user")
        return 130
    except Exception as e:
        print(f"Unexpected error: {str(e)}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
