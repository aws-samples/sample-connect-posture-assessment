"""
Coverage tests for CLI initialization path (initialize_assessment_components).
"""

from unittest.mock import Mock, patch

from amazon_connect_assessment.analyzers.contact_flow_analyzer import ContactFlowAnalyzer
from amazon_connect_assessment.cli import (
    ConfigurationManager,
    create_argument_parser,
    initialize_assessment_components,
    merge_cli_args_with_config,
)


class TestConfigurationManager:
    def test_default_config_has_all_pillars(self):
        mgr = ConfigurationManager()
        config = mgr.load_config()
        assert "resilience" in config["enabled_pillars"]
        assert "security" in config["enabled_pillars"]
        assert "cost_optimization" in config["enabled_pillars"]

    def test_validate_default_config_is_valid(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        errors = mgr.validate_config()
        assert errors == []

    def test_validate_rejects_invalid_pillar(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        mgr.config["enabled_pillars"] = ["invalid_pillar"]
        errors = mgr.validate_config()
        assert any("invalid_pillar" in e for e in errors)

    def test_validate_accepts_new_pillars(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        mgr.config["enabled_pillars"] = [
            "resilience",
            "operational_excellence",
            "performance_efficiency",
        ]
        errors = mgr.validate_config()
        assert errors == []


class TestCLIParsing:
    def test_skip_flow_analysis_flag(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--skip-flow-analysis"])
        assert args.skip_flow_analysis is True

    def test_pillars_accepts_new_values(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--pillars", "security", "operational_excellence"])
        assert "operational_excellence" in args.pillars

    def test_merge_cli_args_includes_skip_flow(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--skip-flow-analysis"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["cli"]["skip_flow_analysis"] is True


class TestInitializeComponents:
    @patch("amazon_connect_assessment.cli.AWSClientFactory")
    def test_initialize_registers_all_checks(self, mock_factory_class):
        mock_factory_class.return_value = Mock()
        config = ConfigurationManager().load_config()
        # Isolate from config/assessment_config.yaml's example `checks:`
        # section, which ConfigurationManager auto-discovers whenever the
        # working directory is the repo root (as it is under pytest). That
        # file intentionally disables one check as a documentation example
        # (see the file's own comments) — real behavior, not a no-op — so
        # tests asserting exact/floor counts must not depend on it.
        config["checks"] = {}
        config["cli"] = {
            "checks": None,
            "exclude_checks": None,
            "dry_run": False,
            "resume_assessment": None,
            "checkpoint_dir": None,
            "no_checkpoints": True,
            "skip_flow_analysis": False,
        }
        config["global_settings"]["parallel_execution"] = False

        engine, factory, registry = initialize_assessment_components(config)
        # Floor rather than exact count so catalog growth doesn't churn this
        # test — a drop below the floor signals accidental unregistration.
        # 55 before Multi-AZ / DR removals, 53 before FailoverMechanism, 52
        # before NetworkSecurityCheck + EncryptionConfigurationCheck. Floor
        # of 50 reflects the current baseline. See security_checks.py and
        # resilience_checks (deleted) module docstrings for the rationale.
        assert len(registry) >= 50

    @patch("amazon_connect_assessment.cli.AWSClientFactory")
    def test_initialize_with_skip_flow(self, mock_factory_class):
        mock_factory_class.return_value = Mock()
        config = ConfigurationManager().load_config()
        config["cli"] = {
            "checks": None,
            "exclude_checks": None,
            "dry_run": False,
            "resume_assessment": None,
            "checkpoint_dir": None,
            "no_checkpoints": True,
            "skip_flow_analysis": True,
        }
        config["global_settings"]["parallel_execution"] = False

        engine, factory, registry = initialize_assessment_components(config)
        # Fewer checks when flow analysis is skipped.
        assert len(registry) < 50
        assert "sec-prompt-inject-001" not in registry
        assert not any(isinstance(analyzer, ContactFlowAnalyzer) for analyzer in engine.analyzers)

    @patch("amazon_connect_assessment.cli.AWSClientFactory")
    def test_initialize_without_skip_flow_registers_contact_flow_analyzer(self, mock_factory_class):
        mock_factory_class.return_value = Mock()
        config = ConfigurationManager().load_config()
        config["cli"] = {
            "checks": None,
            "exclude_checks": None,
            "dry_run": False,
            "resume_assessment": None,
            "checkpoint_dir": None,
            "no_checkpoints": True,
            "skip_flow_analysis": False,
        }
        config["global_settings"]["parallel_execution"] = False

        engine, factory, registry = initialize_assessment_components(config)

        assert any(isinstance(analyzer, ContactFlowAnalyzer) for analyzer in engine.analyzers)

    @patch("amazon_connect_assessment.cli.AWSClientFactory")
    def test_initialize_with_pillar_filter(self, mock_factory_class):
        mock_factory_class.return_value = Mock()
        config = ConfigurationManager().load_config()
        config["enabled_pillars"] = ["security"]
        config["cli"] = {
            "checks": None,
            "exclude_checks": None,
            "dry_run": False,
            "resume_assessment": None,
            "checkpoint_dir": None,
            "no_checkpoints": True,
            "skip_flow_analysis": False,
        }
        config["global_settings"]["parallel_execution"] = False

        engine, factory, registry = initialize_assessment_components(config)
        for check in registry.get_all_checks():
            assert check.pillar.value == "security"


# ---------------------------------------------------------------------------
# Regression tests for CLI bugs found in review:
#
# 1. --severity / --checks / --exclude-checks were parsed and stored in
#    config but never reached register_all_checks — a smoke run of
#    `--severity critical --list-checks` still listed every check.
# 2. --parallel had default=True, so `elif args.parallel:` was truthy on
#    every invocation and silently forced parallel_execution back to True
#    even when a config file set `parallel_execution: false`.
# 3. --skip-flow-analysis is stored under config["cli"]["skip_flow_analysis"]
#    (see merge_cli_args_with_config below), not at the top level, so
#    AssessmentEngine._compute_journey_map's original top-level-only check
#    never actually disabled the Journey Map's API path for CLI users.
# ---------------------------------------------------------------------------


class TestCLIFilterWiring:
    @patch("amazon_connect_assessment.cli.AWSClientFactory")
    def test_severity_filter_reaches_registry(self, mock_factory_class):
        mock_factory_class.return_value = Mock()
        config = ConfigurationManager().load_config()
        config["enabled_severities"] = ["critical"]
        config["cli"] = {
            "checks": None,
            "exclude_checks": None,
            "dry_run": False,
            "resume_assessment": None,
            "checkpoint_dir": None,
            "no_checkpoints": True,
            "skip_flow_analysis": False,
        }
        config["global_settings"]["parallel_execution"] = False

        engine, factory, registry = initialize_assessment_components(config)
        assert len(registry) > 0
        for check in registry.get_all_checks():
            assert check.severity.value == "critical"

    @patch("amazon_connect_assessment.cli.AWSClientFactory")
    def test_checks_allowlist_reaches_registry(self, mock_factory_class):
        mock_factory_class.return_value = Mock()
        config = ConfigurationManager().load_config()
        config["cli"] = {
            "checks": ["security-iam-001"],
            "exclude_checks": None,
            "dry_run": False,
            "resume_assessment": None,
            "checkpoint_dir": None,
            "no_checkpoints": True,
            "skip_flow_analysis": False,
        }
        config["global_settings"]["parallel_execution"] = False

        engine, factory, registry = initialize_assessment_components(config)
        assert registry.list_check_ids() == ["security-iam-001"]

    @patch("amazon_connect_assessment.cli.AWSClientFactory")
    def test_exclude_checks_reaches_registry(self, mock_factory_class):
        mock_factory_class.return_value = Mock()
        config = ConfigurationManager().load_config()
        # See comment in test_initialize_registers_all_checks — isolate
        # from the repo's example config/assessment_config.yaml checks:
        # section so this count assertion is independent of it.
        config["checks"] = {}
        config["cli"] = {
            "checks": None,
            "exclude_checks": ["ops-logging-001"],
            "dry_run": False,
            "resume_assessment": None,
            "checkpoint_dir": None,
            "no_checkpoints": True,
            "skip_flow_analysis": False,
        }
        config["global_settings"]["parallel_execution"] = False

        engine, factory, registry = initialize_assessment_components(config)
        assert "ops-logging-001" not in registry
        assert len(registry) >= 49  # floor(50) - 1 excluded


class TestParallelExecutionFlagDefault:
    def test_parallel_flag_defaults_to_none_not_true(self):
        # This is the actual bug: --parallel used to default=True, which
        # meant `elif args.parallel:` was truthy even when the user never
        # passed the flag, silently overriding a config file's
        # parallel_execution: false back to True on every run.
        parser = create_argument_parser()
        args = parser.parse_args([])
        assert args.parallel is None

    def test_config_file_sequential_setting_survives_without_flags(self):
        parser = create_argument_parser()
        args = parser.parse_args([])  # no --parallel, no --sequential
        config = ConfigurationManager().load_config()
        config["global_settings"]["parallel_execution"] = False
        merged = merge_cli_args_with_config(args, config)
        # Must stay False — the whole point of the fix is that an
        # unpassed --parallel no longer clobbers this.
        assert merged["global_settings"]["parallel_execution"] is False

    def test_explicit_parallel_flag_still_overrides_config_false(self):
        # --parallel remains a real, working override for the case where
        # a config file says sequential but the user wants parallel for
        # one run.
        parser = create_argument_parser()
        args = parser.parse_args(["--parallel"])
        config = ConfigurationManager().load_config()
        config["global_settings"]["parallel_execution"] = False
        merged = merge_cli_args_with_config(args, config)
        assert merged["global_settings"]["parallel_execution"] is True

    def test_sequential_flag_overrides_default_true(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--sequential"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["global_settings"]["parallel_execution"] is False

    def test_sequential_wins_if_both_flags_passed(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--parallel", "--sequential"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["global_settings"]["parallel_execution"] is False


class TestSkipFlowAnalysisConfigLocation:
    def test_skip_flow_analysis_lands_under_cli_key(self):
        # Documents where the CLI actually puts this flag — engine code
        # that only checked the top-level key was reading the wrong
        # location. See AssessmentEngine._compute_journey_map /
        # _compute_journey_findings, which now check both locations.
        parser = create_argument_parser()
        args = parser.parse_args(["--skip-flow-analysis"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["cli"]["skip_flow_analysis"] is True
        assert merged.get("skip_flow_analysis") is None
