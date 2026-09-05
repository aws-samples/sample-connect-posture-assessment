"""
Extended CLI coverage — tests for helper functions and config operations.
"""

from amazon_connect_assessment.cli import (
    ConfigurationManager,
    create_argument_parser,
    merge_cli_args_with_config,
    setup_logging_from_args,
)


class TestConfigurationManagerExtended:
    def test_env_override_region(self, monkeypatch):
        monkeypatch.setenv("AWS_REGION", "eu-west-1")
        mgr = ConfigurationManager()
        config = mgr.load_config()
        assert config["aws"]["region"] == "eu-west-1"

    def test_env_override_log_level(self, monkeypatch):
        monkeypatch.setenv("CONNECT_ASSESSMENT_LOG_LEVEL", "DEBUG")
        mgr = ConfigurationManager()
        config = mgr.load_config()
        assert config["global_settings"]["log_level"] == "DEBUG"

    def test_env_override_timeout(self, monkeypatch):
        monkeypatch.setenv("CONNECT_ASSESSMENT_TIMEOUT", "600")
        mgr = ConfigurationManager()
        config = mgr.load_config()
        assert config["global_settings"]["timeout"] == 600

    def test_validate_invalid_timeout(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        mgr.config["global_settings"]["timeout"] = -1
        errors = mgr.validate_config()
        assert any("timeout" in e for e in errors)

    def test_validate_invalid_output_format(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        mgr.config["output"]["format"] = ["pdf"]
        errors = mgr.validate_config()
        assert any("pdf" in e for e in errors)

    def test_validate_invalid_severity(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        mgr.config["enabled_severities"] = ["extreme"]
        errors = mgr.validate_config()
        assert any("extreme" in e for e in errors)

    def test_get_config_returns_copy(self):
        mgr = ConfigurationManager()
        mgr.load_config()
        c1 = mgr.get_config()
        c1["new_key"] = "x"
        assert "new_key" not in mgr.config


class TestMergeCliArgs:
    def test_region_override(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--region", "ap-southeast-1"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["aws"]["region"] == "ap-southeast-1"

    def test_sequential_flag(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--sequential"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["global_settings"]["parallel_execution"] is False

    def test_output_format_override(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--output-format", "json", "csv"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["output"]["format"] == ["json", "csv"]

    def test_config_output_format_survives_without_cli_override(self):
        parser = create_argument_parser()
        args = parser.parse_args([])
        config = ConfigurationManager().load_config()
        config["output"]["format"] = ["json", "csv"]
        merged = merge_cli_args_with_config(args, config)
        assert merged["output"]["format"] == ["json", "csv"]

    def test_output_format_defaults_to_none_for_config_precedence(self):
        parser = create_argument_parser()
        args = parser.parse_args([])
        assert args.output_format is None

    def test_output_directory_cli_override(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--output-dir", "/tmp/custom-reports"])
        config = ConfigurationManager().load_config()
        config["output"]["directory"] = "/var/reports"
        merged = merge_cli_args_with_config(args, config)
        assert merged["output"]["directory"] == "/tmp/custom-reports"

    def test_config_output_directory_survives_without_cli_override(self):
        parser = create_argument_parser()
        args = parser.parse_args([])
        config = ConfigurationManager().load_config()
        config["output"]["directory"] = "/var/reports"
        merged = merge_cli_args_with_config(args, config)
        assert merged["output"]["directory"] == "/var/reports"

    def test_max_workers_override(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--max-workers", "16"])
        config = ConfigurationManager().load_config()
        merged = merge_cli_args_with_config(args, config)
        assert merged["global_settings"]["max_workers"] == 16

    def test_explicit_zero_numeric_values_are_preserved(self):
        parser = create_argument_parser()
        args = parser.parse_args(
            [
                "--timeout",
                "0",
                "--retry-count",
                "0",
                "--max-retry-attempts",
                "0",
                "--retry-base-delay",
                "0",
                "--retry-max-delay",
                "0",
                "--max-workers",
                "0",
                "--batch-size",
                "0",
            ]
        )
        config = ConfigurationManager().load_config()

        merged = merge_cli_args_with_config(args, config)

        assert merged["global_settings"]["timeout"] == 0
        assert merged["global_settings"]["retry_count"] == 0
        assert merged["global_settings"]["max_retry_attempts"] == 0
        assert merged["global_settings"]["retry_base_delay"] == 0
        assert merged["global_settings"]["retry_max_delay"] == 0
        assert merged["global_settings"]["max_workers"] == 0
        assert merged["global_settings"]["batch_size"] == 0


class TestSetupLogging:
    def test_quiet_sets_error(self):
        parser = create_argument_parser()
        args = parser.parse_args(["--quiet"])
        config = {"global_settings": {"log_level": "INFO"}}
        # Should not raise.
        setup_logging_from_args(args, config)

    def test_verbose_sets_info(self):
        parser = create_argument_parser()
        args = parser.parse_args(["-v"])
        config = {"global_settings": {"log_level": "WARNING"}}
        setup_logging_from_args(args, config)

    def test_double_verbose_sets_debug(self):
        parser = create_argument_parser()
        args = parser.parse_args(["-vv"])
        config = {"global_settings": {"log_level": "WARNING"}}
        setup_logging_from_args(args, config)
