"""
Unit tests for the check configuration system.

Tests the configuration management functionality including loading
from files, merging configurations, and validation.
"""

import json
from pathlib import Path
from tempfile import NamedTemporaryFile

import pytest
import yaml

from amazon_connect_assessment.checks.config import (
    AssessmentConfig,
    CheckConfig,
    CheckConfigurationManager,
)
from amazon_connect_assessment.models import Pillar, Severity


class TestCheckConfig:
    """Test CheckConfig functionality."""

    def test_check_config_creation(self):
        """Test basic CheckConfig creation."""
        config = CheckConfig(
            check_id="test-check",
            enabled=True,
            severity=Severity.HIGH,
            parameters={"param1": "value1"},
            remediation_template="Test remediation",
            description="Test description",
        )

        assert config.check_id == "test-check"
        assert config.enabled is True
        assert config.severity == Severity.HIGH
        assert config.parameters == {"param1": "value1"}
        assert config.remediation_template == "Test remediation"
        assert config.description == "Test description"

    def test_check_config_defaults(self):
        """Test CheckConfig with default values."""
        config = CheckConfig(check_id="test-check")

        assert config.check_id == "test-check"
        assert config.enabled is True
        assert config.severity is None
        assert config.parameters == {}
        assert config.remediation_template is None
        assert config.description is None

    def test_check_config_to_dict(self):
        """Test CheckConfig to dictionary conversion."""
        config = CheckConfig(
            check_id="test-check",
            enabled=False,
            severity=Severity.CRITICAL,
            parameters={"key": "value"},
            remediation_template="Fix this",
            description="Test check",
        )

        result = config.to_dict()

        expected = {
            "check_id": "test-check",
            "enabled": False,
            "severity": "critical",
            "parameters": {"key": "value"},
            "remediation_template": "Fix this",
            "description": "Test check",
        }

        assert result == expected

    def test_check_config_from_dict(self):
        """Test CheckConfig creation from dictionary."""
        data = {
            "check_id": "test-check",
            "enabled": False,
            "severity": "high",
            "parameters": {"param": "value"},
            "remediation_template": "Fix it",
            "description": "Test description",
        }

        config = CheckConfig.from_dict(data)

        assert config.check_id == "test-check"
        assert config.enabled is False
        assert config.severity == Severity.HIGH
        assert config.parameters == {"param": "value"}
        assert config.remediation_template == "Fix it"
        assert config.description == "Test description"

    def test_check_config_from_dict_minimal(self):
        """Test CheckConfig creation from minimal dictionary."""
        data = {"check_id": "minimal-check"}

        config = CheckConfig.from_dict(data)

        assert config.check_id == "minimal-check"
        assert config.enabled is True
        assert config.severity is None
        assert config.parameters == {}


class TestAssessmentConfig:
    """Test AssessmentConfig functionality."""

    def test_assessment_config_creation(self):
        """Test basic AssessmentConfig creation."""
        config = AssessmentConfig()

        assert config.global_settings == {}
        assert config.check_configs == {}
        assert config.enabled_pillars == list(Pillar)
        assert config.enabled_severities == list(Severity)

    def test_get_check_config(self):
        """Test getting check configuration."""
        config = AssessmentConfig()
        check_config = CheckConfig(check_id="test-check", enabled=False)
        config.add_check_config(check_config)

        result = config.get_check_config("test-check")
        assert result == check_config

        result = config.get_check_config("nonexistent")
        assert result is None

    def test_is_check_enabled(self):
        """Test check enabled status."""
        config = AssessmentConfig()

        # Non-existent check should default to enabled
        assert config.is_check_enabled("nonexistent") is True

        # Add disabled check
        check_config = CheckConfig(check_id="disabled-check", enabled=False)
        config.add_check_config(check_config)
        assert config.is_check_enabled("disabled-check") is False

        # Add enabled check
        check_config = CheckConfig(check_id="enabled-check", enabled=True)
        config.add_check_config(check_config)
        assert config.is_check_enabled("enabled-check") is True

    def test_get_check_parameters(self):
        """Test getting check parameters."""
        config = AssessmentConfig()

        # Non-existent check should return empty dict
        assert config.get_check_parameters("nonexistent") == {}

        # Add check with parameters
        check_config = CheckConfig(check_id="param-check", parameters={"key": "value", "num": 42})
        config.add_check_config(check_config)
        assert config.get_check_parameters("param-check") == {"key": "value", "num": 42}

    def test_get_check_severity_override(self):
        """Test getting check severity override."""
        config = AssessmentConfig()

        # Non-existent check should return None
        assert config.get_check_severity_override("nonexistent") is None

        # Add check without severity override
        check_config = CheckConfig(check_id="no-override")
        config.add_check_config(check_config)
        assert config.get_check_severity_override("no-override") is None

        # Add check with severity override
        check_config = CheckConfig(check_id="with-override", severity=Severity.CRITICAL)
        config.add_check_config(check_config)
        assert config.get_check_severity_override("with-override") == Severity.CRITICAL

    def test_to_dict(self):
        """Test AssessmentConfig to dictionary conversion."""
        config = AssessmentConfig()
        config.global_settings = {"timeout": 300}
        config.enabled_pillars = [Pillar.SECURITY]
        config.enabled_severities = [Severity.HIGH, Severity.CRITICAL]

        check_config = CheckConfig(check_id="test-check", enabled=False)
        config.add_check_config(check_config)

        result = config.to_dict()

        expected = {
            "global_settings": {"timeout": 300},
            "enabled_pillars": ["security"],
            "enabled_severities": ["high", "critical"],
            "checks": {
                "test-check": {
                    "check_id": "test-check",
                    "enabled": False,
                    "parameters": {},
                }
            },
        }

        assert result == expected

    def test_from_dict(self):
        """Test AssessmentConfig creation from dictionary."""
        data = {
            "global_settings": {"timeout": 600, "retry_count": 5},
            "enabled_pillars": ["security", "resilience"],
            "enabled_severities": ["critical", "high"],
            "checks": {
                "check-1": {
                    "check_id": "check-1",
                    "enabled": True,
                    "severity": "critical",
                    "parameters": {"param": "value"},
                },
                "check-2": {"check_id": "check-2", "enabled": False},
            },
        }

        config = AssessmentConfig.from_dict(data)

        assert config.global_settings == {"timeout": 600, "retry_count": 5}
        assert config.enabled_pillars == [Pillar.SECURITY, Pillar.RESILIENCE]
        assert config.enabled_severities == [Severity.CRITICAL, Severity.HIGH]
        assert len(config.check_configs) == 2
        assert config.check_configs["check-1"].enabled is True
        assert config.check_configs["check-1"].severity == Severity.CRITICAL
        assert config.check_configs["check-2"].enabled is False


class TestCheckConfigurationManager:
    """Test CheckConfigurationManager functionality."""

    def test_manager_creation(self):
        """Test basic manager creation."""
        manager = CheckConfigurationManager()
        config = manager.get_config()

        assert isinstance(config, AssessmentConfig)
        assert config.global_settings == {}
        assert config.check_configs == {}

    def test_load_from_dict(self):
        """Test loading configuration from dictionary."""
        manager = CheckConfigurationManager()
        config_data = {
            "global_settings": {"timeout": 300},
            "checks": {"test-check": {"check_id": "test-check", "enabled": False}},
        }

        manager.load_from_dict(config_data)
        config = manager.get_config()

        assert config.global_settings["timeout"] == 300
        assert "test-check" in config.check_configs
        assert config.check_configs["test-check"].enabled is False

    def test_load_from_json_file(self):
        """Test loading configuration from JSON file."""
        manager = CheckConfigurationManager()
        config_data = {
            "global_settings": {"timeout": 450},
            "checks": {
                "json-check": {
                    "check_id": "json-check",
                    "enabled": True,
                    "severity": "high",
                    "parameters": {"json_param": "json_value"},
                }
            },
        }

        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            temp_path = f.name

        try:
            manager.load_from_file(temp_path)
            config = manager.get_config()

            assert config.global_settings["timeout"] == 450
            assert "json-check" in config.check_configs
            check_config = config.check_configs["json-check"]
            assert check_config.enabled is True
            assert check_config.severity == Severity.HIGH
            assert check_config.parameters == {"json_param": "json_value"}
        finally:
            Path(temp_path).unlink()

    def test_load_from_yaml_file(self):
        """Test loading configuration from YAML file."""
        manager = CheckConfigurationManager()
        config_data = {
            "global_settings": {"retry_count": 5},
            "enabled_pillars": ["security"],
            "checks": {
                "yaml-check": {
                    "check_id": "yaml-check",
                    "enabled": False,
                    "parameters": {"yaml_param": "yaml_value"},
                }
            },
        }

        with NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(config_data, f)
            temp_path = f.name

        try:
            manager.load_from_file(temp_path)
            config = manager.get_config()

            assert config.global_settings["retry_count"] == 5
            assert config.enabled_pillars == [Pillar.SECURITY]
            assert "yaml-check" in config.check_configs
            assert config.check_configs["yaml-check"].enabled is False
        finally:
            Path(temp_path).unlink()

    def test_load_nonexistent_file(self):
        """Test loading from non-existent file."""
        manager = CheckConfigurationManager()

        with pytest.raises(FileNotFoundError):
            manager.load_from_file("/nonexistent/path/config.json")

    def test_load_unsupported_format(self):
        """Test loading from unsupported file format."""
        manager = CheckConfigurationManager()

        with NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
            f.write("not a config file")
            temp_path = f.name

        try:
            with pytest.raises(ValueError, match="Unsupported configuration file format"):
                manager.load_from_file(temp_path)
        finally:
            Path(temp_path).unlink()

    def test_save_to_json_file(self):
        """Test saving configuration to JSON file."""
        manager = CheckConfigurationManager()
        manager.set_global_setting("timeout", 600)

        check_config = CheckConfig(check_id="save-test", enabled=True, severity=Severity.MEDIUM)
        manager.add_check_config(check_config)

        with NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            temp_path = f.name

        try:
            manager.save_to_file(temp_path)

            # Verify the saved file
            with open(temp_path, "r") as f:
                saved_data = json.load(f)

            assert saved_data["global_settings"]["timeout"] == 600
            assert "save-test" in saved_data["checks"]
            assert saved_data["checks"]["save-test"]["enabled"] is True
            assert saved_data["checks"]["save-test"]["severity"] == "medium"
        finally:
            Path(temp_path).unlink()

    def test_save_to_yaml_file(self):
        """Test saving configuration to YAML file."""
        manager = CheckConfigurationManager()
        manager.set_global_setting("retry_count", 3)

        with NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            temp_path = f.name

        try:
            manager.save_to_file(temp_path)

            # Verify the saved file
            with open(temp_path, "r") as f:
                saved_data = yaml.safe_load(f)

            assert saved_data["global_settings"]["retry_count"] == 3
        finally:
            Path(temp_path).unlink()

    def test_merge_configurations(self):
        """Test merging multiple configurations."""
        manager = CheckConfigurationManager()

        # Load first configuration
        config1 = {
            "global_settings": {"timeout": 300, "retry_count": 3},
            "checks": {"check-1": {"check_id": "check-1", "enabled": True}},
        }
        manager.load_from_dict(config1)

        # Load second configuration (should merge)
        config2 = {
            "global_settings": {"timeout": 600, "max_workers": 8},  # timeout overridden
            "checks": {"check-2": {"check_id": "check-2", "enabled": False}},
        }
        manager.load_from_dict(config2)

        config = manager.get_config()

        # Global settings should be merged with override
        assert config.global_settings["timeout"] == 600  # overridden
        assert config.global_settings["retry_count"] == 3  # preserved
        assert config.global_settings["max_workers"] == 8  # added

        # Check configs should be merged
        assert len(config.check_configs) == 2
        assert "check-1" in config.check_configs
        assert "check-2" in config.check_configs

    def test_configuration_validation(self):
        """Test configuration validation."""
        manager = CheckConfigurationManager()

        # Valid configuration
        manager.set_global_setting("timeout", 300)
        manager.set_global_setting("retry_count", 3)
        manager.set_global_setting("max_workers", 4)

        errors = manager.validate_config()
        assert len(errors) == 0

        # Invalid configuration
        manager.set_global_setting("timeout", -100)  # negative timeout
        manager.set_global_setting("retry_count", "invalid")  # non-integer
        manager.set_global_setting("max_workers", 0)  # zero workers

        errors = manager.validate_config()
        assert len(errors) == 3
        assert any("timeout" in error for error in errors)
        assert any("retry_count" in error for error in errors)
        assert any("max_workers" in error for error in errors)

    def test_create_default_config(self):
        """Test creating default configuration."""
        manager = CheckConfigurationManager()
        default_config = manager.create_default_config()

        assert isinstance(default_config, AssessmentConfig)
        assert "timeout" in default_config.global_settings
        assert "retry_count" in default_config.global_settings
        assert "parallel_execution" in default_config.global_settings
        assert "max_workers" in default_config.global_settings
        assert default_config.enabled_pillars == list(Pillar)
        assert default_config.enabled_severities == list(Severity)

    def test_convenience_methods(self):
        """Test convenience methods for accessing configuration."""
        manager = CheckConfigurationManager()

        # Test global settings
        manager.set_global_setting("test_key", "test_value")
        assert manager.get_global_setting("test_key") == "test_value"
        assert manager.get_global_setting("nonexistent", "default") == "default"

        # Test check configuration methods
        check_config = CheckConfig(
            check_id="convenience-test",
            enabled=False,
            parameters={"param1": "value1"},
        )
        manager.add_check_config(check_config)

        assert manager.is_check_enabled("convenience-test") is False
        assert manager.get_check_parameters("convenience-test") == {"param1": "value1"}
        assert manager.get_check_config("convenience-test") == check_config

        # Test pillar and severity methods
        config = manager.get_config()
        config.enabled_pillars = [Pillar.SECURITY]
        config.enabled_severities = [Severity.HIGH, Severity.CRITICAL]

        assert manager.get_enabled_pillars() == [Pillar.SECURITY]
        assert manager.get_enabled_severities() == [Severity.HIGH, Severity.CRITICAL]
