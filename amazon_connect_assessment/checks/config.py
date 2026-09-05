"""
Check configuration system for Amazon Connect assessments.

Provides external configuration support for assessment checks,
allowing customization of check parameters, enabling/disabling checks,
and overriding default settings through configuration files.
"""

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Union

import yaml

from ..models import Pillar, Severity


@dataclass
class CheckConfig:
    """
    Configuration for an individual assessment check.

    Contains all configurable parameters for a check including
    enablement status, severity overrides, and custom parameters.
    """

    check_id: str
    enabled: bool = True
    severity: Optional[Severity] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    remediation_template: Optional[str] = None
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert check config to dictionary representation."""
        config_dict = {
            "check_id": self.check_id,
            "enabled": self.enabled,
            "parameters": self.parameters,
        }

        if self.severity is not None:
            config_dict["severity"] = self.severity.value
        if self.remediation_template is not None:
            config_dict["remediation_template"] = self.remediation_template
        if self.description is not None:
            config_dict["description"] = self.description

        return config_dict

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CheckConfig":
        """Create CheckConfig from dictionary representation."""
        severity = None
        if "severity" in data:
            severity = Severity(data["severity"])

        return cls(
            check_id=data["check_id"],
            enabled=data.get("enabled", True),
            severity=severity,
            parameters=data.get("parameters", {}),
            remediation_template=data.get("remediation_template"),
            description=data.get("description"),
        )


@dataclass
class AssessmentConfig:
    """
    Complete assessment configuration.

    Contains global assessment settings and individual check configurations.
    """

    global_settings: Dict[str, Any] = field(default_factory=dict)
    check_configs: Dict[str, CheckConfig] = field(default_factory=dict)
    enabled_pillars: List[Pillar] = field(default_factory=lambda: list(Pillar))
    enabled_severities: List[Severity] = field(default_factory=lambda: list(Severity))

    def get_check_config(self, check_id: str) -> Optional[CheckConfig]:
        """Get configuration for a specific check."""
        return self.check_configs.get(check_id)

    def is_check_enabled(self, check_id: str) -> bool:
        """Check if a specific check is enabled."""
        config = self.get_check_config(check_id)
        return config.enabled if config else True

    def get_check_parameters(self, check_id: str) -> Dict[str, Any]:
        """Get parameters for a specific check."""
        config = self.get_check_config(check_id)
        return config.parameters if config else {}

    def get_check_severity_override(self, check_id: str) -> Optional[Severity]:
        """Get severity override for a specific check."""
        config = self.get_check_config(check_id)
        return config.severity if config else None

    def add_check_config(self, check_config: CheckConfig) -> None:
        """Add or update configuration for a check."""
        self.check_configs[check_config.check_id] = check_config

    def to_dict(self) -> Dict[str, Any]:
        """Convert assessment config to dictionary representation."""
        return {
            "global_settings": self.global_settings,
            "enabled_pillars": [pillar.value for pillar in self.enabled_pillars],
            "enabled_severities": [severity.value for severity in self.enabled_severities],
            "checks": {
                check_id: config.to_dict() for check_id, config in self.check_configs.items()
            },
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AssessmentConfig":
        """Create AssessmentConfig from dictionary representation."""
        config = cls()
        config.global_settings = data.get("global_settings", {})

        # Parse enabled pillars
        if "enabled_pillars" in data:
            config.enabled_pillars = [Pillar(pillar) for pillar in data["enabled_pillars"]]

        # Parse enabled severities
        if "enabled_severities" in data:
            config.enabled_severities = [
                Severity(severity) for severity in data["enabled_severities"]
            ]

        # Parse check configurations
        if "checks" in data:
            for check_id, check_data in data["checks"].items():
                check_data["check_id"] = check_id
                config.check_configs[check_id] = CheckConfig.from_dict(check_data)

        return config


class CheckConfigurationManager:
    """
    Manager for loading and managing check configurations.

    Supports loading configurations from JSON and YAML files,
    merging multiple configuration sources, and providing
    runtime access to check settings.
    """

    def __init__(self):
        """Initialize the configuration manager."""
        self.logger = logging.getLogger("check_config")
        self._config = AssessmentConfig()

    def load_from_file(self, config_path: Union[str, Path]) -> None:
        """
        Load configuration from a file.

        Supports JSON and YAML formats. File format is determined
        by the file extension.

        Args:
            config_path: Path to the configuration file

        Raises:
            FileNotFoundError: If the configuration file doesn't exist
            ValueError: If the file format is not supported
            Exception: If the file cannot be parsed
        """
        config_path = Path(config_path)

        if not config_path.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_path}")

        self.logger.info(f"Loading configuration from {config_path}")

        try:
            with open(config_path, "r", encoding="utf-8") as f:
                if config_path.suffix.lower() in [".json"]:
                    data = json.load(f)
                elif config_path.suffix.lower() in [".yaml", ".yml"]:
                    data = yaml.safe_load(f)
                else:
                    raise ValueError(f"Unsupported configuration file format: {config_path.suffix}")

            # Merge with existing configuration
            new_config = AssessmentConfig.from_dict(data)
            self._merge_config(new_config)

            self.logger.info(
                f"Loaded configuration with {len(new_config.check_configs)} check configs"
            )

        except Exception as e:
            self.logger.error(f"Failed to load configuration from {config_path}: {e}")
            raise

    def load_from_dict(self, config_data: Dict[str, Any]) -> None:
        """
        Load configuration from a dictionary.

        Args:
            config_data: Configuration data as dictionary
        """
        self.logger.debug("Loading configuration from dictionary")
        new_config = AssessmentConfig.from_dict(config_data)
        self._merge_config(new_config)

    def _merge_config(self, new_config: AssessmentConfig) -> None:
        """
        Merge new configuration with existing configuration.

        Args:
            new_config: New configuration to merge
        """
        # Merge global settings
        self._config.global_settings.update(new_config.global_settings)

        # Update pillar and severity filters if specified
        if new_config.enabled_pillars:
            self._config.enabled_pillars = new_config.enabled_pillars
        if new_config.enabled_severities:
            self._config.enabled_severities = new_config.enabled_severities

        # Merge check configurations
        self._config.check_configs.update(new_config.check_configs)

    def get_config(self) -> AssessmentConfig:
        """Get the current assessment configuration."""
        return self._config

    def get_check_config(self, check_id: str) -> Optional[CheckConfig]:
        """Get configuration for a specific check."""
        return self._config.get_check_config(check_id)

    def is_check_enabled(self, check_id: str) -> bool:
        """Check if a specific check is enabled."""
        return self._config.is_check_enabled(check_id)

    def get_check_parameters(self, check_id: str) -> Dict[str, Any]:
        """Get parameters for a specific check."""
        return self._config.get_check_parameters(check_id)

    def get_check_severity_override(self, check_id: str) -> Optional[Severity]:
        """Get severity override for a specific check."""
        return self._config.get_check_severity_override(check_id)

    def get_enabled_pillars(self) -> List[Pillar]:
        """Get list of enabled pillars."""
        return self._config.enabled_pillars

    def get_enabled_severities(self) -> List[Severity]:
        """Get list of enabled severities."""
        return self._config.enabled_severities

    def get_global_setting(self, key: str, default: Any = None) -> Any:
        """Get a global configuration setting."""
        return self._config.global_settings.get(key, default)

    def set_global_setting(self, key: str, value: Any) -> None:
        """Set a global configuration setting."""
        self._config.global_settings[key] = value

    def add_check_config(self, check_config: CheckConfig) -> None:
        """Add or update configuration for a check."""
        self._config.add_check_config(check_config)
        self.logger.debug(f"Added configuration for check {check_config.check_id}")

    def save_to_file(self, config_path: Union[str, Path]) -> None:
        """
        Save current configuration to a file.

        Args:
            config_path: Path where to save the configuration file

        Raises:
            ValueError: If the file format is not supported
        """
        config_path = Path(config_path)

        self.logger.info(f"Saving configuration to {config_path}")

        try:
            config_dict = self._config.to_dict()

            with open(config_path, "w", encoding="utf-8") as f:
                if config_path.suffix.lower() in [".json"]:
                    json.dump(config_dict, f, indent=2, ensure_ascii=False)
                elif config_path.suffix.lower() in [".yaml", ".yml"]:
                    yaml.dump(config_dict, f, default_flow_style=False, allow_unicode=True)
                else:
                    raise ValueError(f"Unsupported configuration file format: {config_path.suffix}")

            self.logger.info(f"Configuration saved successfully to {config_path}")

        except Exception as e:
            self.logger.error(f"Failed to save configuration to {config_path}: {e}")
            raise

    def create_default_config(self) -> AssessmentConfig:
        """
        Create a default configuration with common settings.

        Returns:
            AssessmentConfig: Default configuration
        """
        config = AssessmentConfig()

        # Set default global settings
        config.global_settings = {
            "timeout": 300,
            "retry_count": 3,
            "parallel_execution": True,
            "max_workers": 4,
        }

        # Enable all pillars and severities by default
        config.enabled_pillars = list(Pillar)
        config.enabled_severities = list(Severity)

        return config

    def validate_config(self) -> List[str]:
        """
        Validate the current configuration.

        Returns:
            List[str]: List of validation errors (empty if valid)
        """
        errors = []

        # Validate global settings
        timeout = self._config.global_settings.get("timeout")
        if timeout is not None and (not isinstance(timeout, int) or timeout <= 0):
            errors.append("Global setting 'timeout' must be a positive integer")

        retry_count = self._config.global_settings.get("retry_count")
        if retry_count is not None and (not isinstance(retry_count, int) or retry_count < 0):
            errors.append("Global setting 'retry_count' must be a non-negative integer")

        max_workers = self._config.global_settings.get("max_workers")
        if max_workers is not None and (not isinstance(max_workers, int) or max_workers <= 0):
            errors.append("Global setting 'max_workers' must be a positive integer")

        # Validate check configurations
        for check_id, check_config in self._config.check_configs.items():
            if not check_config.check_id:
                errors.append(f"Check configuration missing check_id: {check_id}")

            if not isinstance(check_config.enabled, bool):
                errors.append(f"Check {check_id}: 'enabled' must be a boolean")

            if not isinstance(check_config.parameters, dict):
                errors.append(f"Check {check_id}: 'parameters' must be a dictionary")

        return errors

    def __str__(self) -> str:
        """String representation of the configuration manager."""
        return (
            f"CheckConfigurationManager("
            f"checks={len(self._config.check_configs)}, "
            f"pillars={len(self._config.enabled_pillars)}, "
            f"severities={len(self._config.enabled_severities)})"
        )
