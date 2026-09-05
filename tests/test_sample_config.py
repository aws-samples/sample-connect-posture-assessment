"""Regression tests for the shipped configuration examples."""

import json
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
SUPPORTED_CHECK_KEYS = {"enabled", "severity"}
FUTURE_CHECK_IDS = {
    "security-data-001",
    "cost-unused-001",
    "cost-oversized-001",
    "cost-inefficient-001",
    "experimental-check-001",
}


def _assert_sample_config_shape(config: dict) -> None:
    checks = config["checks"]
    assert checks
    assert all(set(check_config) <= SUPPORTED_CHECK_KEYS for check_config in checks.values())

    future_overrides = config["future_only"]["check_overrides"]
    assert set(future_overrides) == FUTURE_CHECK_IDS
    assert set(future_overrides["experimental-check-001"]) == {"enabled"}
    assert all(
        set(future_overrides[check_id]) == {"parameters", "remediation_template"}
        for check_id in FUTURE_CHECK_IDS - {"experimental-check-001"}
    )


def test_yaml_sample_keeps_unsupported_overrides_future_only() -> None:
    with (ROOT / "config" / "assessment_config.yaml").open(encoding="utf-8") as file:
        config = yaml.safe_load(file)

    _assert_sample_config_shape(config)


def test_json_sample_keeps_unsupported_overrides_future_only() -> None:
    with (ROOT / "config" / "assessment_config.json").open(encoding="utf-8") as file:
        config = json.load(file)

    _assert_sample_config_shape(config)
