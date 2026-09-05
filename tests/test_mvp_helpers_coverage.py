"""
Coverage tests for mvp_checks.py helper functions (52% → target ~85%).

Tests get_check_summary, validate_mvp_checks, get_critical_checks,
get_high_priority_checks, register_priority_checks.
"""

from amazon_connect_assessment.checks.mvp_checks import (
    get_check_summary,
    get_critical_checks,
    get_high_priority_checks,
    get_mvp_checks,
    register_mvp_checks,
    register_priority_checks,
    validate_mvp_checks,
)
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import Severity


class TestMVPHelpers:
    def test_get_mvp_checks_returns_expected_count(self):
        # Five of the original MVP checks were removed across three
        # user-feedback passes:
        #   * MultiAZ, DR, FailoverMechanism — resilience rubber-stamps
        #     (flagged normal deployment shapes as deficiencies).
        #   * NetworkSecurityCheck — HIGH-severity FAIL for CONNECT_MANAGED
        #     identity and for bidirectional calling. Neither is a defect;
        #     the check inspected no actual network configuration.
        #   * EncryptionConfigurationCheck — HIGH-severity FAIL for every
        #     Lambda/S3 integration with the string "requires encryption
        #     validation"; did not actually check any encryption state.
        # Assert the current expected count so accidental additions/removals
        # surface loudly, not silently.
        assert len(get_mvp_checks()) == 5

    def test_get_critical_checks(self):
        crit = get_critical_checks()
        assert all(c.severity == Severity.CRITICAL for c in crit)
        assert len(crit) >= 1

    def test_get_high_priority_checks(self):
        high = get_high_priority_checks()
        assert all(c.severity in (Severity.CRITICAL, Severity.HIGH) for c in high)

    def test_register_priority_checks_without_medium(self):
        reg = CheckRegistry()
        register_priority_checks(reg, include_medium=False)
        for c in reg.get_all_checks():
            assert c.severity in (Severity.CRITICAL, Severity.HIGH)

    def test_register_priority_checks_with_medium(self):
        reg = CheckRegistry()
        register_priority_checks(reg, include_medium=True)
        severities = {c.severity for c in reg.get_all_checks()}
        assert Severity.MEDIUM in severities

    def test_get_check_summary_structure(self):
        summary = get_check_summary()
        assert summary["total_checks"] == 5
        assert "by_pillar" in summary
        assert "by_severity" in summary
        assert "check_list" in summary
        assert len(summary["check_list"]) == 5
        for item in summary["check_list"]:
            assert "check_id" in item
            assert "name" in item
            assert "pillar" in item
            assert "severity" in item

    def test_validate_mvp_checks_no_errors(self):
        errors = validate_mvp_checks()
        assert errors == []

    def test_register_mvp_checks_idempotent_call_raises(self):
        reg = CheckRegistry()
        register_mvp_checks(reg)
        # Second call should raise ValueError (duplicate IDs).
        import pytest

        with pytest.raises(ValueError):
            register_mvp_checks(reg)
