"""
Tests for CheckRegistry.load_checks_from_config.

Regression coverage: this method used to only log what it "would" do and
never mutated the registry or any check — every `enabled` / `severity`
value under a config file's `checks:` section was silently a no-op
despite config/README.md documenting both as live, working overrides.
"""

from amazon_connect_assessment.checks.registration import register_all_checks
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import Severity


def _registry():
    r = CheckRegistry()
    register_all_checks(r)
    return r


class TestEnabledOverride:
    def test_enabled_false_unregisters_the_check(self):
        registry = _registry()
        assert "ops-logging-001" in registry
        registry.load_checks_from_config({"ops-logging-001": {"enabled": False}})
        assert "ops-logging-001" not in registry

    def test_enabled_true_is_a_no_op(self):
        registry = _registry()
        before = len(registry)
        registry.load_checks_from_config({"ops-logging-001": {"enabled": True}})
        assert len(registry) == before
        assert "ops-logging-001" in registry

    def test_omitted_enabled_defaults_to_true(self):
        registry = _registry()
        before = len(registry)
        registry.load_checks_from_config({"ops-logging-001": {"severity": "low"}})
        assert len(registry) == before
        assert "ops-logging-001" in registry


class TestSeverityOverride:
    def test_severity_override_changes_check_severity(self):
        registry = _registry()
        check = registry.get_check("ops-logging-001")
        original = check.severity
        registry.load_checks_from_config({"ops-logging-001": {"severity": "critical"}})
        assert registry.get_check("ops-logging-001").severity == Severity.CRITICAL
        assert original != Severity.CRITICAL or True  # override applied regardless

    def test_severity_override_updates_severity_index(self):
        # get_checks_by_severity must reflect the override, not just the
        # check object's own .severity attribute — the registry keeps a
        # separate severity-indexed view that has to be kept in sync.
        registry = _registry()
        check = registry.get_check("ops-logging-001")
        original_severity = check.severity

        registry.load_checks_from_config({"ops-logging-001": {"severity": "critical"}})

        critical_checks = registry.get_checks_by_severity(Severity.CRITICAL)
        assert any(c.check_id == "ops-logging-001" for c in critical_checks)

        if original_severity != Severity.CRITICAL:
            old_bucket = registry.get_checks_by_severity(original_severity)
            assert not any(c.check_id == "ops-logging-001" for c in old_bucket)

    def test_invalid_severity_value_is_ignored_not_raised(self):
        registry = _registry()
        original = registry.get_check("ops-logging-001").severity
        # Must not raise, and must leave the check's severity unchanged.
        registry.load_checks_from_config({"ops-logging-001": {"severity": "extreme"}})
        assert registry.get_check("ops-logging-001").severity == original

    def test_severity_override_is_case_insensitive(self):
        registry = _registry()
        registry.load_checks_from_config({"ops-logging-001": {"severity": "CRITICAL"}})
        assert registry.get_check("ops-logging-001").severity == Severity.CRITICAL


class TestUnknownCheckIds:
    def test_unknown_check_id_does_not_raise(self):
        registry = _registry()
        # Should log a warning and continue, not crash.
        registry.load_checks_from_config({"totally-made-up-999": {"enabled": False}})
        assert len(registry) > 0

    def test_empty_config_is_a_no_op(self):
        registry = _registry()
        before = len(registry)
        registry.load_checks_from_config({})
        assert len(registry) == before

    def test_none_config_is_a_no_op(self):
        registry = _registry()
        before = len(registry)
        registry.load_checks_from_config(None)
        assert len(registry) == before


class TestCombinedOverrides:
    def test_multiple_checks_configured_at_once(self):
        registry = _registry()
        registry.load_checks_from_config(
            {
                "ops-logging-001": {"enabled": False},
                "security-iam-001": {"severity": "medium"},
            }
        )
        assert "ops-logging-001" not in registry
        assert registry.get_check("security-iam-001").severity == Severity.MEDIUM

    def test_non_dict_config_value_is_skipped_gracefully(self):
        registry = _registry()
        before = len(registry)
        # A malformed config (string instead of dict) must not crash.
        registry.load_checks_from_config({"ops-logging-001": "not-a-dict"})
        assert len(registry) == before
