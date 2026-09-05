"""
Phase 0 audit regression tests.

These tests lock in the correctness fixes and behaviors validated during the
existing-code audit (tasks 1.2-1.4) so future feature work cannot silently
regress them:

- 1.2  AWSClientFactory permission probes + resilient service-name resolution
- 1.3  Serial vs. parallel engine finding parity + malformed-ARN tolerance
- 1.4  JSON/CSV export round-trip fidelity for findings
"""

import csv
import json

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks import BaseCheck, CheckContext, CheckRegistry
from amazon_connect_assessment.engine import AssessmentEngine
from amazon_connect_assessment.models import (
    CheckStatus,
    ConnectInstance,
    Pillar,
    Severity,
)
from amazon_connect_assessment.parallel_engine import ParallelAssessmentEngine
from amazon_connect_assessment.report_generator import ReportGenerator

# ---------------------------------------------------------------------------
# 1.3 — helper checks/analyzers for engine parity
# ---------------------------------------------------------------------------


class _DeterministicCheck(BaseCheck):
    """A check that returns a fixed status per check_id for parity testing."""

    def __init__(self, check_id, status, pillar=Pillar.SECURITY, severity=Severity.MEDIUM):
        super().__init__(
            check_id=check_id,
            name=f"Check {check_id}",
            pillar=pillar,
            severity=severity,
            description="parity test check",
            remediation_template="do the thing",
        )
        self._status = status

    def execute(self, context: CheckContext):
        return self.create_finding(
            status=self._status,
            resource_id=context.instance.instance_id,
            resource_type="ConnectInstance",
            description=f"{self.check_id} on {context.instance.instance_id}",
        )


def _make_instances():
    return [
        ConnectInstance(
            instance_id=f"inst-{i}",
            instance_arn=f"arn:aws:connect:us-east-1:123456789012:instance/inst-{i}",
            identity_management_type="CONNECT_MANAGED",
            inbound_calls_enabled=True,
            outbound_calls_enabled=True,
            status="ACTIVE",
        )
        for i in range(3)
    ]


def _registry_with_checks():
    reg = CheckRegistry()
    reg.register_check(_DeterministicCheck("chk-pass", CheckStatus.PASS))
    reg.register_check(
        _DeterministicCheck("chk-fail", CheckStatus.FAIL, Pillar.RESILIENCE, Severity.HIGH)
    )
    reg.register_check(
        _DeterministicCheck("chk-skip", CheckStatus.SKIPPED, Pillar.COST_OPTIMIZATION, Severity.LOW)
    )
    return reg


def _finding_key(f):
    return (f.check_id, f.resource_id, f.status.value, f.severity.value, f.pillar.value)


class TestEngineParity:
    """1.3 — serial and parallel engines must produce equivalent findings."""

    def test_serial_vs_parallel_finding_parity(self, mock_aws_client_factory, sample_config):
        instances = _make_instances()

        serial = AssessmentEngine(mock_aws_client_factory, sample_config)
        serial.check_registry = _registry_with_checks()
        serial.enable_checkpoints(False)

        parallel = ParallelAssessmentEngine(mock_aws_client_factory, sample_config)
        parallel.check_registry = _registry_with_checks()
        parallel.enable_checkpoints(False)

        serial_findings = []
        for inst in instances:
            serial_findings.extend(serial.execute_checks(inst))
        parallel_findings = parallel._execute_checks_parallel(instances)

        # Order may differ (parallel uses as_completed), so compare as multisets.
        assert sorted(map(_finding_key, serial_findings)) == sorted(
            map(_finding_key, parallel_findings)
        )
        # 3 instances x 3 checks
        assert len(parallel_findings) == 9

    def test_parallel_execution_enriches_mvp_remediation(
        self, mock_aws_client_factory, sample_config
    ):
        registry = CheckRegistry()
        registry.register_check(_DeterministicCheck("security-iam-001", CheckStatus.FAIL))
        instance = _make_instances()[0]

        serial = AssessmentEngine(mock_aws_client_factory, sample_config)
        serial.check_registry = registry
        serial.enable_checkpoints(False)
        serial_finding = serial.execute_checks(instance)[0]

        parallel = ParallelAssessmentEngine(mock_aws_client_factory, sample_config)
        parallel.check_registry = registry
        parallel.enable_checkpoints(False)
        parallel_finding = parallel._execute_checks_parallel([instance])[0]

        assert serial_finding.structured_remediation is not None
        assert parallel_finding.structured_remediation is not None
        assert (
            parallel_finding.structured_remediation.summary
            == serial_finding.structured_remediation.summary
        )


class TestMalformedArnTolerance:
    """1.3 — ARN extraction must not crash on malformed ARNs."""

    def test_parallel_account_region_extraction_handles_bad_arn(
        self, mock_aws_client_factory, sample_config
    ):
        engine = ParallelAssessmentEngine(mock_aws_client_factory, sample_config)
        bad = [
            ConnectInstance(
                instance_id="x",
                instance_arn="not-an-arn",
                identity_management_type="CONNECT_MANAGED",
                inbound_calls_enabled=False,
                outbound_calls_enabled=False,
                status="ACTIVE",
            )
        ]
        assert engine._extract_account_from_instances(bad) == "unknown"
        assert engine._extract_region_from_instances(bad) == "unknown"

    def test_parallel_account_region_extraction_parses_valid_arn(
        self, mock_aws_client_factory, sample_config
    ):
        engine = ParallelAssessmentEngine(mock_aws_client_factory, sample_config)
        good = _make_instances()
        assert engine._extract_account_from_instances(good) == "123456789012"
        assert engine._extract_region_from_instances(good) == "us-east-1"


class TestExportRoundTrip:
    """1.4 — JSON/CSV exports must preserve all finding fields."""

    def test_json_export_round_trip(self, sample_assessment_result, tmp_path):
        gen = ReportGenerator()
        path = gen.generate_json_report(sample_assessment_result, str(tmp_path))
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        assert data["assessment_id"] == sample_assessment_result.assessment_id
        assert data["account_id"] == sample_assessment_result.account_id
        assert len(data["findings"]) == len(sample_assessment_result.findings)

        src = sample_assessment_result.findings[0]
        out = data["findings"][0]
        assert out["check_id"] == src.check_id
        assert out["pillar"] == src.pillar.value
        assert out["severity"] == src.severity.value
        assert out["status"] == src.status.value
        assert out["evidence"] == src.evidence

    def test_csv_export_round_trip(self, sample_assessment_result, tmp_path):
        gen = ReportGenerator()
        path = gen.generate_csv_report(sample_assessment_result, str(tmp_path))
        with open(path, newline="", encoding="utf-8") as f:
            rows = list(csv.DictReader(f))

        assert len(rows) == len(sample_assessment_result.findings)
        src = sample_assessment_result.findings[0]
        assert rows[0]["Check ID"] == src.check_id
        assert rows[0]["Severity"] == src.severity.value
        assert rows[0]["Status"] == src.status.value


class TestPermissionProbeBehavior:
    """1.2 — permission probes distinguish AccessDenied from 'no resources'."""

    def test_list_instances_no_resources_is_not_a_permission_failure(self):
        factory = AWSClientFactory(region="us-east-1")
        # Empty result (no instances) must be treated as permission OK.
        factory.list_connect_instances_resilient = lambda **kw: {"InstanceSummaryList": []}
        assert factory._test_connect_list_instances() is True

    def test_list_instances_access_denied_is_a_permission_failure(self):
        from botocore.exceptions import ClientError

        factory = AWSClientFactory(region="us-east-1")

        def _denied(**kw):
            raise ClientError({"Error": {"Code": "AccessDenied", "Message": "no"}}, "ListInstances")

        factory.list_connect_instances_resilient = _denied
        assert factory._test_connect_list_instances() is False

    def test_resilient_service_name_resolution_without_service_model(self):
        """The hardened fallback must not raise when _service_model is absent."""
        factory = AWSClientFactory(region="us-east-1")

        class _FakeClient:
            def ping(self, **kwargs):
                return {"ok": True}

        # No _service_model attribute; explicit service_name omitted.
        result = factory.call_api_with_resilience(_FakeClient(), "ping")
        assert result == {"ok": True}
