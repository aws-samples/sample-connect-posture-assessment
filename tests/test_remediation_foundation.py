"""
Tests for the structured remediation foundation (Task 3.3) and the shared
access-denied / SKIPPED helpers (Task 3.2).

Covers Requirement 42 acceptance criteria at the framework level; per-check
specificity is verified in each check's own tests and holistically in 18.3.
"""

import csv
import json

from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.base import BaseCheck, CheckContext
from amazon_connect_assessment.models import (
    CheckStatus,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from amazon_connect_assessment.network_resilience import NetworkResilienceError
from amazon_connect_assessment.report_generator import ReportGenerator


class _RemediatingCheck(BaseCheck):
    """A check that emits a structured, evidence-specific remediation."""

    def __init__(self):
        super().__init__(
            check_id="demo-rem-001",
            name="Demo Remediation Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description="demo",
        )

    def execute(self, context: CheckContext):
        flow_id = "flow-XYZ"
        remediation = Remediation(
            summary=f"Fix flow {flow_id}.",
            steps=[
                RemediationStep(
                    order=1,
                    instruction=f"Open action a1 in flow {flow_id} and replace the literal.",
                    console_path="Connect console -> Routing -> Flows",
                    command="aws ssm put-parameter --name /connect/x --value y --type String",
                ),
            ],
            target_resources=[flow_id, "a1"],
            references=[RemediationReference(title="Docs", url="https://example.com")],
            applies_if="the destination changes across environments.",
            placeholders=["<key>"],
        )
        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=flow_id,
            resource_type="ContactFlow",
            description="hardcoded value found",
            evidence={"flow_id": flow_id, "action_id": "a1"},
            structured_remediation=remediation,
        )


class TestStructuredRemediation:
    def test_finding_carries_structured_remediation(self, make_check_context):
        finding = _RemediatingCheck().execute(make_check_context())
        assert finding.structured_remediation is not None
        assert finding.structured_remediation.target_resources == ["flow-XYZ", "a1"]
        assert finding.structured_remediation.applies_if

    def test_flat_remediation_derived_from_structured(self, make_check_context):
        finding = _RemediatingCheck().execute(make_check_context())
        flat = finding.remediation
        # Summary, numbered step, command, targets, applies-if, reference all present.
        assert "Fix flow flow-XYZ." in flat
        assert "1. Open action a1" in flat
        assert "$ aws ssm put-parameter" in flat
        assert "Targets: flow-XYZ, a1" in flat
        assert "Applies if relevant:" in flat
        assert "https://example.com" in flat

    def test_target_resources_reference_evidence(self, make_check_context):
        """Req 42.2/42.4 — targets must reference ids present in evidence."""
        finding = _RemediatingCheck().execute(make_check_context())
        targets = set(finding.structured_remediation.target_resources)
        evidence_ids = set(str(v) for v in finding.evidence.values())
        assert targets & evidence_ids  # non-empty intersection


class TestSkippedHelper:
    def test_skipped_for_access_denied(self, make_check_context):
        check = _RemediatingCheck()
        finding = check.skipped_for_access_denied(make_check_context(), "cloudtrail:DescribeTrails")
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["required_permission"] == "cloudtrail:DescribeTrails"


class TestAccessDeniedDetector:
    def _client_error(self, code):
        return ClientError({"Error": {"Code": code, "Message": "x"}}, "Op")

    def test_detects_plain_access_denied(self):
        assert AWSClientFactory.is_access_denied(self._client_error("AccessDenied"))
        assert AWSClientFactory.is_access_denied(self._client_error("AccessDeniedException"))

    def test_detects_wrapped_access_denied(self):
        wrapped = NetworkResilienceError(
            "failed", original_error=self._client_error("AccessDenied")
        )
        assert AWSClientFactory.is_access_denied(wrapped) is True

    def test_non_access_errors_are_false(self):
        assert AWSClientFactory.is_access_denied(self._client_error("Throttling")) is False
        assert AWSClientFactory.is_access_denied(ValueError("nope")) is False


class TestExportIncludesStructuredRemediation:
    def _result_with_structured(self, sample_assessment_result, make_check_context):
        finding = _RemediatingCheck().execute(make_check_context())
        sample_assessment_result.findings = [finding]
        return sample_assessment_result

    def test_json_export_includes_structured_remediation(
        self, sample_assessment_result, make_check_context, tmp_path
    ):
        result = self._result_with_structured(sample_assessment_result, make_check_context)
        path = ReportGenerator().generate_json_report(result, str(tmp_path))
        data = json.load(open(path, encoding="utf-8"))
        sr = data["findings"][0]["structured_remediation"]
        assert sr is not None
        assert sr["summary"].startswith("Fix flow")
        assert sr["target_resources"] == ["flow-XYZ", "a1"]
        assert sr["steps"][0]["command"].startswith("aws ssm")

    def test_csv_export_includes_remediation_targets(
        self, sample_assessment_result, make_check_context, tmp_path
    ):
        result = self._result_with_structured(sample_assessment_result, make_check_context)
        path = ReportGenerator().generate_csv_report(result, str(tmp_path))
        rows = list(csv.DictReader(open(path, newline="", encoding="utf-8")))
        assert rows[0]["Remediation Targets"] == "flow-XYZ, a1"
