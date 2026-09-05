"""
Tests for cost optimization checks (Tasks 8, 9, 10 / Requirements 13-16, 28-32, 40-41).
"""

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.cost_containment_checks import (
    IVRToAgentDataContinuityCheck,
    QueueWaitTimeCheck,
    RepeatContactFCRCheck,
    SelfServiceContainmentCheck,
    register_cost_containment_checks,
)
from amazon_connect_assessment.checks.cost_intelligence_checks import (
    PremiumFeaturesCostCheck,
    UsageMetricsCheck,
    register_cost_intelligence_checks,
)
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.cost.cost_estimator import (
    estimate_callback_savings,
    estimate_containment_savings,
    estimate_unused_numbers_cost,
)
from amazon_connect_assessment.models import CheckStatus, ContactFlow
from tests.conftest import build_action, build_contact_flow


def _wire(factory):
    factory.is_access_denied = AWSClientFactory.is_access_denied


def _instance_with_flow(instance, flow_json, name="TestFlow"):
    instance.contact_flows = [
        ContactFlow(
            id="f1",
            arn="arn:...:flow/f1",
            name=name,
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=flow_json,
        )
    ]
    return instance


# --- Task 8: cost intelligence checks ---


class TestUsageMetricsCheck:
    def test_no_datapoints_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {"Datapoints": []}
        finding = UsageMetricsCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL
        assert "unused" in finding.description.lower()

    def test_datapoints_present_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "Datapoints": [{"Maximum": 10, "Average": 5}]
        }
        finding = UsageMetricsCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


class TestPremiumFeaturesCostCheck:
    def test_enabled_feature_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "Attribute": {"Value": "true"}
        }
        finding = PremiumFeaturesCostCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL

    def test_no_features_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "Attribute": {"Value": "false"}
        }
        finding = PremiumFeaturesCostCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS

    def test_only_probes_contact_lens_not_wisdom_or_cases(
        self, make_check_context, mock_aws_client_factory
    ):
        """
        Regression test: WISDOM and CASES are not valid AttributeType
        enum members for connect:DescribeInstanceAttribute — only
        CONTACT_LENS is real. The check used to probe all three; the two
        invalid ones always raised, got swallowed by a bare `except
        Exception`, and permanently reported as "disabled" regardless of
        actual state. Assert the check only ever calls
        DescribeInstanceAttribute with AttributeType=CONTACT_LENS.
        """
        _wire(mock_aws_client_factory)
        seen_attribute_types = []

        def _side_effect(client, op_name, service, **kwargs):
            if op_name == "describe_instance_attribute":
                seen_attribute_types.append(kwargs.get("AttributeType"))
            return {"Attribute": {"Value": "false"}}

        mock_aws_client_factory.call_api_with_resilience.side_effect = _side_effect
        PremiumFeaturesCostCheck().execute(make_check_context())

        assert seen_attribute_types == ["CONTACT_LENS"]
        assert "WISDOM" not in seen_attribute_types
        assert "CASES" not in seen_attribute_types

    def test_access_denied_produces_skipped_not_false_pass(
        self, make_check_context, mock_aws_client_factory
    ):
        """
        Regression test: a bare `except Exception` mapped AccessDenied on
        DescribeInstanceAttribute to "feature disabled" and returned
        PASS — indistinguishable from a genuinely-disabled feature, and
        contradicting the module's own SKIPPED-on-AccessDenied
        degradation contract used by every other check.
        """
        from botocore.exceptions import ClientError

        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}},
            "DescribeInstanceAttribute",
        )
        finding = PremiumFeaturesCostCheck().execute(make_check_context())
        assert finding.status == CheckStatus.SKIPPED
        assert finding.status != CheckStatus.PASS


# --- Task 9: cost containment checks ---


class TestSelfServiceContainmentCheck:
    def test_direct_queue_no_automation_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow([build_action("a1", "TransferToQueue", {"QueueId": "q1"})])
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = SelfServiceContainmentCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_lex_before_queue_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action("a1", "ConnectToLexBot", {"BotName": "faq"}, next_action="a2"),
                build_action("a2", "TransferToQueue", {"QueueId": "q1"}),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = SelfServiceContainmentCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


class TestQueueWaitTimeCheck:
    def test_queue_without_callback_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow([build_action("a1", "TransferToQueue", {"QueueId": "q1"})])
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = QueueWaitTimeCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_queue_with_callback_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action("a1", "CreateCallback", {}, next_action="a2"),
                build_action("a2", "TransferToQueue", {"QueueId": "q1"}),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = QueueWaitTimeCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


class TestRepeatContactFCRCheck:
    def test_no_detection_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow([build_action("a1", "MessageParticipant", {"Text": "hello"})])
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = RepeatContactFCRCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_returning_caller_detection_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:crm-returning-caller-lookup"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = RepeatContactFCRCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


class TestIVRToAgentDataContinuityCheck:
    def test_inputs_not_persisted_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action("a1", "GetParticipantInput", {}, next_action="a2"),
                build_action(
                    "a2",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:fn"},
                    next_action="a3",
                ),
                build_action("a3", "ConnectToLexBot", {"BotName": "x"}, next_action="a4"),
                build_action("a4", "TransferToQueue", {"QueueId": "q1"}),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = IVRToAgentDataContinuityCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_data_persisted_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action("a1", "GetParticipantInput", {}, next_action="a2"),
                build_action(
                    "a2",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:fn"},
                    next_action="a3",
                ),
                build_action(
                    "a3",
                    "UpdateContactAttributes",
                    {"Attributes": {"Reason": "x", "AcctNum": "y"}},
                    next_action="a4",
                ),
                build_action("a4", "ConnectToLexBot", {"BotName": "x"}, next_action="a5"),
                build_action("a5", "TransferToQueue", {"QueueId": "q1"}),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = IVRToAgentDataContinuityCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


# --- Task 10: cost estimator ---


class TestCostEstimator:
    def test_unused_numbers_estimate(self):
        est = estimate_unused_numbers_cost(5, "US")
        assert est.monthly_estimate_usd == 9.0  # 5 * 0.06 * 30
        assert est.confidence == "approximate"
        assert "DID" in est.calculation_basis

    def test_containment_with_volume(self):
        est = estimate_containment_savings(10000, 0.0)  # 0% containment
        assert est.monthly_estimate_usd == 60000.0  # 10000 * 6.0
        assert "deflectable" in est.calculation_basis

    def test_containment_without_volume(self):
        est = estimate_containment_savings(0, 0.5)
        assert est.confidence == "unable_to_calculate"
        assert est.monthly_estimate_usd is None

    def test_callback_estimate(self):
        est = estimate_callback_savings(4.0, 1000)
        # 1000 * 4 * 0.018 = 72
        assert est.monthly_estimate_usd == 72.0

    def test_callback_missing_data(self):
        est = estimate_callback_savings(0, 0)
        assert est.confidence == "unable_to_calculate"


# --- Registration ---


def test_register_cost_intelligence_checks():
    registry = CheckRegistry()
    register_cost_intelligence_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    assert {
        "cost-usage-metrics-001",
        "cost-unused-numbers-001",
        "cost-premium-features-001",
        "cost-hours-mismatch-001",
    } <= ids


def test_register_cost_containment_checks():
    registry = CheckRegistry()
    register_cost_containment_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    assert {
        "cost-containment-001",
        "cost-wait-time-001",
        "cost-occupancy-001",
        "cost-fcr-001",
        "cost-acw-001",
        "cost-data-continuity-001",
    } <= ids
