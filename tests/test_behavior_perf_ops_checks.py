"""
Tests for contact-flow behavior, performance, and ops excellence checks
(Tasks 11, 12, 13 / Requirements 3-6, 17-18, 33).
"""

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.contact_flow_behavior_checks import (
    AuthenticationPatternCheck,
    ErrorHandlingCompletenessCheck,
    LoopDetectionCheck,
    register_contact_flow_behavior_checks,
)
from amazon_connect_assessment.checks.operational_excellence_checks import (
    ContactFlowLoggingCheck,
    register_operational_excellence_checks,
)
from amazon_connect_assessment.checks.performance_efficiency_checks import (
    FlowComplexityCheck,
    LambdaInvocationCountCheck,
    SequentialLambdaCheck,
    register_performance_efficiency_checks,
)
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import CheckStatus, ContactFlow
from tests.conftest import build_action, build_contact_flow


def _wire(factory):
    factory.is_access_denied = AWSClientFactory.is_access_denied


def _inst(instance, flow_json, name="TestFlow"):
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


# --- Task 11: behavior checks ---


class TestAuthenticationPatternCheck:
    def test_queue_without_auth_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow([build_action("a1", "TransferToQueue", {"QueueId": "q1"})])
        inst = _inst(sample_connect_instance, flow)
        finding = AuthenticationPatternCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_auth_before_queue_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:verify-caller"},
                    next_action="a2",
                ),
                build_action("a2", "TransferToQueue", {"QueueId": "q1"}),
            ]
        )
        inst = _inst(sample_connect_instance, flow)
        finding = AuthenticationPatternCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


class TestErrorHandlingCheck:
    def test_all_missing_errors_fails(self, make_check_context, sample_connect_instance):
        # 5 error-capable actions, none with error transitions -> 100% > 20%.
        actions = [
            build_action(
                f"a{i}",
                "InvokeLambdaFunction",
                {"FunctionArn": f"arn:...:fn{i}"},
                next_action=f"a{i + 1}" if i < 4 else None,
            )
            for i in range(5)
        ]
        flow = build_contact_flow(actions)
        inst = _inst(sample_connect_instance, flow)
        finding = ErrorHandlingCompletenessCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_errors_present_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:fn"},
                    next_action="a2",
                    errors=[{"NextAction": "a3", "ErrorType": "NoMatchingError"}],
                ),
                build_action("a2", "DisconnectParticipant"),
                build_action("a3", "MessageParticipant", {"Text": "sorry"}),
            ]
        )
        inst = _inst(sample_connect_instance, flow)
        finding = ErrorHandlingCompletenessCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


class TestLoopDetectionCheck:
    def test_unbounded_loop_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action("a1", "MessageParticipant", {"Text": "x"}, next_action="a2"),
                build_action("a2", "MessageParticipant", {"Text": "y"}, next_action="a1"),
            ]
        )
        inst = _inst(sample_connect_instance, flow)
        finding = LoopDetectionCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_linear_flow_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action("a1", "MessageParticipant", {"Text": "x"}, next_action="a2"),
                build_action("a2", "DisconnectParticipant"),
            ]
        )
        inst = _inst(sample_connect_instance, flow)
        finding = LoopDetectionCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


# --- Task 12: performance checks ---


class TestLambdaInvocationCountCheck:
    def test_lambda_usage_many_linear_blocks_remains_observational_pass(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        actions = [
            build_action(
                f"a{i}",
                "InvokeLambdaFunction",
                {"FunctionArn": f"arn:aws:lambda:us-east-1:123:function:fn{i}"},
                next_action=f"a{i + 1}" if i < 6 else None,
            )
            for i in range(7)
        ]
        flow = build_contact_flow(actions)
        inst = _inst(sample_connect_instance, flow)

        # Act
        finding = LambdaInvocationCountCheck().execute(make_check_context(instance=inst))

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.check_name == "Lambda Usage Structure Review"
        assert finding.evidence["numeric_compliance_threshold_applied"] is False
        usage = finding.evidence["flow_lambda_usage"][0]
        assert usage["total_lambda_blocks"] == 7
        assert usage["reachable_lambda_blocks"] == 7
        assert usage["max_lambda_blocks_on_simple_route"] == 7
        assert "does not fail a flow from a locally selected count" in finding.description
        assert "PASS means the inventory completed" in finding.description

    def test_lambda_usage_mutually_exclusive_branches_reports_one_per_route(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "start",
                    "CheckContactAttributes",
                    conditions=[
                        {"NextAction": "lambda-a", "Condition": {"Equals": "a"}},
                        {"NextAction": "lambda-b", "Condition": {"Equals": "b"}},
                    ],
                ),
                build_action(
                    "lambda-a",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:fn-a"},
                    next_action="end",
                ),
                build_action(
                    "lambda-b",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:fn-b"},
                    next_action="end",
                ),
                build_action("end", "DisconnectParticipant"),
            ],
            start_action="start",
        )
        inst = _inst(sample_connect_instance, flow)

        # Act
        finding = LambdaInvocationCountCheck().execute(make_check_context(instance=inst))

        # Assert
        usage = finding.evidence["flow_lambda_usage"][0]
        assert usage["total_lambda_blocks"] == 2
        assert usage["reachable_lambda_blocks"] == 2
        assert usage["max_lambda_blocks_on_simple_route"] == 1
        assert usage["route_analysis_capped"] is False

    def test_lambda_usage_normalizes_arn_fields_and_marks_unreachable_actions(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        reachable_arn = "arn:aws:lambda:us-east-1:123:function:reachable-fn"
        orphan_arn = "arn:aws:lambda:us-east-1:123:function:orphan-fn:PROD"
        flow = build_contact_flow(
            [
                build_action(
                    "reachable",
                    "InvokeLambdaFunction",
                    {
                        "FunctionArn": reachable_arn,
                        "InvocationType": "SYNCHRONOUS",
                        "InvocationTimeLimitSeconds": 8,
                    },
                    next_action="end",
                    errors=[{"NextAction": "error", "ErrorType": "NoMatchingError"}],
                ),
                build_action("end", "DisconnectParticipant"),
                build_action("error", "DisconnectParticipant"),
                build_action(
                    "orphan",
                    "InvokeLambdaFunction",
                    {
                        "LambdaFunctionARN": {"Value": orphan_arn},
                        "InvocationType": "ASYNCHRONOUS",
                        "InvocationTimeLimitSeconds": 60,
                    },
                ),
            ],
            start_action="reachable",
        )
        inst = _inst(sample_connect_instance, flow)

        # Act
        finding = LambdaInvocationCountCheck().execute(make_check_context(instance=inst))

        # Assert
        usage = finding.evidence["flow_lambda_usage"][0]
        assert usage["total_lambda_blocks"] == 2
        assert usage["reachable_lambda_blocks"] == 1
        assert usage["unreachable_lambda_blocks"] == 1
        details = {
            row["lambda_action_id"]: row for row in finding.evidence["lambda_action_details"]
        }
        assert details["reachable"]["lambda_function_arn"] == reachable_arn
        assert details["reachable"]["lambda_function_name"] == "reachable-fn"
        assert details["reachable"]["lambda_invocation_type"] == "SYNCHRONOUS"
        assert details["reachable"]["lambda_timeout_seconds"] == "8"
        assert details["reachable"]["lambda_has_error_branch"] is True
        assert details["reachable"]["reachable_from_entry"] is True
        assert "error (NoMatchingError) -> error" in details["reachable"]["outgoing_transitions"]
        assert details["orphan"]["lambda_function_arn"] == orphan_arn
        assert details["orphan"]["lambda_function_name"] == "orphan-fn:PROD"
        assert details["orphan"]["lambda_invocation_type"] == "ASYNCHRONOUS"
        assert details["orphan"]["lambda_timeout_seconds"] == "60"
        assert details["orphan"]["reachable_from_entry"] is False


class TestSequentialLambdaCheck:
    def test_sequential_lambda_direct_pair_returns_detailed_aws_rationale(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        first_arn = "arn:aws:lambda:us-east-1:123456789012:function:first-lookup"
        second_arn = "arn:aws:lambda:us-east-1:123456789012:function:second-lookup:PROD"
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {
                        "LambdaFunctionARN": {"Value": first_arn},
                        "InvocationType": "SYNCHRONOUS",
                        "InvocationTimeLimitSeconds": 8,
                        "ResponseValidation": {"ResponseType": "JSON"},
                    },
                    next_action="a2",
                    errors=[{"NextAction": "a3", "ErrorType": "NoMatchingError"}],
                ),
                build_action(
                    "a2",
                    "InvokeLambdaFunction",
                    {
                        "FunctionArn": second_arn,
                        "InvocationType": "ASYNCHRONOUS",
                        "InvocationTimeLimitSeconds": 60,
                    },
                    errors=[{"NextAction": "a3", "ErrorType": "NoMatchingError"}],
                ),
                build_action("a3", "DisconnectParticipant"),
            ]
        )
        inst = _inst(sample_connect_instance, flow)

        # Act
        finding = SequentialLambdaCheck().execute(make_check_context(instance=inst))

        # Assert
        assert finding.status == CheckStatus.FAIL
        detail = finding.evidence["sequence_details"][0]
        assert detail["flow_id"] == "f1"
        assert detail["first_action_id"] == "a1"
        assert detail["first_function_arn"] == first_arn
        assert detail["first_function_name"] == "first-lookup"
        assert detail["first_invocation_type"] == "SYNCHRONOUS"
        assert detail["first_timeout_seconds"] == "8"
        assert detail["first_response_type"] == "JSON"
        assert detail["first_has_error_branch"] is True
        assert detail["second_action_id"] == "a2"
        assert detail["second_function_arn"] == second_arn
        assert detail["second_function_name"] == "second-lookup:PROD"
        assert detail["second_timeout_seconds"] == "60"
        assert detail["intermediate_actions"] == "none (direct transition)"
        assert detail["transition_route"] == "default"
        assert "20 seconds" in finding.description
        assert "callers hear silence" in finding.description
        assert "three times" in finding.description
        assert "Error branch" in finding.description
        assert "Do not reorder or parallelize dependent calls" in finding.remediation

    def test_sequential_lambda_processing_block_between_calls_still_fails(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:first"},
                    next_action="middle",
                ),
                build_action(
                    "middle",
                    "CheckContactAttributes",
                    {"Attribute": "customerType"},
                    next_action="a2",
                ),
                build_action("a2", "InvokeLambdaFunction", {"FunctionArn": "arn:...:second"}),
            ]
        )
        inst = _inst(sample_connect_instance, flow)

        # Act
        finding = SequentialLambdaCheck().execute(make_check_context(instance=inst))

        # Assert
        assert finding.status == CheckStatus.FAIL
        detail = finding.evidence["sequence_details"][0]
        assert detail["path_action_ids"] == ["a1", "middle", "a2"]
        assert detail["intermediate_actions"] == "middle (CheckContactAttributes)"
        assert detail["transition_route"] == "default -> default"

    def test_sequential_lambda_prompt_between_calls_stops_sequence(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:first"},
                    next_action="prompt",
                ),
                build_action(
                    "prompt", "MessageParticipant", {"Text": "Still working"}, next_action="a2"
                ),
                build_action("a2", "InvokeLambdaFunction", {"FunctionArn": "arn:...:second"}),
            ]
        )
        inst = _inst(sample_connect_instance, flow)

        # Act
        finding = SequentialLambdaCheck().execute(make_check_context(instance=inst))

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["sequential_pairs"] == 0

    def test_sequential_lambda_unreachable_pair_is_not_reported(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action("start", "MessageParticipant", next_action="end"),
                build_action("end", "DisconnectParticipant"),
                build_action(
                    "orphan-1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:first"},
                    next_action="orphan-2",
                ),
                build_action("orphan-2", "InvokeLambdaFunction", {"FunctionArn": "arn:...:second"}),
            ],
            start_action="start",
        )
        inst = _inst(sample_connect_instance, flow)

        # Act
        finding = SequentialLambdaCheck().execute(make_check_context(instance=inst))

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["sequential_pairs"] == 0

    def test_sequential_lambda_error_route_reports_transition_type(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:first"},
                    next_action="prompt",
                    errors=[{"NextAction": "a2", "ErrorType": "NoMatchingError"}],
                ),
                build_action("prompt", "MessageParticipant", {"Text": "Done"}),
                build_action("a2", "InvokeLambdaFunction", {"FunctionArn": "arn:...:fallback"}),
            ]
        )
        inst = _inst(sample_connect_instance, flow)

        # Act
        finding = SequentialLambdaCheck().execute(make_check_context(instance=inst))

        # Assert
        assert finding.status == CheckStatus.FAIL
        detail = finding.evidence["sequence_details"][0]
        assert detail["transition_route"] == "error (NoMatchingError)"
        assert detail["route_contains_error_transition"] is True


class TestFlowComplexityCheck:
    def test_flow_structure_long_linear_flow_remains_observational_pass(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        actions = [
            build_action(
                f"a{i}",
                "MessageParticipant",
                {"Text": "x"},
                next_action=f"a{i + 1}" if i < 55 else None,
            )
            for i in range(56)
        ]
        flow = build_contact_flow(actions)
        inst = _inst(sample_connect_instance, flow)

        # Act
        finding = FlowComplexityCheck().execute(make_check_context(instance=inst))

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.check_name == "Contact Flow Structure Review"
        assert finding.evidence["numeric_compliance_threshold_applied"] is False
        metrics = finding.evidence["flow_structural_metrics"][0]
        assert metrics["total_actions"] == 56
        assert metrics["reachable_actions"] == 56
        assert metrics["longest_route_transitions"] == 55
        assert "branching_depth" not in metrics
        assert "overall_score" not in metrics
        assert "does not classify a flow as compliant or noncompliant" in finding.description
        assert "PASS means the structural inventory completed" in finding.description

    def test_flow_structure_metrics_include_cycles_paths_integrations_and_modules(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action("a1", "InvokeFlowModule", next_action="a2"),
                build_action(
                    "a2",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:lookup"},
                    next_action="a1",
                    conditions=[{"NextAction": "a3", "Condition": {"Equals": "done"}}],
                ),
                build_action("a3", "DisconnectParticipant"),
            ]
        )
        inst = _inst(sample_connect_instance, flow)

        # Act
        finding = FlowComplexityCheck().execute(make_check_context(instance=inst))

        # Assert
        metrics = finding.evidence["flow_structural_metrics"][0]
        assert metrics["integration_points"] == 2
        assert metrics["module_invocations"] == 1
        assert metrics["cycles"] == 1
        assert metrics["paths_enumerated"] >= 1
        assert metrics["route_analysis_capped"] is False


# --- Task 13: operational excellence checks ---


class TestContactFlowLoggingCheck:
    def test_logging_disabled_fails(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "Attribute": {"Value": "false"}
        }
        finding = ContactFlowLoggingCheck().execute(make_check_context())
        assert finding.status == CheckStatus.FAIL

    def test_logging_enabled_passes(self, make_check_context, mock_aws_client_factory):
        _wire(mock_aws_client_factory)
        mock_aws_client_factory.call_api_with_resilience.return_value = {
            "Attribute": {"Value": "true"}
        }
        finding = ContactFlowLoggingCheck().execute(make_check_context())
        assert finding.status == CheckStatus.PASS


# --- Registration ---


def test_register_behavior_checks():
    registry = CheckRegistry()
    register_contact_flow_behavior_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    assert {
        "sec-flow-auth-001",
        "cx-personalization-001",
        "res-flow-errors-001",
        "res-flow-loops-001",
    } <= ids


def test_register_performance_checks():
    registry = CheckRegistry()
    register_performance_efficiency_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    assert {
        "perf-lambda-count-001",
        "perf-sequential-lambda-001",
        "perf-flow-complexity-001",
    } <= ids


def test_register_ops_excellence_checks():
    registry = CheckRegistry()
    register_operational_excellence_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    assert {"ops-logging-001", "ops-early-media-001", "ops-auto-resolve-001"} <= ids
