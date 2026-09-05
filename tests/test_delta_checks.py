"""Regression tests for the Well-Architected delta checks."""

from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.contact_flow_behavior_checks import (
    UnreachableActionsCheck,
    register_contact_flow_behavior_checks,
)
from amazon_connect_assessment.checks.cost_containment_checks import (
    LegacySelfServiceTierCheck,
    register_cost_containment_checks,
)
from amazon_connect_assessment.checks.registration import register_all_checks
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.checks.resilience_advanced_checks import (
    LambdaDependencyRiskCheck,
    register_advanced_resilience_checks,
)
from amazon_connect_assessment.models import CheckStatus, ContactFlow
from tests.conftest import build_action, build_contact_flow


def _wire_access_denied(factory):
    factory.is_access_denied = AWSClientFactory.is_access_denied


def _contact_flow(flow_id, name, content):
    return ContactFlow(
        id=flow_id,
        arn=f"arn:aws:connect:us-east-1:123:instance/i/flow/{flow_id}",
        name=name,
        type="CONTACT_FLOW",
        state="ACTIVE",
        content=content,
    )


def _instance_with_flows(instance, *flows):
    instance.contact_flows = list(flows)
    return instance


def _access_denied(operation_name):
    return ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "denied"}},
        operation_name,
    )


class TestUnreachableActionsCheck:
    def test_unreachable_actions_condition_and_error_routes_reachable_returns_pass(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "entry",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "fn"},
                    conditions=[{"NextAction": "condition", "Condition": {"Equals": "1"}}],
                    errors=[{"NextAction": "error", "ErrorType": "NoMatchingError"}],
                ),
                build_action("condition", "DisconnectParticipant"),
                build_action("error", "DisconnectParticipant"),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "ConditionAndError", flow)
        )

        # Act
        finding = UnreachableActionsCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["flows_discovered"] == 1
        assert finding.evidence["flows_analyzed"] == 1
        assert finding.evidence["flows_skipped"] == 0

    def test_unreachable_actions_connected_dead_subgraph_returns_fail(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action("entry", "DisconnectParticipant"),
                build_action("dead-a", "MessageParticipant", next_action="dead-b"),
                build_action("dead-b", "TransferToQueue", {"QueueId": "queue-1"}),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "DeadSubgraph", flow)
        )

        # Act
        finding = UnreachableActionsCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["total_unreachable_actions"] == 2
        assert [
            action["action_id"] for action in finding.evidence["details"][0]["unreachable_actions"]
        ] == ["dead-a", "dead-b"]
        assert "no path from the flow entry point" in finding.description

    def test_unreachable_actions_partial_content_without_known_issue_returns_skipped(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        valid_flow = build_contact_flow([build_action("entry", "DisconnectParticipant")])
        instance = _instance_with_flows(
            sample_connect_instance,
            _contact_flow("flow-1", "Analyzed", valid_flow),
            _contact_flow("flow-2", "Unavailable", None),
        )

        # Act
        finding = UnreachableActionsCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["flows_discovered"] == 2
        assert finding.evidence["flows_analyzed"] == 1
        assert finding.evidence["flows_skipped"] == 1
        assert finding.evidence["analysis_complete"] is False

    def test_unreachable_actions_partial_content_with_known_issue_returns_fail_with_limitation(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        failing_flow = build_contact_flow(
            [
                build_action("entry", "DisconnectParticipant"),
                build_action("orphan", "MessageParticipant"),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance,
            _contact_flow("flow-1", "KnownIssue", failing_flow),
            _contact_flow("flow-2", "Unavailable", None),
        )

        # Act
        finding = UnreachableActionsCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["flows_analyzed"] == 1
        assert finding.evidence["flows_skipped"] == 1
        assert "incomplete" in finding.description.lower()

    def test_unreachable_actions_invalid_entry_returns_skipped_instead_of_fallback_pass(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [build_action("action-1", "DisconnectParticipant")], start_action="missing-entry"
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "InvalidEntry", flow)
        )

        # Act
        finding = UnreachableActionsCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["flows_analyzed"] == 0
        assert finding.evidence["skipped_flow_details"][0]["reason"] == (
            "entry action is missing or invalid"
        )

    def test_unreachable_actions_no_flows_returns_not_applicable(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        sample_connect_instance.contact_flows = []

        # Act
        finding = UnreachableActionsCheck().execute(
            make_check_context(instance=sample_connect_instance)
        )

        # Assert
        assert finding.status == CheckStatus.NOT_APPLICABLE
        assert finding.evidence["flows_discovered"] == 0


class TestLambdaDependencyRiskCheck:
    def test_lambda_dependency_mixed_guarded_call_sites_reports_only_unguarded_site(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _wire_access_denied(mock_aws_client_factory)
        function_arn = "arn:aws:lambda:us-east-1:123:function:shared"
        flow = build_contact_flow(
            [
                build_action(
                    "guarded",
                    "InvokeLambdaFunction",
                    {"FunctionArn": function_arn},
                    next_action="unguarded",
                    errors=[{"NextAction": "fallback", "ErrorType": "NoMatchingError"}],
                ),
                build_action(
                    "unguarded",
                    "InvokeLambdaFunction",
                    {"FunctionArn": function_arn},
                    next_action="done",
                ),
                build_action("fallback", "DisconnectParticipant"),
                build_action("done", "DisconnectParticipant"),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "MixedGuarding", flow)
        )
        mock_aws_client_factory.get_lambda_function_resilient.return_value = {
            "Configuration": {
                "FunctionName": "shared",
                "VpcConfig": {"VpcId": "vpc-1"},
            }
        }

        # Act
        finding = LambdaDependencyRiskCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["vpc_attached_without_error_branch"] == 1
        assert [detail["action_id"] for detail in finding.evidence["details"]] == ["unguarded"]
        mock_aws_client_factory.get_lambda_function_resilient.assert_called_once_with(function_arn)

    def test_lambda_dependency_supported_reference_shapes_resolve_all_static_values(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _wire_access_denied(mock_aws_client_factory)
        references = [
            "arn:aws:lambda:us-east-1:123:function:first",
            "second-function",
            "arn:aws:lambda:us-east-1:123:function:third",
            "fourth-function",
        ]
        flow = build_contact_flow(
            [
                build_action(
                    "lambda-1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": references[0]},
                    next_action="lambda-2",
                ),
                build_action(
                    "lambda-2",
                    "InvokeLambdaFunction",
                    {"LambdaFunctionARN": references[1]},
                    next_action="lambda-3",
                ),
                build_action(
                    "lambda-3",
                    "InvokeLambdaFunction",
                    {"FunctionArn": {"Value": references[2]}},
                    next_action="lambda-4",
                ),
                build_action(
                    "lambda-4",
                    "InvokeLambdaFunction",
                    {"LambdaFunctionARN": {"StaticValue": references[3]}},
                    next_action="done",
                ),
                build_action("done", "DisconnectParticipant"),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "ReferenceShapes", flow)
        )
        mock_aws_client_factory.get_lambda_function_resilient.return_value = {
            "Configuration": {"VpcConfig": {}}
        }

        # Act
        finding = LambdaDependencyRiskCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["reachable_lambda_call_sites"] == 4
        assert finding.evidence["lambda_functions_checked"] == 4
        actual_references = {
            call.args[0]
            for call in mock_aws_client_factory.get_lambda_function_resilient.call_args_list
        }
        assert actual_references == set(references)

    def test_lambda_dependency_unreachable_call_is_ignored(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action("entry", "DisconnectParticipant"),
                build_action(
                    "orphan-lambda",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:aws:lambda:us-east-1:123:function:orphan"},
                ),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "UnreachableLambda", flow)
        )

        # Act
        finding = LambdaDependencyRiskCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.NOT_APPLICABLE
        assert finding.evidence["unreachable_lambda_blocks"] == 1
        assert finding.evidence["reachable_lambda_call_sites"] == 0
        mock_aws_client_factory.get_lambda_function_resilient.assert_not_called()

    def test_lambda_dependency_partial_access_denied_returns_skipped_not_pass(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _wire_access_denied(mock_aws_client_factory)
        flow = build_contact_flow(
            [
                build_action(
                    "first", "InvokeLambdaFunction", {"FunctionArn": "denied"}, next_action="second"
                ),
                build_action(
                    "second", "InvokeLambdaFunction", {"FunctionArn": "checked"}, next_action="done"
                ),
                build_action("done", "DisconnectParticipant"),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "PartialDenied", flow)
        )

        def lookup(reference):
            if reference == "denied":
                raise _access_denied("GetFunction")
            return {"Configuration": {"VpcConfig": {}}}

        mock_aws_client_factory.get_lambda_function_resilient.side_effect = lookup

        # Act
        finding = LambdaDependencyRiskCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["lambda_functions_checked"] == 1
        assert finding.evidence["lambda_functions_access_denied"] == ["denied"]
        assert finding.evidence["analysis_complete"] is False

    def test_lambda_dependency_partial_lookup_failure_returns_skipped_not_pass(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _wire_access_denied(mock_aws_client_factory)
        flow = build_contact_flow(
            [
                build_action(
                    "first", "InvokeLambdaFunction", {"FunctionArn": "broken"}, next_action="second"
                ),
                build_action(
                    "second", "InvokeLambdaFunction", {"FunctionArn": "checked"}, next_action="done"
                ),
                build_action("done", "DisconnectParticipant"),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "PartialFailure", flow)
        )

        def lookup(reference):
            if reference == "broken":
                raise RuntimeError("lookup unavailable")
            return {"Configuration": {"VpcConfig": {}}}

        mock_aws_client_factory.get_lambda_function_resilient.side_effect = lookup

        # Act
        finding = LambdaDependencyRiskCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["lambda_functions_checked"] == 1
        assert (
            finding.evidence["lambda_function_lookup_failures"][0]["function_reference"] == "broken"
        )
        assert "required_permission" not in finding.evidence

    def test_lambda_dependency_known_risk_with_partial_denial_returns_fail_with_limitation(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        _wire_access_denied(mock_aws_client_factory)
        flow = build_contact_flow(
            [
                build_action(
                    "risky", "InvokeLambdaFunction", {"FunctionArn": "risky"}, next_action="denied"
                ),
                build_action(
                    "denied", "InvokeLambdaFunction", {"FunctionArn": "denied"}, next_action="done"
                ),
                build_action("done", "DisconnectParticipant"),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "KnownRisk", flow)
        )

        def lookup(reference):
            if reference == "denied":
                raise _access_denied("GetFunction")
            return {
                "Configuration": {
                    "FunctionName": "risky",
                    "VpcConfig": {"SubnetIds": ["subnet-1"]},
                }
            }

        mock_aws_client_factory.get_lambda_function_resilient.side_effect = lookup

        # Act
        finding = LambdaDependencyRiskCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["vpc_attached_without_error_branch"] == 1
        assert finding.evidence["analysis_complete"] is False
        assert "limited" in finding.description.lower()

    def test_lambda_dependency_dynamic_reference_returns_skipped_not_pass(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "lambda",
                    "InvokeLambdaFunction",
                    {"FunctionArn": {"Value": "$.Attributes.FunctionArn"}},
                    next_action="done",
                ),
                build_action("done", "DisconnectParticipant"),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "DynamicReference", flow)
        )

        # Act
        finding = LambdaDependencyRiskCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.SKIPPED
        assert finding.evidence["unresolved_call_sites"][0]["action_id"] == "lambda"
        mock_aws_client_factory.get_lambda_function_resilient.assert_not_called()


class TestLegacySelfServiceTierCheck:
    def test_legacy_self_service_lex_on_other_route_does_not_suppress_dtmf_route(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "entry",
                    "MessageParticipant",
                    conditions=[
                        {"NextAction": "dtmf", "Condition": {"Equals": "1"}},
                        {"NextAction": "lex", "Condition": {"Equals": "2"}},
                    ],
                ),
                build_action(
                    "dtmf",
                    "GetParticipantInput",
                    {"Text": "Press 1 for support", "MaxDigits": 1},
                    next_action="queue-dtmf",
                ),
                build_action(
                    "lex",
                    "ConnectParticipantWithLexBot",
                    {"LexV2Bot": {"AliasArn": "arn:aws:lex:alias"}},
                    next_action="queue-lex",
                ),
                build_action("queue-dtmf", "TransferToQueue", {"QueueId": "queue-1"}),
                build_action("queue-lex", "TransferToQueue", {"QueueId": "queue-2"}),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "SplitRoutes", flow)
        )

        # Act
        finding = LegacySelfServiceTierCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["dtmf_only_route_count"] == 1
        detail = finding.evidence["details"][0]
        assert detail["route_action_ids"] == ["entry", "dtmf", "queue-dtmf"]
        assert detail["dtmf_actions"] == [
            {"action_id": "dtmf", "action_type": "GetParticipantInput"}
        ]
        assert detail["queue_action_id"] == "queue-dtmf"

    def test_legacy_self_service_lex_backed_get_participant_input_returns_pass(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "lex-input",
                    "GetParticipantInput",
                    {
                        "LexV2Bot": {"AliasArn": "arn:aws:lex:alias"},
                        "Text": "How can I help?",
                        "MaxDigits": 1,
                    },
                    next_action="queue",
                ),
                build_action("queue", "TransferToQueue", {"QueueId": "queue-1"}),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "LexBackedInput", flow)
        )

        # Act
        finding = LegacySelfServiceTierCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["eligible_reachable_queue_routes"] == 1
        assert finding.evidence["dtmf_only_route_count"] == 0

    def test_legacy_self_service_unreachable_dtmf_block_is_ignored(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action("entry", "TransferToQueue", {"QueueId": "queue-1"}),
                build_action(
                    "orphan-dtmf",
                    "GetParticipantInput",
                    {"Text": "Press 1", "MaxDigits": 1},
                ),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "OrphanDtmf", flow)
        )

        # Act
        finding = LegacySelfServiceTierCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["dtmf_only_route_count"] == 0

    def test_legacy_self_service_unreachable_lex_does_not_suppress_reachable_dtmf(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "dtmf",
                    "GetUserInput",
                    {"Text": "Press 1", "MaxDigits": 1},
                    next_action="queue",
                ),
                build_action("queue", "TransferToQueue", {"QueueId": "queue-1"}),
                build_action(
                    "orphan-lex",
                    "ConnectToLexBot",
                    {"BotName": "Unused"},
                ),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "OrphanLex", flow)
        )

        # Act
        finding = LegacySelfServiceTierCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.FAIL
        assert finding.evidence["dtmf_only_route_count"] == 1
        assert finding.evidence["details"][0]["dtmf_actions"][0]["action_id"] == "dtmf"

    def test_legacy_self_service_dtmf_branch_not_leading_to_queue_is_ignored(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "entry",
                    "MessageParticipant",
                    conditions=[
                        {"NextAction": "dtmf", "Condition": {"Equals": "1"}},
                        {"NextAction": "queue", "Condition": {"Equals": "2"}},
                    ],
                ),
                build_action(
                    "dtmf",
                    "GetParticipantInput",
                    {"Text": "Press 1", "MaxDigits": 1},
                    next_action="done",
                ),
                build_action("done", "DisconnectParticipant"),
                build_action("queue", "TransferToQueue", {"QueueId": "queue-1"}),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "SeparateBranch", flow)
        )

        # Act
        finding = LegacySelfServiceTierCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["eligible_reachable_queue_routes"] == 1
        assert finding.evidence["dtmf_only_route_count"] == 0

    def test_legacy_self_service_no_reachable_queue_route_returns_not_applicable(
        self, make_check_context, sample_connect_instance
    ):
        # Arrange
        flow = build_contact_flow(
            [
                build_action(
                    "dtmf",
                    "StoreUserInput",
                    {"MaxDigits": 4},
                    next_action="done",
                ),
                build_action("done", "DisconnectParticipant"),
            ]
        )
        instance = _instance_with_flows(
            sample_connect_instance, _contact_flow("flow-1", "NoQueue", flow)
        )

        # Act
        finding = LegacySelfServiceTierCheck().execute(make_check_context(instance=instance))

        # Assert
        assert finding.status == CheckStatus.NOT_APPLICABLE
        assert finding.evidence["eligible_reachable_queue_routes"] == 0


def test_delta_check_registrars_include_all_three_checks():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_contact_flow_behavior_checks(registry)
    register_advanced_resilience_checks(registry)
    register_cost_containment_checks(registry)

    # Assert
    assert {
        "ops-unreachable-blocks-001",
        "res-lambda-dependency-001",
        "cost-self-service-tier-001",
    } <= set(registry.list_check_ids())


def test_delta_checks_skip_flow_analysis_excludes_all_three_checks():
    # Arrange
    registry = CheckRegistry()

    # Act
    register_all_checks(registry, skip_flow_analysis=True)

    # Assert
    registered = set(registry.list_check_ids())
    assert "ops-unreachable-blocks-001" not in registered
    assert "res-lambda-dependency-001" not in registered
    assert "cost-self-service-tier-001" not in registered
