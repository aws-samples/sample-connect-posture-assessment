"""
Tests for AI/agentic security checks (Task 6 / Requirements 25, 27).
"""

from botocore.exceptions import ClientError

from amazon_connect_assessment.aws_client_factory import AWSClientFactory
from amazon_connect_assessment.checks.ai_agent_security_checks import (
    ExcessiveAgencyCheck,
    LambdaAIPathwayCheck,
    LexBotGuardrailCheck,
    MultiAICascadeCheck,
    register_ai_agent_security_checks,
)
from amazon_connect_assessment.checks.registry import CheckRegistry
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


# --- Lex bot guardrail (sec-ai-lex-001) ---


class TestLexBotGuardrailCheck:
    def test_lex_integration_flags(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow([build_action("a1", "ConnectToLexBot", {"BotName": "FAQ"})])
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = LexBotGuardrailCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL
        assert finding.structured_remediation is not None

    def test_no_lex_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow([build_action("a1", "MessageParticipant", {"Text": "hi"})])
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = LexBotGuardrailCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


# --- Lambda AI pathway (sec-ai-lambda-001) ---


class TestLambdaAIPathwayCheck:
    def test_bedrock_lambda_flags(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:aws:lambda:us-east-1:123:function:bedrock-agent"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = LambdaAIPathwayCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_non_ai_lambda_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:aws:lambda:us-east-1:123:function:routing-helper"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = LambdaAIPathwayCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


# --- Multi-AI cascade (sec-ai-cascade-001) ---


class TestMultiAICascadeCheck:
    def test_lex_plus_ai_lambda_flags(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action("a1", "ConnectToLexBot", {"BotName": "faq"}, next_action="a2"),
                build_action(
                    "a2",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:bedrock-summarize"},
                ),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = MultiAICascadeCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL
        # Reviewer feedback: the description was a single terse line with
        # no explanation of the actual risk. It must now spell out what
        # "cascade" means and why an unchecked handoff between stages is
        # dangerous, plus name the flagged flow(s).
        assert "flow(s) chain two or more AI components" in finding.description
        assert "My Custom Flow" in finding.description or "TestFlow" in finding.description

    def test_single_ai_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow([build_action("a1", "ConnectToLexBot", {"BotName": "faq"})])
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = MultiAICascadeCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


# --- Excessive agency (sec-excessive-agency-001) ---


class TestExcessiveAgencyCheck:
    def test_broad_lambda_role_fails(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        _wire(mock_aws_client_factory)
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:aws:lambda:us-east-1:123:function:handler"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)

        f = mock_aws_client_factory
        f.get_lambda_function_resilient.return_value = {
            "Configuration": {"Role": "arn:aws:iam::123:role/BroadRole"}
        }
        f.list_role_policies_resilient.return_value = {"PolicyNames": ["pol1"]}
        f.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["s3:PutObject", "iam:CreateUser"],
                        "Resource": "*",
                    }
                ]
            }
        }

        finding = ExcessiveAgencyCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL
        assert "excessive" in finding.description.lower()

    def test_scoped_lambda_role_passes(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        _wire(mock_aws_client_factory)
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:aws:lambda:us-east-1:123:function:handler"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)

        f = mock_aws_client_factory
        f.get_lambda_function_resilient.return_value = {
            "Configuration": {"Role": "arn:aws:iam::123:role/ScopedRole"}
        }
        f.list_role_policies_resilient.return_value = {"PolicyNames": ["pol1"]}
        f.get_role_policy_resilient.return_value = {
            "PolicyDocument": {
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["connect:DescribeInstance"],
                        "Resource": "arn:aws:connect:*",
                    }
                ]
            }
        }

        finding = ExcessiveAgencyCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS

    def test_access_denied_skips(
        self, make_check_context, sample_connect_instance, mock_aws_client_factory
    ):
        _wire(mock_aws_client_factory)
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:aws:lambda:us-east-1:123:function:handler"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        mock_aws_client_factory.get_lambda_function_resilient.side_effect = ClientError(
            {"Error": {"Code": "AccessDenied", "Message": "no"}}, "GetFunction"
        )
        finding = ExcessiveAgencyCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.SKIPPED


# --- Registration ---


def test_register_ai_agent_security_checks():
    registry = CheckRegistry()
    register_ai_agent_security_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    assert {
        "sec-ai-lex-001",
        "sec-ai-lambda-001",
        "sec-ai-cascade-001",
        "sec-excessive-agency-001",
    } <= ids
