"""
Tests for contact-flow security checks (Task 5 / Requirements 20-23, 26, 39).

These checks consume the parser so we build flow JSON using conftest helpers.
"""

from amazon_connect_assessment.checks.contact_flow_security_checks import (
    DynamicPromptInjectionCheck,
    ExternalTransferTollFraudCheck,
    LambdaResponseValidationCheck,
    OutputHandlingInjectionCheck,
    PIIInPromptsCheck,
    SensitiveDataInAttributesCheck,
    register_contact_flow_security_checks,
)
from amazon_connect_assessment.checks.registry import CheckRegistry
from amazon_connect_assessment.models import CheckStatus, ContactFlow
from tests.conftest import build_action, build_contact_flow


def _instance_with_flow(instance, flow_json, name="TestFlow"):
    """Attach a single parsed flow to the instance fixture."""
    instance.contact_flows = [
        ContactFlow(
            id="f1",
            arn="arn:aws:connect:us-east-1:123:instance/i/flow/f1",
            name=name,
            type="CONTACT_FLOW",
            state="ACTIVE",
            content=flow_json,
        )
    ]
    return instance


# --- Prompt injection (sec-prompt-inject-001) ---


class TestDynamicPromptInjection:
    def test_dynamic_ref_in_prompt_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [build_action("a1", "MessageParticipant", {"Text": "Hello $.Attributes.Name"})]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = DynamicPromptInjectionCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL
        assert finding.structured_remediation is not None

    def test_static_prompt_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [build_action("a1", "MessageParticipant", {"Text": "Thank you for calling."})]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = DynamicPromptInjectionCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS

    # --- Reviewer feedback: system attributes (queue name, agent name,
    # etc) are Connect-populated/admin-configured and a caller cannot
    # influence what they resolve to, so referencing one in a prompt is
    # not the SSML-injection risk this check exists to catch. Previously
    # every "$." reference was flagged the same way, including
    # $.Queue.Name — the reviewer noted this without further context. ---

    def test_system_attribute_only_reference_passes(
        self, make_check_context, sample_connect_instance
    ):
        flow = build_contact_flow(
            [
                build_action(
                    "a1", "MessageParticipant", {"Text": "You are in the $.Queue.Name queue."}
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = DynamicPromptInjectionCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS
        assert finding.evidence["system_attribute_prompts_excluded"] == 1

    def test_agent_name_system_attribute_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "MessageParticipant",
                    {"Text": "You're speaking with $.Agent.FirstName."},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = DynamicPromptInjectionCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS

    def test_caller_sourced_reference_still_fails(
        self, make_check_context, sample_connect_instance
    ):
        # A user-defined attribute (set from caller input, a Lex slot, or
        # a Lambda lookup) is NOT a system attribute and must still be
        # flagged -- this is the actual injection risk.
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "MessageParticipant",
                    {"Text": "Hello, $.Attributes.CustomerName."},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = DynamicPromptInjectionCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_mixed_system_and_caller_reference_still_fails(
        self, make_check_context, sample_connect_instance
    ):
        # A prompt mixing a safe system attribute with a caller-sourced
        # one must still be flagged -- the caller-sourced part is the risk.
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "MessageParticipant",
                    {"Text": "Queue $.Queue.Name, customer $.Attributes.CustomerName."},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = DynamicPromptInjectionCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL


# --- Lambda response validation (sec-lambda-validation-001) ---


class TestLambdaResponseValidation:
    def test_branch_without_default_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:fn"},
                    conditions=[
                        {
                            "NextAction": "a2",
                            "Condition": {"Operator": "Equals", "Operands": ["1"]},
                        }
                    ],
                ),
                build_action("a2", "DisconnectParticipant"),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = LambdaResponseValidationCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_lambda_with_default_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:fn"},
                    next_action="a3",
                    conditions=[
                        {
                            "NextAction": "a2",
                            "Condition": {"Operator": "Equals", "Operands": ["1"]},
                        }
                    ],
                ),
                build_action("a2", "DisconnectParticipant"),
                build_action("a3", "DisconnectParticipant"),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = LambdaResponseValidationCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


# --- Toll fraud (sec-toll-fraud-001) ---


class TestExternalTransferTollFraud:
    def test_dynamic_transfer_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "TransferContactToPhoneNumber",
                    {"PhoneNumber": "$.Attributes.DestNumber"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = ExternalTransferTollFraudCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL
        assert finding.severity.value == "critical"

    def test_static_transfer_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "TransferContactToPhoneNumber",
                    {"PhoneNumber": "+18005551234"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = ExternalTransferTollFraudCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


# --- Sensitive data in attributes (sec-sensitive-data-001) ---


class TestSensitiveDataInAttributes:
    def test_ssn_attribute_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "UpdateContactAttributes",
                    {"Attributes": {"CustomerSSN": "123-45-6789"}},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = SensitiveDataInAttributesCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL
        assert "ssn" in finding.evidence["flagged_attributes"][0]["attribute_name"].lower()

    def test_safe_attribute_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "UpdateContactAttributes",
                    {"Attributes": {"Language": "en-US"}},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = SensitiveDataInAttributesCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


# --- PII in prompts (sec-pii-prompts-001) ---


class TestPIIInPrompts:
    def test_unmasked_account_number_fails(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "MessageParticipant",
                    {"Text": "Your AccountNumber is $.Attributes.AccountNumber"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = PIIInPromptsCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL

    def test_masked_reference_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "MessageParticipant",
                    {"Text": "Account ending in last4 $.Attributes.AcctLast4"},
                )
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = PIIInPromptsCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


# --- Output handling injection (sec-output-handling-001) ---


class TestOutputHandlingInjection:
    def test_lambda_to_prompt_with_dynamic_ref_fails(
        self, make_check_context, sample_connect_instance
    ):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:fn"},
                    next_action="a2",
                ),
                build_action("a2", "MessageParticipant", {"Text": "Result: $.External.result"}),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = OutputHandlingInjectionCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.FAIL
        assert "injection" in finding.description.lower()

    def test_lambda_to_static_prompt_passes(self, make_check_context, sample_connect_instance):
        flow = build_contact_flow(
            [
                build_action(
                    "a1",
                    "InvokeLambdaFunction",
                    {"FunctionArn": "arn:...:fn"},
                    next_action="a2",
                ),
                build_action("a2", "MessageParticipant", {"Text": "Thank you, processing."}),
            ]
        )
        inst = _instance_with_flow(sample_connect_instance, flow)
        finding = OutputHandlingInjectionCheck().execute(make_check_context(instance=inst))
        assert finding.status == CheckStatus.PASS


# --- Registration ---


def test_register_contact_flow_security_checks():
    registry = CheckRegistry()
    register_contact_flow_security_checks(registry)
    ids = {c.check_id for c in registry.get_all_checks()}
    expected = {
        "sec-prompt-inject-001",
        "sec-lambda-validation-001",
        "sec-toll-fraud-001",
        "sec-sensitive-data-001",
        "sec-pii-prompts-001",
        "sec-output-handling-001",
    }
    assert expected <= ids
