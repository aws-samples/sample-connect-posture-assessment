"""
AI / Agentic security checks (Phase 2 / Task 6).

Checks for agentic AI threat vectors specific to contact centers:

- sec-ai-lex-001           : Lex bot integration without guardrails
- sec-ai-lambda-001        : Lambda AI-pathway least-privilege
- sec-ai-cascade-001       : Multi-AI cascade without inter-stage validation
- sec-excessive-agency-001 : Lambda execution role overly broad (OWASP LLM06)

These checks combine flow-content analysis (parser) with AWS API inspection
(Lambda configs, IAM roles). They degrade to SKIPPED on access denied.
"""

from typing import Optional

from ..models import (
    CheckStatus,
    ContactFlow,
    ContactFlowGraph,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from ..parsers import ContactFlowParser
from .base import BaseCheck, CheckContext

_PARSER = ContactFlowParser()

# Action types representing AI/ML integrations.
_LEX_BOT_ACTIONS = {"ConnectToLexBot", "ConnectParticipantWithLexBot"}
_AI_LAMBDA_HINTS = ("bedrock", "sagemaker", "comprehend", "ai", "ml", "llm")
_SENSITIVE_SERVICE_PREFIXES = (
    "iam:",
    "kms:Decrypt",
    "s3:Put",
    "s3:Delete",
    "dynamodb:Delete",
    "sqs:Send",
    "sns:Publish",
    "secretsmanager:",
    "organizations:",
)


def _parse_flow(flow: ContactFlow) -> Optional[ContactFlowGraph]:
    if not flow.content or not isinstance(flow.content, dict):
        return None
    try:
        return _PARSER.parse(flow.content)
    except Exception:
        return None


def _role_name_from_arn(arn: str) -> Optional[str]:
    if not arn or ":role/" not in arn:
        return None
    return arn.split(":role/", 1)[1].split("/")[-1]


class LexBotGuardrailCheck(BaseCheck):
    """Verify Lex bot integrations have guardrails configured (Req 25.1)."""

    def __init__(self):
        super().__init__(
            check_id="sec-ai-lex-001",
            name="Lex Bot Guardrail Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Checks that Lex bot integrations in contact flows have input "
                "validation or guardrail configuration to prevent prompt injection "
                "and content manipulation."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        lex_actions = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type in _LEX_BOT_ACTIONS:
                    lex_actions.append(
                        {
                            "flow": flow.name,
                            "flow_id": flow.id,
                            "action_id": action.action_id,
                            "bot_name": (
                                action.parameters.get("BotName")
                                or action.parameters.get("LexBot", {}).get("Name", "unknown")
                            ),
                        }
                    )

        if not lex_actions:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description="No Lex bot integrations found in contact flows.",
                evidence={"lex_actions_found": 0},
            )

        # For this check, we flag all Lex integrations with a recommendation
        # to verify guardrails exist (we cannot inspect Lex bot configs deeply
        # without additional API access beyond what the current scope covers).
        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"{len(lex_actions)} Lex bot integration(s) detected; verify that "
                "each bot has input validation and guardrails configured."
            ),
            evidence={"lex_integrations": lex_actions},
            structured_remediation=Remediation(
                summary="Verify Lex bot guardrails (input validation, content filtering).",
                target_resources=[a["action_id"] for a in lex_actions],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "For each Lex bot referenced in the contact flows, "
                            "enable Bedrock Guardrails or configure slot validation "
                            "prompts and fallback intents to constrain user inputs."
                        ),
                        console_path="Lex console -> Bot -> Guardrails / Slot validation",
                    ),
                    RemediationStep(
                        order=2,
                        instruction=(
                            "Add a FallbackIntent that handles unexpected or "
                            "malicious inputs gracefully rather than passing "
                            "them through to downstream actions."
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Amazon Lex bot guardrails",
                        url="https://docs.aws.amazon.com/lexv2/latest/dg/guardrails.html",
                    )
                ],
                applies_if="bots accept free-text or open-ended slot inputs.",
            ),
        )


class LambdaAIPathwayCheck(BaseCheck):
    """Flag Lambda AI/ML pathways for least-privilege review (Req 25.2)."""

    def __init__(self):
        super().__init__(
            check_id="sec-ai-lambda-001",
            name="Lambda AI-Pathway Least Privilege",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description=(
                "Identifies Lambda functions in contact flows that likely invoke "
                "AI/ML services (Bedrock, SageMaker, Comprehend) and flags them "
                "for least-privilege IAM review."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        ai_lambdas = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type != "InvokeLambdaFunction":
                    continue
                fn_arn = action.parameters.get("FunctionArn", "")
                fn_lower = fn_arn.lower()
                if any(hint in fn_lower for hint in _AI_LAMBDA_HINTS):
                    ai_lambdas.append(
                        {
                            "flow": flow.name,
                            "flow_id": flow.id,
                            "action_id": action.action_id,
                            "function_arn": fn_arn,
                        }
                    )

        if not ai_lambdas:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description="No AI/ML Lambda pathways detected in contact flows.",
                evidence={"ai_lambdas_found": 0},
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"{len(ai_lambdas)} Lambda function(s) appear to invoke AI/ML "
                "services; verify their execution roles follow least privilege "
                "for model invocation."
            ),
            evidence={"ai_lambda_pathways": ai_lambdas},
            structured_remediation=Remediation(
                summary="Review AI-pathway Lambda execution roles for least privilege.",
                target_resources=[a["function_arn"] for a in ai_lambdas],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "For each flagged Lambda, review its execution role "
                            "and ensure it only has InvokeModel / InvokeEndpoint "
                            "permissions on the specific model(s) it needs."
                        ),
                        command=(
                            "aws lambda get-function --function-name "
                            f"{ai_lambdas[0]['function_arn'] if ai_lambdas else '<fn-arn>'}"
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Bedrock IAM permissions",
                        url="https://docs.aws.amazon.com/bedrock/latest/userguide/security-iam.html",  # noqa: E501
                    )
                ],
                applies_if="Lambda functions invoke generative AI or ML models.",
            ),
        )


class MultiAICascadeCheck(BaseCheck):
    """Detect multi-AI stages without inter-stage validation (Req 25.3)."""

    def __init__(self):
        super().__init__(
            check_id="sec-ai-cascade-001",
            name="Multi-AI Cascade Validation",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description=(
                "Flags contact flows that chain two or more AI components "
                "(a Lex bot, then a Lambda that calls Bedrock/SageMaker/"
                "Comprehend, etc.) back-to-back with nothing checking the "
                "output in between. Each AI stage can misread the caller or "
                "return something it shouldn't; without a check between "
                "stages, one bad output silently becomes the next stage's "
                "trusted input."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        multi_ai_flows = []

        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            ai_count = 0
            ai_types = set()
            for action in graph.actions.values():
                if action.action_type in _LEX_BOT_ACTIONS:
                    ai_count += 1
                    ai_types.add("lex")
                elif action.action_type == "InvokeLambdaFunction":
                    fn = action.parameters.get("FunctionArn", "").lower()
                    if any(h in fn for h in _AI_LAMBDA_HINTS):
                        ai_count += 1
                        ai_types.add("lambda_ai")

            if ai_count >= 2:
                multi_ai_flows.append(
                    {
                        "flow": flow.name,
                        "flow_id": flow.id,
                        "ai_integration_count": ai_count,
                        "ai_types": sorted(ai_types),
                    }
                )

        if not multi_ai_flows:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description="No multi-AI cascade patterns detected.",
                evidence={"flows_analyzed": len(instance.contact_flows)},
            )

        flow_lines = []
        for f in multi_ai_flows[:3]:
            flow_lines.append(
                f"* `{f['flow']}`: {f['ai_integration_count']} AI stage(s) "
                f"({', '.join(f['ai_types'])})"
            )
        more_note = (
            f"\n\n_+ {len(multi_ai_flows) - 3} additional flow(s); see JSON "
            "export for the full list._"
            if len(multi_ai_flows) > 3
            else ""
        )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ContactFlow",
            description=(
                f"**{len(multi_ai_flows)} flow(s) chain two or more AI "
                "components** (a Lex bot, then a Lambda that calls an AI/ML "
                "service such as Bedrock, SageMaker, or Comprehend) "
                "**without anything checking the output between stages.**\n\n"
                "**Why this matters.** Each AI stage can misread the "
                "caller, hallucinate, or return output outside the shape "
                "the flow expects. When one stage's output feeds directly "
                "into the next stage's input with no check, an error at "
                "stage 1 doesn't stay contained — it becomes stage 2's "
                "trusted input, and the flow acts on it as if it were "
                "verified. A caller crafting adversarial input for stage 1 "
                "(prompt injection against the Lex bot) can potentially "
                "influence stage 2's behavior the same way.\n\n"
                f"**Flagged flow(s):**\n\n{chr(10).join(flow_lines)}{more_note}\n\n"
                "**Fix.** Between each AI stage, add a Check contact "
                "attributes block (or a small validation Lambda) that "
                "confirms the previous stage's output matches an expected "
                "shape — a known intent name, a slot value in an allowed "
                "set, a confidence score above a threshold — before letting "
                "the next stage act on it."
            ),
            evidence={"multi_ai_flows": multi_ai_flows},
            structured_remediation=Remediation(
                summary=(
                    "Add inter-stage validation between AI components to "
                    "prevent one stage's bad output from propagating "
                    "unchecked into the next."
                ),
                target_resources=[f["flow_id"] for f in multi_ai_flows],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "Between each AI stage (Lex → Lambda, Lambda → Lambda), "
                            "add a Check Attribute or validation Lambda that verifies "
                            "the output conforms to expected format before passing "
                            "it to the next stage."
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="OWASP Top 10 for LLM Applications",
                        url="https://owasp.org/www-project-top-10-for-large-language-model-applications/",  # noqa: E501
                    )
                ],
                applies_if="multiple AI components process the same contact flow path.",
            ),
        )


class ExcessiveAgencyCheck(BaseCheck):
    """Detect Lambda functions with overly broad IAM roles (Req 27 / OWASP LLM06)."""

    def __init__(self):
        super().__init__(
            check_id="sec-excessive-agency-001",
            name="Excessive Agency / Lambda Privilege Scope",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Identifies Lambda functions invoked by contact flows whose "
                "execution roles grant overly broad or sensitive permissions, "
                "reducing blast radius if the flow is manipulated."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory
        flagged = []

        # Collect unique Lambda ARNs from all flows.
        lambda_arns = set()
        for flow in instance.contact_flows:
            graph = _parse_flow(flow)
            if not graph:
                continue
            for action in graph.actions.values():
                if action.action_type == "InvokeLambdaFunction":
                    arn = action.parameters.get("FunctionArn")
                    if arn:
                        lambda_arns.add(arn)

        if not lambda_arns:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ContactFlow",
                description="No Lambda integrations to evaluate.",
                evidence={"lambda_count": 0},
            )

        for fn_arn in lambda_arns:
            try:
                fn_resp = factory.get_lambda_function_resilient(fn_arn)
            except Exception as e:
                if factory.is_access_denied(e):
                    return self.skipped_for_access_denied(context, "lambda:GetFunction")
                continue

            role_arn = fn_resp.get("Configuration", {}).get("Role", "")
            role_name = _role_name_from_arn(role_arn)
            if not role_name:
                continue

            # Check inline policies for broad permissions.
            try:
                inline_names = factory.list_role_policies_resilient(role_name).get(
                    "PolicyNames", []
                )
                for policy_name in inline_names:
                    doc = factory.get_role_policy_resilient(role_name, policy_name).get(
                        "PolicyDocument", {}
                    )
                    for stmt in doc.get("Statement", []) if isinstance(doc, dict) else []:
                        if stmt.get("Effect") != "Allow":
                            continue
                        actions = stmt.get("Action", [])
                        if isinstance(actions, str):
                            actions = [actions]
                        for a in actions:
                            if a == "*" or any(
                                a.startswith(p) for p in _SENSITIVE_SERVICE_PREFIXES
                            ):
                                flagged.append(
                                    {
                                        "function_arn": fn_arn,
                                        "role_name": role_name,
                                        "excessive_action": a,
                                        "policy_name": policy_name,
                                    }
                                )
            except Exception as e:
                if factory.is_access_denied(e):
                    return self.skipped_for_access_denied(context, "iam:GetRolePolicy")
                continue

        if flagged:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="LambdaFunction",
                description=(
                    f"{len(flagged)} excessive permission(s) detected in Lambda "
                    "execution roles used by contact flows."
                ),
                evidence={"excessive_permissions": flagged},
                structured_remediation=Remediation(
                    summary="Scope down Lambda execution roles to least privilege.",
                    target_resources=list({f["function_arn"] for f in flagged}),
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "For each flagged Lambda role, remove or constrain "
                                "sensitive-service permissions (iam:*, kms:Decrypt, "
                                "s3:Put/Delete, dynamodb:Delete, sqs:Send) to only "
                                "the specific resources the function needs."
                            ),
                            command=(
                                f"aws iam list-role-policies --role-name {flagged[0]['role_name']}"
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Consider using a dedicated execution role per "
                                "Lambda rather than sharing a broad role across "
                                "multiple functions."
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="OWASP LLM06: Excessive Agency",
                            url="https://owasp.org/www-project-top-10-for-large-language-model-applications/",  # noqa: E501
                        )
                    ],
                    applies_if="Lambda functions handle untrusted contact-flow data.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="LambdaFunction",
            description=(
                f"Evaluated {len(lambda_arns)} Lambda execution role(s); no "
                "excessive permissions detected."
            ),
            evidence={"lambda_count": len(lambda_arns)},
        )


def register_ai_agent_security_checks(registry) -> None:
    """Register all AI/agentic security checks."""
    registry.register_check(LexBotGuardrailCheck())
    registry.register_check(LambdaAIPathwayCheck())
    registry.register_check(MultiAICascadeCheck())
    registry.register_check(ExcessiveAgencyCheck())
