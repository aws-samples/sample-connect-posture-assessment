"""Evidence-bounded AI operations maturity checks for Amazon Q in Connect.

The six instance-level checks in this module discover Q in Connect resources
through ``connect:ListIntegrationAssociations`` and then inspect the relevant
Q in Connect or Amazon Bedrock control-plane settings. List operations are
fully paginated with bounded loops. Incomplete discovery is reported as
``SKIPPED`` rather than being interpreted as healthy configuration.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional

from ..models import (
    CheckStatus,
    Finding,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from .base import BaseCheck, CheckContext

_MAX_LIST_PAGES = 20
_LIST_PAGE_SIZE = 100
_PREMIUM_MODEL_HINTS = ("opus", "sonnet-4", "sonnet4", "gpt-5")
_KB_FAILED_LIFECYCLE_STATUSES = {"CREATE_FAILED", "DELETE_FAILED"}
_KB_TRANSIENT_OR_INACTIVE_STATUSES = {
    "CREATE_IN_PROGRESS",
    "DELETE_IN_PROGRESS",
    "DELETED",
}
_KB_TRANSIENT_INGESTION_STATUSES = {"SYNCING_IN_PROGRESS", "CREATE_IN_PROGRESS"}


@dataclass
class _IncompleteCollectionError(Exception):
    """Describe an incomplete paginated or detail lookup without losing evidence."""

    operation: str
    reason: str
    partial_count: int = 0
    pages_completed: int = 0
    cause: Optional[Exception] = None


PageFetcher = Callable[..., Dict[str, Any]]


def _collect_paginated(
    fetch_page: PageFetcher,
    *,
    operation: str,
    items_key: str,
    response_token_key: str,
    request_token_key: str,
    request_page_size_key: str,
) -> List[Dict[str, Any]]:
    """Collect every page from a list API or raise with deterministic partial evidence."""
    items: List[Dict[str, Any]] = []
    next_token: Optional[str] = None

    for page_index in range(_MAX_LIST_PAGES):
        kwargs: Dict[str, Any] = {request_page_size_key: _LIST_PAGE_SIZE}
        if next_token:
            kwargs[request_token_key] = next_token
        try:
            response = fetch_page(**kwargs)
        except Exception as error:  # noqa: BLE001 - classified by the caller
            raise _IncompleteCollectionError(
                operation=operation,
                reason="api_call_failed",
                partial_count=len(items),
                pages_completed=page_index,
                cause=error,
            ) from error

        page_items = response.get(items_key) or []
        items.extend(item for item in page_items if isinstance(item, dict))
        next_token = response.get(response_token_key)
        if not next_token:
            return items

    raise _IncompleteCollectionError(
        operation=operation,
        reason="pagination_limit_reached",
        partial_count=len(items),
        pages_completed=_MAX_LIST_PAGES,
    )


def _list_association_arns(factory: Any, instance_id: str, integration_type: str) -> List[str]:
    associations = _collect_paginated(
        lambda **kwargs: factory.list_integration_associations_resilient(
            instance_id, integration_type, **kwargs
        ),
        operation="connect:ListIntegrationAssociations",
        items_key="IntegrationAssociationSummaryList",
        response_token_key="NextToken",
        request_token_key="NextToken",
        request_page_size_key="MaxResults",
    )

    arns: List[str] = []
    for association in associations:
        arn = association.get("IntegrationArn")
        if not arn:
            raise _IncompleteCollectionError(
                operation="connect:ListIntegrationAssociations",
                reason="association_missing_integration_arn",
                partial_count=len(arns),
            )
        if arn not in arns:
            arns.append(arn)
    return arns


def _list_assistant_arns(factory: Any, instance_id: str) -> List[str]:
    return _list_association_arns(factory, instance_id, "WISDOM_ASSISTANT")


def _list_knowledge_base_arns(factory: Any, instance_id: str) -> List[str]:
    return _list_association_arns(factory, instance_id, "WISDOM_KNOWLEDGE_BASE")


def _list_guardrails(factory: Any, assistant_id: str) -> List[Dict[str, Any]]:
    return _collect_paginated(
        lambda **kwargs: factory.list_ai_guardrails_resilient(assistant_id, **kwargs),
        operation="wisdom:ListAIGuardrails",
        items_key="aiGuardrailSummaries",
        response_token_key="nextToken",
        request_token_key="nextToken",
        request_page_size_key="maxResults",
    )


def _list_prompts(factory: Any, assistant_id: str) -> List[Dict[str, Any]]:
    return _collect_paginated(
        lambda **kwargs: factory.list_ai_prompts_resilient(assistant_id, **kwargs),
        operation="wisdom:ListAIPrompts",
        items_key="aiPromptSummaries",
        response_token_key="nextToken",
        request_token_key="nextToken",
        request_page_size_key="maxResults",
    )


def _list_inference_profiles(factory: Any) -> List[Dict[str, Any]]:
    return _collect_paginated(
        lambda **kwargs: factory.list_inference_profiles_resilient(
            typeEquals="SYSTEM_DEFINED", **kwargs
        ),
        operation="bedrock:ListInferenceProfiles",
        items_key="inferenceProfileSummaries",
        response_token_key="nextToken",
        request_token_key="nextToken",
        request_page_size_key="maxResults",
    )


def _id_from_arn(arn: str) -> str:
    return arn.rsplit("/", 1)[-1] if arn else ""


def _safe_failure_reasons(raw_reasons: Any) -> List[str]:
    """Bound service-provided failure text before placing it in report evidence."""
    if not isinstance(raw_reasons, list):
        return []
    return [str(reason)[:300] for reason in raw_reasons[:5]]


def _skipped_for_incomplete_collection(
    check: BaseCheck,
    context: CheckContext,
    error: _IncompleteCollectionError,
    required_permission: str,
    extra_evidence: Optional[Dict[str, Any]] = None,
) -> Finding:
    evidence: Dict[str, Any] = {
        "operation": error.operation,
        "limitation": error.reason,
        "partial_item_count": error.partial_count,
        "pages_completed": error.pages_completed,
    }
    if extra_evidence:
        evidence.update(extra_evidence)

    factory = context.aws_client_factory
    if error.cause is not None and factory.is_access_denied(error.cause):
        finding = check.skipped_for_access_denied(context, required_permission)
        finding.evidence.update(evidence)
        return finding

    if error.cause is not None:
        evidence["error_type"] = type(error.cause).__name__
    return check.create_finding(
        status=CheckStatus.SKIPPED,
        resource_id=context.instance.instance_id,
        resource_type="ConnectInstance",
        description=(
            f"Skipped: insufficient data from {error.operation}. Partial results were retained "
            "as evidence but were not interpreted as a healthy configuration."
        ),
        evidence=evidence,
    )


def _skipped_for_detail_error(
    check: BaseCheck,
    context: CheckContext,
    error: Exception,
    required_permission: str,
    operation: str,
    evidence: Dict[str, Any],
) -> Finding:
    if context.aws_client_factory.is_access_denied(error):
        finding = check.skipped_for_access_denied(context, required_permission)
        finding.evidence.update({"operation": operation, **evidence})
        return finding
    return check.create_finding(
        status=CheckStatus.SKIPPED,
        resource_id=context.instance.instance_id,
        resource_type="ConnectInstance",
        description=(
            f"Skipped: insufficient data because {operation} failed. Partial observations were "
            "retained but were not interpreted as a healthy configuration."
        ),
        evidence={"operation": operation, "error_type": type(error).__name__, **evidence},
    )


class AIGuardrailCoverageCheck(BaseCheck):
    """Check for an ACTIVE and PUBLISHED guardrail in each assistant scope."""

    def __init__(self) -> None:
        super().__init__(
            check_id="ai-ops-guardrail-001",
            name="Q in Connect AI Guardrail Availability",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Checks whether each Q in Connect assistant exposes at least one ACTIVE and "
                "PUBLISHED AI guardrail. This evidence does not establish AI-agent attachment "
                "or the guardrail's configured filter categories."
            ),
        )

    def execute(self, context: CheckContext) -> Finding:
        instance = context.instance
        factory = context.aws_client_factory
        try:
            assistant_arns = _list_assistant_arns(factory, instance.instance_id)
        except _IncompleteCollectionError as error:
            return _skipped_for_incomplete_collection(
                self, context, error, "connect:ListIntegrationAssociations"
            )

        if not assistant_arns:
            return self.not_applicable(
                context,
                "no Q in Connect assistant integration was found on the instance",
                evidence={"assistant_count": 0},
            )

        uncovered: List[Dict[str, Any]] = []
        observations: List[Dict[str, Any]] = []
        for assistant_index, arn in enumerate(assistant_arns):
            assistant_id = _id_from_arn(arn)
            try:
                guardrails = _list_guardrails(factory, assistant_id)
            except _IncompleteCollectionError as error:
                return _skipped_for_incomplete_collection(
                    self,
                    context,
                    error,
                    "wisdom:ListAIGuardrails",
                    {"assistant_id": assistant_id, "assistants_evaluated": assistant_index},
                )

            qualifying = [
                guardrail
                for guardrail in guardrails
                if guardrail.get("status") == "ACTIVE"
                and guardrail.get("visibilityStatus") == "PUBLISHED"
            ]
            states = sorted(
                {
                    f"{guardrail.get('status', 'MISSING')}/"
                    f"{guardrail.get('visibilityStatus', 'MISSING')}"
                    for guardrail in guardrails
                }
            )
            observation = {
                "assistant_arn": arn,
                "assistant_id": assistant_id,
                "guardrail_count": len(guardrails),
                "active_published_count": len(qualifying),
                "observed_states": states,
            }
            observations.append(observation)
            if not qualifying:
                uncovered.append(observation)

        limitation = (
            "ListAIGuardrails proves assistant-scoped availability only; it does not prove "
            "attachment to or enforcement by every AI agent, or which content/PII filters are "
            "configured. Review those controls separately."
        )
        evidence = {
            "assistants_checked": len(assistant_arns),
            "assistant_guardrail_observations": observations,
            "evidence_limitation": limitation,
        }
        if not uncovered:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="QConnectAssistant",
                description=(
                    f"All {len(assistant_arns)} Q in Connect assistant(s) expose at least one "
                    f"ACTIVE and PUBLISHED AI guardrail. {limitation}"
                ),
                evidence=evidence,
            )

        evidence["assistants_without_active_published_guardrail"] = uncovered
        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="QConnectAssistant",
            description=(
                f"{len(uncovered)} of {len(assistant_arns)} Q in Connect assistant(s) do not "
                "expose an AI guardrail that is both ACTIVE and PUBLISHED. Saved drafts and "
                "guardrails that are creating, failed, deleting, or deleted do not count as "
                f"published-active coverage. {limitation}"
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary=(
                    "Create or repair and publish an AI guardrail, then separately verify its "
                    "agent attachment and filter configuration."
                ),
                target_resources=[item["assistant_arn"] for item in uncovered],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "For each flagged assistant, create or repair an AI guardrail and "
                            "publish it so ListAIGuardrails reports ACTIVE/PUBLISHED."
                        ),
                        console_path=(
                            "Connect Customer admin website -> AI agent designer -> AI guardrails"
                        ),
                    ),
                    RemediationStep(
                        order=2,
                        instruction=(
                            "Separately review AI-agent orchestration attachment and configure "
                            "content, denied-topic, word, and sensitive-information filters for "
                            "the workload's requirements; this list API does not verify them."
                        ),
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Create AI guardrails for AI agents",
                        url=(
                            "https://docs.aws.amazon.com/connect/latest/adminguide/"
                            "create-ai-guardrails.html"
                        ),
                    )
                ],
            ),
        )


class QConnectEncryptionCheck(BaseCheck):
    """Check Q in Connect assistant and knowledge-base customer-managed encryption."""

    def __init__(self) -> None:
        super().__init__(
            check_id="ai-ops-encryption-001",
            name="Q in Connect Customer-Managed Key Encryption",
            pillar=Pillar.SECURITY,
            severity=Severity.MEDIUM,
            description=(
                "Checks whether associated Q in Connect assistants and knowledge bases report a "
                "customer-managed KMS key in their server-side encryption configuration."
            ),
        )

    def execute(self, context: CheckContext) -> Finding:
        instance = context.instance
        factory = context.aws_client_factory
        try:
            assistant_arns = _list_assistant_arns(factory, instance.instance_id)
            knowledge_base_arns = _list_knowledge_base_arns(factory, instance.instance_id)
        except _IncompleteCollectionError as error:
            return _skipped_for_incomplete_collection(
                self, context, error, "connect:ListIntegrationAssociations"
            )

        if not assistant_arns and not knowledge_base_arns:
            return self.not_applicable(
                context,
                "no Q in Connect assistant or knowledge-base integration was found",
                evidence={"assistant_count": 0, "knowledge_base_count": 0},
            )

        unencrypted: List[Dict[str, str]] = []
        checked = 0
        resources = [
            (
                "assistant",
                arn,
                factory.get_qconnect_assistant_resilient,
                "assistant",
                "wisdom:GetAssistant",
            )
            for arn in assistant_arns
        ] + [
            (
                "knowledge_base",
                arn,
                factory.get_qconnect_knowledge_base_resilient,
                "knowledgeBase",
                "wisdom:GetKnowledgeBase",
            )
            for arn in knowledge_base_arns
        ]

        for resource_type, arn, getter, response_key, permission in resources:
            try:
                response = getter(_id_from_arn(arn))
            except Exception as error:  # noqa: BLE001 - converted to a finding
                return _skipped_for_detail_error(
                    self,
                    context,
                    error,
                    permission,
                    permission,
                    {"resources_checked": checked, "resource_arn": arn},
                )
            resource = response.get(response_key)
            if not isinstance(resource, dict):
                return self.create_finding(
                    status=CheckStatus.SKIPPED,
                    resource_id=instance.instance_id,
                    resource_type="QConnectResource",
                    description=(
                        f"Skipped: {permission} returned no {response_key} object, so encryption "
                        "configuration could not be evaluated completely."
                    ),
                    evidence={"operation": permission, "resources_checked": checked},
                )
            checked += 1
            encryption = resource.get("serverSideEncryptionConfiguration") or {}
            if not encryption.get("kmsKeyId"):
                unencrypted.append({"resource_type": resource_type, "resource_arn": arn})

        if not unencrypted:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="QConnectResource",
                description=(
                    f"All {checked} associated Q in Connect resource(s) report a customer-managed "
                    "KMS key."
                ),
                evidence={"resources_checked": checked},
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="QConnectResource",
            description=(
                f"{len(unencrypted)} of {checked} associated Q in Connect resource(s) do not "
                "report a customer-managed KMS key and rely on AWS-owned encryption instead."
            ),
            evidence={"resources_checked": checked, "unencrypted_resources": unencrypted},
            structured_remediation=Remediation(
                summary="Recreate flagged Q in Connect resources with a customer-managed KMS key.",
                target_resources=[item["resource_arn"] for item in unencrypted],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "Choose a customer-managed KMS key with a policy that permits the "
                            "required Q in Connect use."
                        ),
                        console_path="AWS KMS console -> Customer managed keys",
                    ),
                    RemediationStep(
                        order=2,
                        instruction=(
                            "Recreate each flagged resource with the key ARN in "
                            "serverSideEncryptionConfiguration.kmsKeyId; this setting is selected "
                            "when the resource is created."
                        ),
                    ),
                ],
            ),
        )


class KnowledgeBaseSyncHealthCheck(BaseCheck):
    """Evaluate Q in Connect knowledge-base lifecycle and ingestion independently."""

    def __init__(self) -> None:
        super().__init__(
            check_id="ai-ops-kb-sync-001",
            name="Q in Connect Knowledge Base Lifecycle and Ingestion Health",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            severity=Severity.MEDIUM,
            description=(
                "Checks the separate lifecycle status and ingestionStatus returned by "
                "wisdom:GetKnowledgeBase. ACTIVE lifecycle alone is not treated as proof of "
                "successful ingestion."
            ),
        )

    def execute(self, context: CheckContext) -> Finding:
        instance = context.instance
        factory = context.aws_client_factory
        try:
            knowledge_base_arns = _list_knowledge_base_arns(factory, instance.instance_id)
        except _IncompleteCollectionError as error:
            return _skipped_for_incomplete_collection(
                self, context, error, "connect:ListIntegrationAssociations"
            )

        if not knowledge_base_arns:
            return self.not_applicable(
                context,
                "no Q in Connect knowledge-base integration was found",
                evidence={"knowledge_base_count": 0},
            )

        observations: List[Dict[str, Any]] = []
        failed: List[Dict[str, Any]] = []
        incomplete: List[Dict[str, Any]] = []
        for index, arn in enumerate(knowledge_base_arns):
            try:
                response = factory.get_qconnect_knowledge_base_resilient(_id_from_arn(arn))
            except Exception as error:  # noqa: BLE001 - converted to a finding
                return _skipped_for_detail_error(
                    self,
                    context,
                    error,
                    "wisdom:GetKnowledgeBase",
                    "wisdom:GetKnowledgeBase",
                    {"knowledge_bases_checked": index, "knowledge_base_arn": arn},
                )

            knowledge_base = response.get("knowledgeBase")
            if not isinstance(knowledge_base, dict):
                return self.create_finding(
                    status=CheckStatus.SKIPPED,
                    resource_id=instance.instance_id,
                    resource_type="QConnectKnowledgeBase",
                    description=(
                        "Skipped: wisdom:GetKnowledgeBase returned no knowledgeBase object, so "
                        "lifecycle and ingestion health could not be evaluated completely."
                    ),
                    evidence={"knowledge_bases_checked": index, "knowledge_base_arn": arn},
                )

            lifecycle_status = knowledge_base.get("status")
            ingestion_status = knowledge_base.get("ingestionStatus")
            observation = {
                "knowledge_base_arn": arn,
                "name": knowledge_base.get("name", ""),
                "status": lifecycle_status,
                "ingestion_status": ingestion_status,
                "ingestion_failure_reasons": _safe_failure_reasons(
                    knowledge_base.get("ingestionFailureReasons")
                ),
            }
            observations.append(observation)

            if (
                lifecycle_status in _KB_FAILED_LIFECYCLE_STATUSES
                or ingestion_status == "SYNC_FAILED"
            ):
                failed.append(observation)
            elif lifecycle_status != "ACTIVE" or ingestion_status != "SYNC_SUCCESS":
                incomplete.append(observation)

        evidence = {
            "knowledge_bases_checked": len(observations),
            "knowledge_base_observations": observations,
        }
        if failed:
            evidence["failed_knowledge_bases"] = failed
            if incomplete:
                evidence["incomplete_knowledge_bases"] = incomplete
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="QConnectKnowledgeBase",
                description=(
                    f"{len(failed)} of {len(observations)} knowledge base(s) report a terminal "
                    "lifecycle failure (CREATE_FAILED/DELETE_FAILED) or ingestion SYNC_FAILED. "
                    "Lifecycle and ingestion are evaluated separately; failure reasons are "
                    "included in bounded evidence."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Repair failed knowledge-base lifecycle or ingestion operations.",
                    target_resources=[item["knowledge_base_arn"] for item in failed],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Review the recorded lifecycle status, ingestionStatus, and "
                                "bounded ingestion failure reasons for each flagged knowledge base."
                            ),
                            console_path=(
                                "Connect Customer admin website -> Knowledge -> Knowledge bases"
                            ),
                        ),
                        RemediationStep(
                            order=2,
                            instruction=(
                                "Repair source connectivity and IAM access. Recreate resources "
                                "that remain in a terminal lifecycle failure after the cause is fixed."
                            ),
                        ),
                    ],
                ),
            )

        if incomplete:
            evidence["incomplete_knowledge_bases"] = incomplete
            return self.create_finding(
                status=CheckStatus.SKIPPED,
                resource_id=instance.instance_id,
                resource_type="QConnectKnowledgeBase",
                description=(
                    f"Insufficient data for {len(incomplete)} knowledge base(s): lifecycle or "
                    "ingestion is transient, inactive, unknown, or absent. ACTIVE lifecycle "
                    "without ingestionStatus=SYNC_SUCCESS is not an unqualified pass."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="QConnectKnowledgeBase",
            description=(
                f"All {len(observations)} knowledge base(s) report lifecycle ACTIVE and separate "
                "ingestionStatus SYNC_SUCCESS."
            ),
            evidence=evidence,
        )


class AIPromptModelCostCheck(BaseCheck):
    """Flag assistant-scoped AI prompts that select premium model families."""

    def __init__(self) -> None:
        super().__init__(
            check_id="ai-ops-model-cost-001",
            name="AI Prompt Model Cost Review",
            pillar=Pillar.COST_OPTIMIZATION,
            severity=Severity.LOW,
            description=(
                "Reviews model IDs reported by wisdom:ListAIPrompts and flags premium model "
                "families for workload-specific cost and quality testing."
            ),
        )

    def execute(self, context: CheckContext) -> Finding:
        instance = context.instance
        factory = context.aws_client_factory
        try:
            assistant_arns = _list_assistant_arns(factory, instance.instance_id)
        except _IncompleteCollectionError as error:
            return _skipped_for_incomplete_collection(
                self, context, error, "connect:ListIntegrationAssociations"
            )

        if not assistant_arns:
            return self.not_applicable(
                context,
                "no Q in Connect assistant integration was found",
                evidence={"assistant_count": 0},
            )

        prompts: List[Dict[str, str]] = []
        for assistant_index, arn in enumerate(assistant_arns):
            assistant_id = _id_from_arn(arn)
            try:
                summaries = _list_prompts(factory, assistant_id)
            except _IncompleteCollectionError as error:
                return _skipped_for_incomplete_collection(
                    self,
                    context,
                    error,
                    "wisdom:ListAIPrompts",
                    {"assistant_id": assistant_id, "assistants_evaluated": assistant_index},
                )
            prompts.extend(
                {
                    "assistant_arn": arn,
                    "prompt_name": str(summary.get("name") or ""),
                    "model_id": str(summary.get("modelId") or ""),
                }
                for summary in summaries
            )

        if not prompts:
            return self.not_applicable(
                context,
                "no AI prompts were returned for the associated Q in Connect assistant(s)",
                resource_type="QConnectAssistant",
                evidence={"assistants_checked": len(assistant_arns), "prompt_count": 0},
            )

        premium_prompts = [
            prompt
            for prompt in prompts
            if any(hint in prompt["model_id"].lower() for hint in _PREMIUM_MODEL_HINTS)
        ]
        evidence = {"prompts_checked": len(prompts), "premium_model_prompts": premium_prompts}
        if not premium_prompts:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="QConnectAssistant",
                description=(
                    f"None of the {len(prompts)} AI prompt(s) reports a model ID matching the "
                    "premium-model review hints."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="QConnectAssistant",
            description=(
                f"{len(premium_prompts)} of {len(prompts)} AI prompt(s) report a premium-family "
                "model ID. This is a review signal, not a recommendation to change models without "
                "quality testing against representative conversations."
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary="Test lower-cost models for premium-model prompts where quality permits.",
                target_resources=[prompt["prompt_name"] for prompt in premium_prompts],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "Compare each flagged prompt against a lower-cost model using "
                            "representative conversations and retain the premium model when its "
                            "quality is required."
                        ),
                        console_path=(
                            "Connect Customer admin website -> AI agent designer -> AI prompts"
                        ),
                    )
                ],
                applies_if="the prompt's measured quality remains acceptable on a lower-cost model.",
            ),
        )


class BedrockInvocationLoggingCheck(BaseCheck):
    """Review regional Bedrock invocation logging only for Q-enabled instances."""

    def __init__(self) -> None:
        super().__init__(
            check_id="ai-ops-bedrock-logging-001",
            name="Bedrock Model Invocation Logging",
            pillar=Pillar.OPERATIONAL_EXCELLENCE,
            severity=Severity.MEDIUM,
            description=(
                "For a Connect instance with a Q assistant integration, checks the account/region "
                "Bedrock model invocation logging configuration. This setting is regional and is "
                "not proof of per-assistant log delivery."
            ),
        )

    def execute(self, context: CheckContext) -> Finding:
        instance = context.instance
        factory = context.aws_client_factory
        try:
            assistant_arns = _list_assistant_arns(factory, instance.instance_id)
        except _IncompleteCollectionError as error:
            return _skipped_for_incomplete_collection(
                self, context, error, "connect:ListIntegrationAssociations"
            )

        if not assistant_arns:
            return self.not_applicable(
                context,
                "no Q in Connect assistant integration was found; Bedrock settings were not read",
                evidence={"assistant_count": 0, "bedrock_api_called": False},
            )

        try:
            response = factory.get_model_invocation_logging_configuration_resilient()
        except Exception as error:  # noqa: BLE001 - converted to a finding
            return _skipped_for_detail_error(
                self,
                context,
                error,
                "bedrock:GetModelInvocationLoggingConfiguration",
                "bedrock:GetModelInvocationLoggingConfiguration",
                {"assistant_count": len(assistant_arns)},
            )

        logging_config = response.get("loggingConfig") or {}
        has_cloudwatch = bool(logging_config.get("cloudWatchConfig"))
        has_s3 = bool(logging_config.get("s3Config"))
        evidence = {
            "assistant_count": len(assistant_arns),
            "has_cloudwatch_destination": has_cloudwatch,
            "has_s3_destination": has_s3,
            "text_data_delivery_enabled": bool(logging_config.get("textDataDeliveryEnabled")),
            "evidence_limitation": (
                "The API reports an account/region setting; it does not prove that every Q in "
                "Connect invocation is delivered to the destination."
            ),
        }
        if has_cloudwatch or has_s3:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "Bedrock model invocation logging has at least one account/region destination "
                    "configured. The setting is regional and does not prove per-assistant delivery."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                "A Q in Connect assistant integration exists, but the regional Bedrock model "
                "invocation logging configuration has no CloudWatch Logs or S3 destination."
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary="Configure a regional Bedrock model invocation logging destination.",
                target_resources=[instance.instance_id],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "Configure CloudWatch Logs, S3, or both as Bedrock model invocation "
                            "logging destinations and select the data types required by policy."
                        ),
                        console_path=(
                            "Bedrock console -> Bedrock configurations -> Settings -> "
                            "Model invocation logging"
                        ),
                    )
                ],
            ),
        )


class CrossRegionInferenceAvailabilityCheck(BaseCheck):
    """Report system-defined inference-profile availability for Q-enabled instances."""

    def __init__(self) -> None:
        super().__init__(
            check_id="ai-ops-cross-region-001",
            name="Bedrock Cross-Region Inference Availability",
            pillar=Pillar.RESILIENCE,
            severity=Severity.LOW,
            description=(
                "For a Connect instance with a Q assistant integration, reports the regional "
                "inventory of system-defined Bedrock inference profiles as planning context. It "
                "does not prove a Q workload uses a profile."
            ),
        )

    def execute(self, context: CheckContext) -> Finding:
        instance = context.instance
        factory = context.aws_client_factory
        try:
            assistant_arns = _list_assistant_arns(factory, instance.instance_id)
        except _IncompleteCollectionError as error:
            return _skipped_for_incomplete_collection(
                self, context, error, "connect:ListIntegrationAssociations"
            )

        if not assistant_arns:
            return self.not_applicable(
                context,
                "no Q in Connect assistant integration was found; Bedrock settings were not read",
                evidence={"assistant_count": 0, "bedrock_api_called": False},
            )

        try:
            profiles = _list_inference_profiles(factory)
        except _IncompleteCollectionError as error:
            return _skipped_for_incomplete_collection(
                self,
                context,
                error,
                "bedrock:ListInferenceProfiles",
                {"assistant_count": len(assistant_arns)},
            )

        profile_ids = sorted(
            str(profile.get("inferenceProfileId") or profile.get("inferenceProfileArn") or "")
            for profile in profiles
        )
        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Found {len(profiles)} system-defined Bedrock inference profile(s) in the "
                "account/region. This is availability context only and does not prove that the "
                "associated Q in Connect workload uses cross-region inference."
            ),
            evidence={
                "assistant_count": len(assistant_arns),
                "cross_region_profile_count": len(profiles),
                "inference_profile_ids": profile_ids,
                "evidence_limitation": (
                    "ListInferenceProfiles reports regional availability, not Q in Connect usage."
                ),
            },
        )


def register_ai_ops_maturity_checks(registry: Any) -> None:
    """Register the six instance-level AI operations maturity checks."""
    registry.register_check(AIGuardrailCoverageCheck())
    registry.register_check(QConnectEncryptionCheck())
    registry.register_check(KnowledgeBaseSyncHealthCheck())
    registry.register_check(AIPromptModelCostCheck())
    registry.register_check(BedrockInvocationLoggingCheck())
    registry.register_check(CrossRegionInferenceAvailabilityCheck())
