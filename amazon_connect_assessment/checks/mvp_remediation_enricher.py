"""
Structured remediation enrichment for original MVP checks (Item 4).

The original 10 MVP checks use flat remediation_template strings. Rather than
rewriting those files (breaking backward compat), this module enriches their
FAIL findings with structured remediation post-execution.

Called by the engine after check execution for MVP check IDs.
"""

from ..models import (
    CheckStatus,
    Finding,
    Remediation,
    RemediationReference,
    RemediationStep,
)

# Map of MVP check_id -> function that produces a Remediation from a finding.
_ENRICHMENT_MAP = {}


def _register(check_id):
    def decorator(fn):
        _ENRICHMENT_MAP[check_id] = fn
        return fn

    return decorator


def enrich_finding(finding: Finding) -> Finding:
    """
    If the finding is from an MVP check and is a FAIL, enrich it with
    structured remediation derived from its evidence. Returns the same
    finding object (mutated) for convenience.
    """
    if finding.status != CheckStatus.FAIL:
        return finding
    if finding.structured_remediation is not None:
        return finding  # Already has structured remediation.
    enricher = _ENRICHMENT_MAP.get(finding.check_id)
    if enricher:
        finding.structured_remediation = enricher(finding)
    return finding


# --- Enrichers for each MVP check ---


@_register("security-iam-001")
def _iam_service_role(f: Finding) -> Remediation:
    return Remediation(
        summary=f"Configure a service role for instance {f.resource_id}.",
        target_resources=[f.resource_id],
        steps=[
            RemediationStep(
                order=1,
                instruction=(
                    "Assign a service-linked role to the Connect instance. "
                    "This is created automatically when the instance is "
                    "provisioned via the console."
                ),
                console_path="Connect console -> Instance overview",
            ),
        ],
        references=[
            RemediationReference(
                title="Amazon Connect service-linked roles",
                url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-slr.html",  # noqa: E501
            )
        ],
    )


# security-encryption-001 (EncryptionConfigurationCheck) and security-network-001
# (NetworkSecurityCheck) were removed as noise generators; see the
# security_checks.py module docstring for the rationale. Their remediation
# registrations were dropped alongside the checks themselves — remediation for
# storage encryption is now attached to sec-storage-001 directly, and identity
# posture is covered by sec-federation-001.


@_register("security-data-001")
def _data_protection(f: Finding) -> Remediation:
    return Remediation(
        summary="Address data protection gaps.",
        target_resources=[f.resource_id],
        steps=[
            RemediationStep(
                order=1,
                instruction=(
                    "Assign security profiles to all users and ensure "
                    "multiple role-based profiles exist (not just one)."
                ),
                console_path="Connect console -> Users -> Security profiles",
            ),
        ],
    )


@_register("resilience-multi-az-001")
def _multi_az(f: Finding) -> Remediation:
    return Remediation(
        summary=f"Resolve multi-AZ configuration issue for {f.resource_id}.",
        target_resources=[f.resource_id],
        steps=[
            RemediationStep(
                order=1,
                instruction=(
                    "Ensure the instance is ACTIVE with a service role "
                    "and at least one call direction enabled."
                ),
            ),
        ],
        applies_if="the instance is expected to handle production traffic.",
    )


@_register("resilience-dr-001")
def _dr(f: Finding) -> Remediation:
    return Remediation(
        summary="Implement DR planning for critical components.",
        target_resources=[f.resource_id],
        steps=[
            RemediationStep(
                order=1,
                instruction=(
                    "Export contact flows regularly (versioned backups). "
                    "Document queue and routing profile configurations."
                ),
            ),
            RemediationStep(
                order=2,
                instruction=(
                    "If this workload requires Regional (cross-region) "
                    "resilience, engage your AWS account team or schedule a "
                    "deep dive with an Amazon Connect specialist to evaluate "
                    "Amazon Connect Global Resiliency (ACGR). ACGR is not a "
                    "self-service configuration and should be planned with AWS."
                ),
            ),
        ],
        references=[
            RemediationReference(
                title="Disaster recovery and resiliency",
                url="https://docs.aws.amazon.com/connect/latest/adminguide/disaster-recovery-resiliency.html",  # noqa: E501
            )
        ],
    )


@_register("cost-unused-001")
def _unused_resources(f: Finding) -> Remediation:
    return Remediation(
        summary="Remove or consolidate unused resources.",
        target_resources=[f.resource_id],
        steps=[
            RemediationStep(
                order=1,
                instruction=(
                    "Deactivate users without routing profiles. "
                    "Remove routing profiles not assigned to any user. "
                    "Consolidate queues with no traffic."
                ),
            ),
        ],
        applies_if="resources are confirmed to be unused.",
    )


@_register("cost-oversized-001")
def _oversized(f: Finding) -> Remediation:
    return Remediation(
        summary="Right-size the Connect configuration.",
        target_resources=[f.resource_id],
        steps=[
            RemediationStep(
                order=1,
                instruction=(
                    "Consolidate security profiles with similar permissions. "
                    "Merge routing profiles serving the same queue set."
                ),
            ),
        ],
    )


@_register("cost-inefficient-001")
def _inefficient(f: Finding) -> Remediation:
    return Remediation(
        summary="Optimize resource allocation.",
        target_resources=[f.resource_id],
        steps=[
            RemediationStep(
                order=1,
                instruction=(
                    "Balance user-to-queue ratios. Assign routing profiles "
                    "to unassigned users. Remove unused integrations."
                ),
            ),
        ],
    )
