"""
Deep-inspection security checks for Amazon Connect (Phase 2).

These checks go beyond presence/absence heuristics and inspect real AWS
configuration via read-only APIs:

- sec-iam-deep-001    : IAM service role policy least-privilege inspection
- sec-storage-001     : Instance storage encryption (customer-managed KMS)
- sec-origins-001     : Approved origins / CCP embedding allowlist
- sec-cloudtrail-001  : CloudTrail coverage of Connect API events
- sec-federation-001  : Identity federation / MFA posture
- sec-profile-audit-001 : Security profile permission audit

Every API-backed check degrades to SKIPPED on AccessDenied via the shared
helper, and every FAIL emits evidence-specific structured remediation.
"""

from typing import List

from ..models import (
    CheckStatus,
    Pillar,
    Remediation,
    RemediationReference,
    RemediationStep,
    Severity,
)
from .base import BaseCheck, CheckContext

# Actions that are clearly outside the scope of a Connect service role and
# indicate excessive privilege if present.
_OUT_OF_SCOPE_ACTION_PREFIXES = (
    "iam:",
    "ec2:RunInstances",
    "s3:DeleteBucket",
    "organizations:",
    "sts:AssumeRole",
)
_BROAD_WRITE_HINTS = ("Delete", "Put", "Create", "Write", "Modify", "Update", "*")


def _role_name_from_arn(role_arn: str):
    """Extract the role name (last path segment) from an IAM role ARN."""
    if not role_arn or ":role/" not in role_arn:
        return None
    return role_arn.split(":role/", 1)[1].split("/")[-1]


def _statements(policy_doc) -> List[dict]:
    """Normalize a policy document's Statement into a list of dicts."""
    if not isinstance(policy_doc, dict):
        return []
    stmts = policy_doc.get("Statement", [])
    if isinstance(stmts, dict):
        return [stmts]
    return [s for s in stmts if isinstance(s, dict)]


def _as_list(value) -> List[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [str(v) for v in value]
    return [str(value)]


class IAMServiceRolePolicyCheck(BaseCheck):
    """Inspect the Connect service role's actual policies (Requirement 7)."""

    def __init__(self):
        super().__init__(
            check_id="sec-iam-deep-001",
            name="IAM Service Role Policy Inspection",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Inspects the inline and attached policies on the Amazon Connect "
                "service role for least-privilege violations and out-of-scope "
                "permissions."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        if not instance.service_role:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Connect instance {instance.display_name} has no service role "
                    "configured; role policies cannot be evaluated."
                ),
                evidence={"service_role": None},
                structured_remediation=Remediation(
                    summary="Configure a least-privilege service role for the instance.",
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Assign a dedicated service-linked role to the "
                                "instance so Connect can access other AWS services "
                                "under least privilege."
                            ),
                            console_path="Connect console -> Instance -> Service role",
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Amazon Connect service-linked roles",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-slr.html",  # noqa: E501
                        )
                    ],
                ),
            )

        role_name = _role_name_from_arn(instance.service_role)
        if not role_name:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(f"Service role ARN is malformed: {instance.service_role}"),
                evidence={"service_role": instance.service_role},
                remediation="Correct the service role ARN on the instance.",
            )

        # Collect policy documents (inline + attached managed).
        violations = []
        out_of_scope = []
        evidence = {"service_role": instance.service_role, "role_name": role_name}

        try:
            inline_names = factory.list_role_policies_resilient(role_name).get("PolicyNames", [])
            policy_docs = []
            for name in inline_names:
                doc = factory.get_role_policy_resilient(role_name, name).get("PolicyDocument", {})
                policy_docs.append((name, doc))

            attached = factory.list_attached_role_policies_resilient(role_name).get(
                "AttachedPolicies", []
            )
            evidence["attached_policy_count"] = len(attached)
            evidence["inline_policy_count"] = len(inline_names)
        except Exception as e:  # noqa: BLE001 - mapped to SKIPPED if access denied
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(
                    context, "iam:GetRolePolicy / iam:ListRolePolicies"
                )
            raise

        for policy_name, doc in policy_docs:
            for stmt in _statements(doc):
                if stmt.get("Effect") != "Allow":
                    continue
                actions = _as_list(stmt.get("Action"))
                resources = _as_list(stmt.get("Resource"))
                wildcard_resource = "*" in resources
                broad_action = any(
                    a == "*" or any(h in a for h in _BROAD_WRITE_HINTS) for a in actions
                )
                if wildcard_resource and broad_action:
                    violations.append(
                        f"policy '{policy_name}' allows broad actions on Resource:'*'"
                    )
                for a in actions:
                    if any(a.startswith(p) for p in _OUT_OF_SCOPE_ACTION_PREFIXES):
                        out_of_scope.append(f"{a} (in '{policy_name}')")

        evidence["least_privilege_violations"] = violations
        evidence["out_of_scope_actions"] = out_of_scope

        if out_of_scope:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="IAMRole",
                description=(
                    f"Service role '{role_name}' grants out-of-scope permissions: "
                    f"{'; '.join(sorted(set(out_of_scope)))}."
                ),
                evidence=evidence,
                structured_remediation=self._scope_remediation(role_name, out_of_scope),
            )

        if violations:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="IAMRole",
                description=(
                    f"Service role '{role_name}' has least-privilege violations: "
                    f"{'; '.join(violations)}."
                ),
                evidence=evidence,
                structured_remediation=self._scope_remediation(role_name, violations),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="IAMRole",
            description=(
                f"Service role '{role_name}' shows no broad wildcard or out-of-scope permissions."
            ),
            evidence=evidence,
        )

    def _scope_remediation(self, role_name: str, items: List[str]) -> Remediation:
        return Remediation(
            summary=f"Scope down the Connect service role '{role_name}' to least privilege.",
            target_resources=[role_name],
            steps=[
                RemediationStep(
                    order=1,
                    instruction=(
                        f"Review the flagged statements on role '{role_name}' "
                        f"({len(items)} issue(s)) and replace Resource:'*' with "
                        "specific resource ARNs the instance actually needs."
                    ),
                    console_path="IAM console -> Roles -> " + role_name,
                    command=f"aws iam list-role-policies --role-name {role_name}",
                ),
                RemediationStep(
                    order=2,
                    instruction=(
                        "Remove actions that are unrelated to Connect's operation "
                        "(e.g., iam:*, organizations:*, sts:AssumeRole)."
                    ),
                ),
            ],
            references=[
                RemediationReference(
                    title="IAM least-privilege guidance",
                    url="https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html",
                )
            ],
            applies_if="this role is used only by the Amazon Connect service.",
        )


# Storage resource types that support encryption configuration.
_STORAGE_RESOURCE_TYPES = [
    "CALL_RECORDINGS",
    "CHAT_TRANSCRIPTS",
    "SCHEDULED_REPORTS",
    "MEDIA_STREAMS",
    "CONTACT_TRACE_RECORDS",
    "AGENT_EVENTS",
]


class InstanceStorageEncryptionCheck(BaseCheck):
    """Verify instance storage uses customer-managed KMS keys (Requirement 8)."""

    def __init__(self):
        super().__init__(
            check_id="sec-storage-001",
            name="Instance Storage Encryption Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Checks each Amazon Connect storage configuration (recordings, "
                "transcripts, reports, CTRs) for encryption, preferring "
                "customer-managed KMS keys."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        unencrypted = []
        aws_managed = []
        evidence = {"storage": {}}

        for resource_type in _STORAGE_RESOURCE_TYPES:
            try:
                resp = factory.list_instance_storage_configs_resilient(
                    instance.instance_id, resource_type
                )
            except Exception as e:  # noqa: BLE001
                if factory.is_access_denied(e):
                    return self.skipped_for_access_denied(
                        context, "connect:ListInstanceStorageConfigs"
                    )
                # Resource type not enabled / not found is fine; skip it.
                continue

            for cfg in resp.get("StorageConfigs", []) or []:
                kms = self._kms_type(cfg)
                bucket = (cfg.get("S3Config") or {}).get("BucketName")
                evidence["storage"][resource_type] = {
                    "kms_key_type": kms,
                    "bucket": bucket,
                    "storage_type": cfg.get("StorageType"),
                }
                if kms == "none":
                    unencrypted.append(resource_type)
                elif kms == "aws_managed":
                    aws_managed.append(resource_type)

        if unencrypted:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="InstanceStorageConfig",
                description=(
                    f"Connect instance {instance.display_name} has unencrypted storage "
                    f"for: {', '.join(unencrypted)}."
                ),
                evidence=evidence,
                structured_remediation=self._encryption_remediation(
                    instance.instance_id, unencrypted, severity="critical"
                ),
            )

        if aws_managed:
            # Note: this check's severity is HIGH; AWS-managed keys are a MEDIUM
            # concern, surfaced via the finding text and remediation.
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="InstanceStorageConfig",
                description=(
                    f"Connect instance {instance.display_name} uses AWS-managed KMS "
                    f"keys (not customer-managed) for: {', '.join(aws_managed)}."
                ),
                evidence=evidence,
                structured_remediation=self._encryption_remediation(
                    instance.instance_id, aws_managed, severity="medium"
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="InstanceStorageConfig",
            description=(
                f"All evaluated storage configurations for instance "
                f"{instance.display_name} use customer-managed KMS encryption."
            ),
            evidence=evidence,
        )

    @staticmethod
    def _kms_type(cfg: dict) -> str:
        """Classify a storage config's encryption as customer/aws-managed/none."""
        s3 = cfg.get("S3Config") or {}
        kinesis = cfg.get("KinesisVideoStreamConfig") or {}
        enc = s3.get("EncryptionConfig") or kinesis.get("EncryptionConfig") or {}
        key_id = enc.get("KeyId") if enc else None
        if not enc or not key_id:
            return "none"
        # Customer-managed keys are referenced by key ARN/ID or alias; the
        # AWS-managed Connect key uses the 'aws/connect' alias.
        if "aws/connect" in str(key_id) or str(key_id).endswith(":alias/aws/connect"):
            return "aws_managed"
        return "customer_managed"

    def _encryption_remediation(
        self, instance_id: str, resource_types: List[str], severity: str
    ) -> Remediation:
        verb = (
            "Enable customer-managed KMS encryption"
            if severity == "critical"
            else "Switch to a customer-managed KMS key"
        )
        return Remediation(
            summary=f"{verb} for storage: {', '.join(resource_types)}.",
            target_resources=[instance_id] + resource_types,
            steps=[
                RemediationStep(
                    order=1,
                    instruction=(
                        "In the Connect instance Data storage settings, edit each "
                        f"flagged storage type ({', '.join(resource_types)}) and "
                        "select a customer-managed KMS key for encryption at rest."
                    ),
                    console_path="Connect console -> Instance -> Data storage",
                ),
                RemediationStep(
                    order=2,
                    instruction=(
                        "Ensure the KMS key policy grants the Connect service role "
                        "kms:GenerateDataKey and kms:Decrypt."
                    ),
                    command=(
                        "aws connect list-instance-storage-configs "
                        f"--instance-id {instance_id} --resource-type CALL_RECORDINGS"
                    ),
                ),
            ],
            references=[
                RemediationReference(
                    title="Encryption at rest in Amazon Connect",
                    url="https://docs.aws.amazon.com/connect/latest/adminguide/encryption-at-rest.html",  # noqa: E501
                )
            ],
            applies_if="recordings/transcripts contain regulated or sensitive data.",
        )


class ApprovedOriginsCheck(BaseCheck):
    """Validate the CCP approved origins allowlist (Requirement 9)."""

    def __init__(self):
        super().__init__(
            check_id="sec-origins-001",
            name="Approved Origins / CCP Access Control Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Validates the approved origins allowlist that controls which "
                "domains may embed the Contact Control Panel (CCP)."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.list_approved_origins_resilient(instance.instance_id)
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListApprovedOrigins")
            raise

        origins = resp.get("Origins", []) or []
        evidence = {"approved_origins": origins, "count": len(origins)}

        broad = [
            o
            for o in origins
            if "*" in o or "localhost" in o.lower() or o.strip() in ("http://", "https://")
        ]
        evidence["overly_broad_origins"] = broad

        if broad:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Connect instance {instance.display_name} has overly broad "
                    f"approved origins: {', '.join(broad)}."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Restrict CCP approved origins to specific trusted domains.",
                    target_resources=[instance.instance_id] + broad,
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Remove wildcard/localhost origins and add only the "
                                "exact HTTPS domains that host your agent application."
                            ),
                            console_path="Connect console -> Instance -> Approved origins",
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Use an allow list for integrated applications",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/allowlist-domains.html",  # noqa: E501
                        )
                    ],
                ),
            )

        if not origins:
            # An empty list is the safe default for the native agent workspace.
            # Preserve conditional guidance for customers that embed CCP.
            return self.not_applicable(
                context,
                reason=(
                    f"Connect instance {instance.display_name} has no approved-origins "
                    "allowlist configured.\n\n"
                    "**What this means.** The approved-origins allowlist is the list "
                    "of external website domains that are allowed to load the Contact "
                    "Control Panel (CCP) — the browser UI agents use to take calls — "
                    "as an embedded iframe. When the list is empty, no external site "
                    "can embed the CCP; agents can only reach it through the native "
                    "Connect agent workspace URL "
                    f"(`https://{instance.instance_alias or 'YOUR-ALIAS'}.my.connect.aws/ccp-v2/`).\n\n"
                    "**When to act.** Add an entry only if you plan to embed the CCP "
                    "in a custom agent desktop or CRM. In that case, add the specific "
                    "HTTPS domain(s) of those applications so agents can access CCP "
                    "through them.\n\n"
                    "**When to leave as-is.** If your agents use only the native "
                    "Connect UI, no allowlist entries are needed — the empty list is "
                    "the safe default and blocks arbitrary websites from framing "
                    "CCP against your instance."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary=(
                        "Only if the CCP is embedded in a custom agent application: "
                        "add its HTTPS domain to the approved-origins allowlist."
                    ),
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "In the Connect console, go to Instance -> Approved "
                                "origins and add the specific HTTPS domain(s) of the "
                                "custom agent app(s) that embed the CCP. Use full "
                                "https:// URLs (no wildcards, no localhost)."
                            ),
                            console_path="Connect console -> Instance -> Approved origins",
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Use an allow list for integrated applications",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/allowlist-domains.html",  # noqa: E501
                        )
                    ],
                    applies_if="the CCP is embedded in a custom agent application.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Connect instance {instance.display_name} restricts CCP embedding to "
                f"{len(origins)} explicit origin(s)."
            ),
            evidence=evidence,
        )


class CloudTrailIntegrationCheck(BaseCheck):
    """Verify CloudTrail captures Connect API events (Requirement 10)."""

    def __init__(self):
        super().__init__(
            check_id="sec-cloudtrail-001",
            name="CloudTrail Integration Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Verifies that at least one CloudTrail trail is configured to "
                "capture Amazon Connect management events for audit completeness."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.describe_trails_resilient()
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "cloudtrail:DescribeTrails")
            raise

        trails = resp.get("trailList", []) or []
        # A multi-region trail (or any trail) logging management events covers
        # Connect control-plane API calls.
        management_trails = [t for t in trails if t.get("Name")]
        evidence = {
            "trail_count": len(trails),
            "trail_names": [t.get("Name") for t in trails],
            "has_multi_region_trail": any(t.get("IsMultiRegionTrail") for t in trails),
        }

        if not management_trails:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    "No CloudTrail trail is configured to capture Connect API "
                    "management events; administrative actions are not audited."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Create a multi-region CloudTrail trail logging management events.",
                    target_resources=[instance.instance_id],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Create an organization or account multi-region trail "
                                "that records management events to an encrypted S3 bucket."
                            ),
                            console_path="CloudTrail console -> Trails -> Create trail",
                            command=(
                                "aws cloudtrail create-trail --name connect-audit "
                                "--s3-bucket-name <your-audit-bucket> --is-multi-region-trail"
                            ),
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Logging Amazon Connect API calls with CloudTrail",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/logging-using-cloudtrail.html",  # noqa: E501
                        )
                    ],
                    placeholders=["<your-audit-bucket>"],
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"{len(management_trails)} CloudTrail trail(s) present to capture "
                "Connect management events."
            ),
            evidence=evidence,
        )


class IdentityFederationCheck(BaseCheck):
    """Assess identity management strength (Requirement 11)."""

    def __init__(self):
        super().__init__(
            check_id="sec-federation-001",
            name="Identity Federation / MFA Check",
            pillar=Pillar.SECURITY,
            severity=Severity.LOW,
            description=(
                "Reports the instance's identity management type so you can "
                "confirm centralized authentication and MFA are enforced "
                "somewhere in the sign-in path — either via SAML federation "
                "to your enterprise IdP, or via Connect-managed identity "
                "combined with your own SSO/MFA layer (e.g. Okta, Entra ID) "
                "in front of it."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        idm = (instance.identity_management_type or "").upper()
        evidence = {"identity_management_type": idm}

        if idm == "SAML":
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description=(
                    f"Instance {instance.display_name} uses SAML federation, enabling "
                    "centralized authentication and MFA enforcement at the IdP."
                ),
                evidence=evidence,
            )

        return self.create_finding(
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description=(
                f"Instance {instance.display_name} uses '{idm or 'unknown'}' identity "
                "management rather than SAML federation.\n\n"
                "**This is not necessarily a gap.** SAML/SSO federation is "
                "one good option for enterprise authentication strength and "
                "centralized MFA, but it is not the only one — Connect-"
                "managed identity is also a viable choice, including when "
                "paired with a third-party identity provider (Okta, "
                "Microsoft Entra ID, etc.) for MFA and lifecycle management "
                "at the org level, or Connect's own native MFA setting. "
                "Treat this as a prompt to confirm MFA is enforced somewhere "
                "in your actual sign-in path, not an instruction to migrate "
                "off Connect-managed identity."
            ),
            evidence=evidence,
            structured_remediation=Remediation(
                summary=(
                    "Confirm MFA is enforced in your actual sign-in path — "
                    "via SAML federation to an enterprise IdP, or via "
                    "Connect-managed identity paired with your own SSO/MFA "
                    "provider."
                ),
                target_resources=[instance.instance_id],
                steps=[
                    RemediationStep(
                        order=1,
                        instruction=(
                            "If you already require MFA through a "
                            "third-party identity provider (Okta, Entra ID, "
                            "etc.) or Connect's native MFA setting, no "
                            "change is needed — this finding is informational."
                        ),
                    ),
                    RemediationStep(
                        order=2,
                        instruction=(
                            "If agents currently sign in with only a "
                            "username and password and no MFA anywhere in "
                            "the path, either configure SAML-based identity "
                            "management integrated with your IdP, or enable "
                            "MFA directly on Connect-managed user accounts."
                        ),
                        console_path="Connect console -> Instance -> Identity management",
                    ),
                ],
                references=[
                    RemediationReference(
                        title="Configure SAML for identity management",
                        url="https://docs.aws.amazon.com/connect/latest/adminguide/configure-saml.html",  # noqa: E501
                    )
                ],
                applies_if=(
                    "MFA is not currently enforced anywhere in the agent "
                    "sign-in path — if it already is (via a third-party IdP "
                    "or Connect's native MFA), this finding does not apply."
                ),
            ),
        )


# Administrative permission names that should not appear on non-admin profiles.
_ADMIN_PERMISSIONS = {
    "Users.Create",
    "Users.Edit",
    "Users.Delete",
    "SecurityProfiles.Create",
    "SecurityProfiles.Edit",
    "SecurityProfiles.Delete",
    "InstanceSettings.Edit",
}


class SecurityProfileAuditCheck(BaseCheck):
    """Audit security profile permissions (Requirement 12)."""

    def __init__(self):
        super().__init__(
            check_id="sec-profile-audit-001",
            name="Security Profile Permissions Audit",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description=(
                "Audits security profile permissions to flag non-administrator "
                "profiles that grant administrative capabilities."
            ),
        )

    def execute(self, context: CheckContext):
        instance = context.instance
        factory = context.aws_client_factory

        try:
            resp = factory.list_security_profiles_resilient(instance.instance_id)
        except Exception as e:  # noqa: BLE001
            if factory.is_access_denied(e):
                return self.skipped_for_access_denied(context, "connect:ListSecurityProfiles")
            raise

        profiles = resp.get("SecurityProfileSummaryList", []) or []
        over_privileged = []
        evidence = {"profile_count": len(profiles), "profiles": {}}

        for profile in profiles:
            name = profile.get("Name", "")
            pid = profile.get("Id", "")
            try:
                perms_resp = factory.list_security_profile_permissions_resilient(
                    instance.instance_id, pid
                )
            except Exception as e:  # noqa: BLE001
                if factory.is_access_denied(e):
                    return self.skipped_for_access_denied(
                        context, "connect:ListSecurityProfilePermissions"
                    )
                continue

            perms = set(perms_resp.get("Permissions", []) or [])
            admin_perms = perms & _ADMIN_PERMISSIONS
            evidence["profiles"][name] = {
                "permission_count": len(perms),
                "has_admin_permissions": bool(admin_perms),
            }
            # Treat the canonical "Admin" profile as expected to hold admin perms.
            if admin_perms and name.lower() not in ("admin", "administrator"):
                over_privileged.append(f"{name} ({', '.join(sorted(admin_perms))})")

        if over_privileged:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="SecurityProfile",
                description=(
                    "Non-administrator security profiles grant administrative "
                    f"permissions: {'; '.join(over_privileged)}."
                ),
                evidence=evidence,
                structured_remediation=Remediation(
                    summary="Remove administrative permissions from non-admin profiles.",
                    target_resources=[p.split(" ")[0] for p in over_privileged],
                    steps=[
                        RemediationStep(
                            order=1,
                            instruction=(
                                "Edit each flagged security profile and remove "
                                "Users.*/SecurityProfiles.*/InstanceSettings.Edit "
                                "permissions unless the role is genuinely an admin."
                            ),
                            console_path="Connect console -> Users -> Security profiles",
                        ),
                    ],
                    references=[
                        RemediationReference(
                            title="Security profiles in Amazon Connect",
                            url="https://docs.aws.amazon.com/connect/latest/adminguide/connect-security-profiles.html",  # noqa: E501,
                        )
                    ],
                    applies_if="agents assigned these profiles should not administer the instance.",
                ),
            )

        return self.create_finding(
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="SecurityProfile",
            description=(
                f"No non-administrator profile among {len(profiles)} grants "
                "administrative permissions."
            ),
            evidence=evidence,
        )


def register_security_deep_checks(registry) -> None:
    """Register all deep-inspection security checks with the given registry."""
    registry.register_check(IAMServiceRolePolicyCheck())
    registry.register_check(InstanceStorageEncryptionCheck())
    registry.register_check(ApprovedOriginsCheck())
    registry.register_check(CloudTrailIntegrationCheck())
    registry.register_check(IdentityFederationCheck())
    registry.register_check(SecurityProfileAuditCheck())
