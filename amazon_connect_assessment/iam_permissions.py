"""Single source of truth for the IAM permissions the assessment requires.

Three artifacts are derived from this module so they can never silently drift:

1. ``docs/iam-policy-template.json`` — the standalone IAM policy a user
   attaches directly to their own IAM user or role. **Fully generated** from
   :func:`render_policy_json`; ``tests/test_iam_policy_consistency.py`` asserts
   the checked-in file matches byte-for-byte (run that test, or
   ``python -m amazon_connect_assessment.iam_permissions --write`` to refresh it).

2. ``cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`` — the same-account
   CloudFormation template. Its inline policy is hand-maintained (it carries
   CFN intrinsics, conditions, parameters, and outputs that don't round-trip
   through Python), but a drift test asserts every canonical action listed
   below is present in the template — and no strays.

3. :data:`REQUIRED_PERMISSIONS` — the minimal subset probed by
   ``amazon-connect-assessment --check-permissions``. ``AWSClientFactory``
   imports it from here; the drift test asserts it is a subset of the canonical
   action set.

To add a permission: add it to the relevant statement in
:data:`POLICY_STATEMENTS` (and to :data:`REQUIRED_PERMISSIONS` if the
``--check-permissions`` smoke test should probe it), then run the test suite,
which regenerates the JSON and re-checks all three artifacts.
"""

from __future__ import annotations

import json
from typing import Dict, List, Set, Union

POLICY_VERSION = "2012-10-17"

# Why several statements below use ``Resource: "*"``
# --------------------------------------------------
# Every action in this catalog is read-only, and the wildcard resources are not
# over-permissioning by omission — they are the tightest scope the underlying
# APIs support for how this tool is used:
#
#   * Account-wide discovery. The tool is a self-assessment that enumerates
#     *every* Connect instance in the account, so it cannot know an instance ARN
#     up front — ``connect:ListInstances`` (and the KMS/Lex/CloudTrail list
#     calls) are inherently ``"*"`` bootstrap operations.
#   * APIs with no resource-level authorization. AWS does not support
#     resource-level permissions for these read actions, so ``"*"`` is the only
#     value IAM accepts: cloudwatch:GetMetricData/GetMetricStatistics/ListMetrics/
#     DescribeAlarms(ForMetric), logs:Describe*, cloudtrail:LookupEvents/
#     GetTrailStatus/DescribeTrails, kms:ListKeys/ListAliases, and
#     sts:GetCallerIdentity.
#
# Statements that *can* be scoped are scoped (S3 to ``arn:aws:s3:::*`` bucket
# ARNs, Lambda to function ARNs, IAM to this account's role/policy ARNs). Each
# ``"*"`` statement below carries an inline note recording which of the two
# reasons applies, so the choice is auditable rather than inferred.


def _statement(sid: str, actions: List[str], resource: Union[str, List[str]]) -> Dict[str, object]:
    """Build one IAM statement with keys in the canonical JSON order."""
    return {
        "Sid": sid,
        "Effect": "Allow",
        "Action": list(actions),
        "Resource": resource,
    }


# Canonical policy statements. Order and key order here define the generated
# docs/iam-policy-template.json exactly, so edit deliberately.
POLICY_STATEMENTS: List[Dict[str, object]] = [
    _statement(
        "AmazonConnectReadOnlyAccess",
        [
            "connect:ListInstances",
            "connect:DescribeInstance",
            "connect:ListContactFlows",
            "connect:DescribeContactFlow",
            "connect:ListQueues",
            "connect:DescribeQueue",
            "connect:ListRoutingProfiles",
            "connect:DescribeRoutingProfile",
            "connect:ListUsers",
            "connect:DescribeUser",
            "connect:ListSecurityProfiles",
            "connect:DescribeSecurityProfile",
            "connect:ListPhoneNumbers",
            "connect:DescribePhoneNumber",
            "connect:ListHoursOfOperations",
            "connect:DescribeHoursOfOperation",
            "connect:ListPrompts",
            "connect:DescribePrompt",
            "connect:ListQuickConnects",
            "connect:DescribeQuickConnect",
            "connect:ListAgentStatuses",
            "connect:DescribeAgentStatus",
            "connect:ListInstanceAttributes",
            "connect:DescribeInstanceAttribute",
            "connect:ListInstanceStorageConfigs",
            "connect:DescribeInstanceStorageConfig",
            "connect:ListLambdaFunctions",
            "connect:ListLexBots",
            "connect:ListBots",
            "connect:GetMetricData",
            "connect:GetCurrentMetricData",
            "connect:GetMetricDataV2",
        ],
        # "*": account-wide discovery — the tool enumerates every Connect
        # instance, so no instance ARN is known before ListInstances runs. All
        # actions are read-only.
        "*",
    ),
    _statement(
        "CloudWatchMetricsAccess",
        [
            "cloudwatch:GetMetricStatistics",
            "cloudwatch:GetMetricData",
            "cloudwatch:ListMetrics",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams",
        ],
        # "*": CloudWatch metrics/logs read APIs do not support resource-level
        # authorization — "*" is the only value IAM accepts. All read-only.
        "*",
    ),
    _statement(
        "S3ConfigurationAccess",
        [
            "s3:GetBucketPolicy",
            "s3:GetBucketPolicyStatus",
            # s3:GetEncryptionConfiguration is the IAM action that authorizes the
            # GetBucketEncryption API call (an AWS naming quirk).
            "s3:GetEncryptionConfiguration",
            "s3:GetBucketVersioning",
            "s3:GetBucketLogging",
            "s3:GetBucketNotification",
            "s3:GetBucketLocation",
            "s3:GetBucketAcl",
            "s3:GetBucketCORS",
            "s3:GetBucketPublicAccessBlock",
        ],
        "arn:aws:s3:::*",
    ),
    _statement(
        "LambdaIntegrationAccess",
        [
            "lambda:GetFunction",
            "lambda:GetFunctionConfiguration",
            "lambda:GetPolicy",
            "lambda:ListTags",
        ],
        "arn:aws:lambda:*:*:function:*",
    ),
    _statement(
        "LexIntegrationAccess",
        [
            # Lex V1 (lex-models) — the assessment uses get_bot via the lex-models client
            "lex:GetBot",
            "lex:GetBots",
            "lex:GetBotAlias",
            "lex:GetBotAliases",
            "lex:GetBotVersions",
            # Lex V2
            "lex:DescribeBot",
            "lex:DescribeBotVersion",
            "lex:DescribeBotAlias",
            "lex:ListBots",
            "lex:ListBotVersions",
            "lex:ListBotAliases",
        ],
        # "*": the Lex list operations (GetBots/ListBots) are account-wide
        # discovery — bots are enumerated before any bot ARN is known. Read-only.
        "*",
    ),
    _statement(
        "KMSKeyAccess",
        [
            "kms:DescribeKey",
            "kms:GetKeyPolicy",
            "kms:ListAliases",
            "kms:ListKeys",
        ],
        # "*": ListKeys/ListAliases are account-wide discovery; DescribeKey/
        # GetKeyPolicy then run against keys found via Connect storage configs
        # whose ARNs aren't known in advance. Read-only.
        "*",
    ),
    _statement(
        "IAMRoleAccess",
        [
            "iam:GetRole",
            "iam:GetRolePolicy",
            "iam:ListAttachedRolePolicies",
            "iam:ListRolePolicies",
            "iam:GetPolicy",
            "iam:GetPolicyVersion",
        ],
        # Cannot be scoped to *Connect* names: the assessment also inspects the
        # execution roles of Lambdas wired into contact flows, which are
        # frequently not named with a "Connect" prefix. All actions are read-only.
        [
            "arn:aws:iam::*:role/*",
            "arn:aws:iam::*:policy/*",
        ],
    ),
    _statement(
        "STSAccess",
        [
            "sts:GetCallerIdentity",
        ],
        # "*": sts:GetCallerIdentity takes no resource and cannot be scoped.
        "*",
    ),
    _statement(
        "CloudTrailReadAccess",
        [
            "cloudtrail:DescribeTrails",
            "cloudtrail:GetTrailStatus",
            "cloudtrail:GetEventSelectors",
            # Used by res-acgr-failover-test-001 to look up
            # UpdateTrafficDistribution events over the last 90 days.
            "cloudtrail:LookupEvents",
        ],
        # "*": CloudTrail read APIs (LookupEvents/DescribeTrails/GetTrailStatus/
        # GetEventSelectors) don't support resource-level authorization for the
        # lookup this tool performs — "*" is the only accepted value. Read-only.
        "*",
    ),
    _statement(
        "CloudWatchAlarmsAccess",
        [
            "cloudwatch:DescribeAlarms",
            "cloudwatch:DescribeAlarmsForMetric",
        ],
        # "*": cloudwatch:DescribeAlarms(ForMetric) do not support resource-level
        # authorization — "*" is the only value IAM accepts. Read-only.
        "*",
    ),
    _statement(
        "ConnectAdvancedReadAccess",
        [
            "connect:ListTrafficDistributionGroups",
            "connect:DescribeTrafficDistributionGroup",
            # Used by res-acgr-traffic-dist-001 to inspect the region split.
            "connect:GetTrafficDistribution",
            "connect:ListSecurityProfilePermissions",
            "connect:ListApprovedOrigins",
            "connect:ListPhoneNumbersV2",
            "connect:ListContactFlowModules",
            "connect:DescribeContactFlowModule",
            "connect:DescribeInstanceAttribute",
            # Resolves which contact flow each phone number is actually
            # assigned to, for the Caller Journey Map. ListPhoneNumbersV2's
            # TargetArn is documented as the instance/TDG ARN a number is
            # claimed to, not the flow it's assigned to in the console —
            # ListFlowAssociations is the API that reflects that field.
            "connect:ListFlowAssociations",
            # Discovers Q in Connect assistant and knowledge-base integrations
            # for the instance-level AI operations maturity checks.
            "connect:ListIntegrationAssociations",
        ],
        # "*": account-wide Connect discovery (same rationale as
        # AmazonConnectReadOnlyAccess) — resources are enumerated, not known in
        # advance. Read-only.
        "*",
    ),
    _statement(
        "QConnectAIOpsReadAccess",
        [
            "wisdom:GetAssistant",
            "wisdom:GetKnowledgeBase",
            "wisdom:ListAIGuardrails",
            "wisdom:ListAIPrompts",
        ],
        # "*": these Q in Connect reads are called with assistant or knowledge-
        # base IDs discovered at runtime. The boto3 service name is qconnect,
        # while the IAM service prefix is wisdom.
        "*",
    ),
    _statement(
        "BedrockAIOpsReadAccess",
        [
            "bedrock:GetModelInvocationLoggingConfiguration",
            "bedrock:ListInferenceProfiles",
        ],
        # "*": these read-only Bedrock APIs inspect account/region-level
        # configuration and inventory rather than a known resource ARN.
        "*",
    ),
]


# The minimal subset probed by ``--check-permissions``. This is intentionally a
# small smoke-test list, not the full catalog — it spot-checks one or two
# actions per service to confirm credentials are wired up. The drift test
# enforces that every entry is also present in the canonical catalog above.
REQUIRED_PERMISSIONS: List[str] = [
    "connect:ListInstances",
    "connect:DescribeInstance",
    "connect:ListContactFlows",
    "connect:DescribeContactFlow",
    "connect:ListQueues",
    "connect:DescribeQueue",
    "connect:ListRoutingProfiles",
    "connect:DescribeRoutingProfile",
    "connect:ListUsers",
    "connect:DescribeUser",
    "connect:ListSecurityProfiles",
    "connect:DescribeSecurityProfile",
    "connect:ListPhoneNumbers",
    "connect:ListHoursOfOperations",
    "connect:DescribeHoursOfOperation",
    "connect:ListLambdaFunctions",
    "connect:ListLexBots",
    # Probed alongside the legacy ListPhoneNumbers because the Caller
    # Journey Map, cost checks, and several resilience checks all use the
    # V2 API exclusively — a role with only the V1 permission would pass
    # this smoke test while the Journey Map silently produced nothing.
    "connect:ListPhoneNumbersV2",
    # Resolves phone-number-to-flow assignment for the Caller Journey Map;
    # a role missing this would pass every other Connect probe and still
    # see the Journey Map silently produce nothing.
    "connect:ListFlowAssociations",
    # Gates discovery for every AI operations maturity check.
    "connect:ListIntegrationAssociations",
    "cloudwatch:GetMetricStatistics",
    "s3:GetBucketPolicy",
    "s3:GetEncryptionConfiguration",
    "sts:GetCallerIdentity",
]


def all_actions() -> Set[str]:
    """Return the full set of canonical actions across every statement."""
    actions: Set[str] = set()
    for statement in POLICY_STATEMENTS:
        actions.update(statement["Action"])  # type: ignore[arg-type]
    return actions


def build_policy_document() -> Dict[str, object]:
    """Return the canonical IAM policy document as a dict."""
    return {"Version": POLICY_VERSION, "Statement": POLICY_STATEMENTS}


def render_policy_json() -> str:
    """Render the standalone IAM policy as JSON (with a trailing newline)."""
    return json.dumps(build_policy_document(), indent=4) + "\n"


if __name__ == "__main__":
    import argparse
    import pathlib

    parser = argparse.ArgumentParser(description="Generate the standalone IAM policy JSON.")
    parser.add_argument(
        "--write",
        action="store_true",
        help="Write docs/iam-policy-template.json instead of printing to stdout.",
    )
    args = parser.parse_args()

    rendered = render_policy_json()
    if args.write:
        target = pathlib.Path(__file__).resolve().parents[1] / "docs" / "iam-policy-template.json"
        target.write_text(rendered)
        print(f"Wrote {target}")
    else:
        print(rendered, end="")
