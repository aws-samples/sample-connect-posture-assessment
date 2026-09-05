"""Drift tests: keep the IAM-permission artifacts in sync.

All three artifacts derive from ``amazon_connect_assessment.iam_permissions``:

  1. ``docs/iam-policy-template.json`` (generated; must match byte-for-byte)
  2. ``cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`` (hand-maintained
     inline policy)
  3. ``AWSClientFactory.REQUIRED_PERMISSIONS`` (imported from the module)

These tests would have caught every gap from the original audit: the missing
lex:GetBot, the over-narrow IAM role scope, and the absent Connect integration
actions in the standalone policy.
"""

import json
import re
from pathlib import Path

import yaml

from amazon_connect_assessment import iam_permissions
from amazon_connect_assessment.aws_client_factory import AWSClientFactory

REPO_ROOT = Path(__file__).resolve().parents[1]
JSON_POLICY_PATH = REPO_ROOT / "docs" / "iam-policy-template.json"
CFN_SELF_ASSESSMENT_PATH = REPO_ROOT / "cloudformation" / "AmazonConnectSelfAssessmentPolicy.yaml"


def test_standalone_json_matches_generated_source():
    """The checked-in JSON policy must match what the module generates exactly.

    To refresh after editing iam_permissions.py:
        python -m amazon_connect_assessment.iam_permissions --write
    """
    on_disk = JSON_POLICY_PATH.read_text()
    generated = iam_permissions.render_policy_json()
    assert on_disk == generated, (
        "docs/iam-policy-template.json is out of sync with iam_permissions.py. "
        "Regenerate it with: "
        "python -m amazon_connect_assessment.iam_permissions --write"
    )


def test_standalone_json_is_valid_policy():
    """Sanity-check the generated document parses and is well-formed."""
    doc = json.loads(JSON_POLICY_PATH.read_text())
    assert doc["Version"] == iam_permissions.POLICY_VERSION
    assert isinstance(doc["Statement"], list) and doc["Statement"]
    sids = [s["Sid"] for s in doc["Statement"]]
    assert len(sids) == len(set(sids)), "Duplicate Sids in policy"


def test_required_permissions_is_subset_of_canonical():
    """The --check-permissions smoke list must not name actions outside the catalog."""
    canonical = iam_permissions.all_actions()
    missing = set(AWSClientFactory.REQUIRED_PERMISSIONS) - canonical
    assert not missing, (
        f"REQUIRED_PERMISSIONS contains actions absent from the canonical "
        f"policy catalog: {sorted(missing)}"
    )


def test_required_permissions_sourced_from_module():
    """AWSClientFactory must use the single source of truth, not a private copy."""
    assert AWSClientFactory.REQUIRED_PERMISSIONS is iam_permissions.REQUIRED_PERMISSIONS


# ---------------------------------------------------------------------------
# Same-account self-assessment CloudFormation template.
#
# The template's inline managed policy is hand-maintained (it carries CFN
# intrinsics and conditions that don't round-trip through Python), so we
# assert bidirectional coverage against the canonical action set — every
# canonical action must be granted, and every granted action must be
# canonical (no dead over-permissioning).
# ---------------------------------------------------------------------------


def _cfn_self_assessment_actions() -> set:
    """Extract every action from the self-assessment template's inline policy."""
    # The CFN template uses !Sub/!Ref/!If intrinsics; register a permissive
    # multi-constructor so PyYAML can load the file for inspection.
    loader = yaml.SafeLoader
    loader.add_multi_constructor("!", lambda ldr, suffix, node: None)
    # SafeLoader (not the unsafe default) parsing a repo-local template; the
    # multi-constructor above only tolerates CFN intrinsics. Not untrusted input.
    template = yaml.load(CFN_SELF_ASSESSMENT_PATH.read_text(), Loader=loader)  # nosec B506

    policy = template["Resources"]["AmazonConnectReadOnlyPolicy"]
    doc = policy["Properties"]["PolicyDocument"]
    assert doc["Version"] == iam_permissions.POLICY_VERSION, (
        "Self-assessment policy uses an invalid IAM policy version"
    )
    actions = set()
    for statement in doc["Statement"]:
        action = statement["Action"]
        actions.update(action if isinstance(action, list) else [action])
    return actions


def _load_cfn_self_assessment_template() -> dict:
    """Load the self-assessment CloudFormation template for structural checks."""
    loader = yaml.SafeLoader
    loader.add_multi_constructor("!", lambda ldr, suffix, node: None)
    return yaml.load(CFN_SELF_ASSESSMENT_PATH.read_text(), Loader=loader)  # nosec B506


def test_self_assessment_policy_covers_every_canonical_action():
    """Every canonical action must be present inline in the CFN template.

    The template attaches no AWS managed policies (SecurityAudit or
    ViewOnlyAccess), so there's no backstop — omitting an action here means
    users hit AccessDenied at runtime.
    """
    on_policy = _cfn_self_assessment_actions()
    canonical = iam_permissions.all_actions()

    missing = canonical - on_policy
    assert not missing, (
        "These canonical actions are missing from "
        f"cloudformation/AmazonConnectSelfAssessmentPolicy.yaml: {sorted(missing)}. "
        "Add them to the appropriate statement in the template."
    )


def test_self_assessment_policy_has_no_stray_actions():
    """The template shouldn't grant actions outside the canonical catalog.

    Catches accidental additions and typos — an action that IAM would accept
    but the tool never actually calls (dead over-permissioning).
    """
    on_policy = _cfn_self_assessment_actions()
    canonical = iam_permissions.all_actions()

    stray = on_policy - canonical
    assert not stray, (
        "These actions are in AmazonConnectSelfAssessmentPolicy.yaml but not in "
        f"the canonical policy catalog: {sorted(stray)}. Add them to "
        "iam_permissions.py::POLICY_STATEMENTS or remove them from the template."
    )


def test_self_assessment_policy_version_is_valid():
    """Guard against the template-format version (2010-09-09) leaking into the
    inline IAM policy document, which requires the IAM version (2012-10-17)."""
    text = CFN_SELF_ASSESSMENT_PATH.read_text()
    policy_versions = re.findall(r"Version:\s*'(\d{4}-\d{2}-\d{2})'", text)
    iam_versions = [v for v in policy_versions if v != "2010-09-09"]
    assert iam_versions, "No IAM policy Version found in self-assessment template"
    assert all(v == "2012-10-17" for v in iam_versions), (
        f"Invalid IAM policy version in self-assessment template: {policy_versions}"
    )


def test_self_assessment_policy_does_not_attach_directly_to_users():
    """User-based access must go through an IAM group to satisfy cfn-nag F12."""
    template = _load_cfn_self_assessment_template()
    resources = template["Resources"]

    policy = resources["AmazonConnectReadOnlyPolicy"]
    assert "Users" not in policy["Properties"]

    group = resources["AmazonConnectAssessmentGroup"]
    assert group["Type"] == "AWS::IAM::Group"
    assert group["Condition"] == "HasUserAttachment"
    assert "ManagedPolicyArns" in group["Properties"]

    membership = resources["AmazonConnectUserGroupMembership"]
    assert membership["Type"] == "AWS::IAM::UserToGroupAddition"
    assert membership["Condition"] == "HasUserAttachment"


def test_ai_ops_policy_uses_wisdom_iam_prefix_for_qconnect_calls():
    # Arrange
    canonical = iam_permissions.all_actions()
    expected_ai_actions = {
        "connect:ListIntegrationAssociations",
        "wisdom:GetAssistant",
        "wisdom:GetKnowledgeBase",
        "wisdom:ListAIGuardrails",
        "wisdom:ListAIPrompts",
        "bedrock:GetModelInvocationLoggingConfiguration",
        "bedrock:ListInferenceProfiles",
    }

    # Assert
    assert expected_ai_actions <= canonical
    assert "connect:ListIntegrationAssociations" in AWSClientFactory.REQUIRED_PERMISSIONS
