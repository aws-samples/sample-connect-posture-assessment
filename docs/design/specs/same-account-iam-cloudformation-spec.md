# Spec: Same-Account IAM CloudFormation Template

**Status:** Implemented, and subsequently promoted to the *only* CloudFormation template — the sibling cross-account role template (`cloudformation/AmazonConnectScanRole.yaml`) referenced throughout the "Related work" and comparison sections below was deleted in a follow-up cleanup after the cross-account workflow was scoped out. This spec is retained as a design record because the "Alternatives considered" and "Open questions" sections capture *why* we chose CloudFormation over a CLI subcommand or shell script, which is not obvious from reading the template alone.
**Author:** susbhaga (drafted with agent assistance)
**Delivered artifacts:**
- [`cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`](../../../cloudformation/AmazonConnectSelfAssessmentPolicy.yaml)
- Drift tests in [`tests/test_iam_policy_consistency.py`](../../../tests/test_iam_policy_consistency.py)
- README's "Setting up AWS access" section

## Table of Contents

- [Motivation](#motivation)
- [Goals](#goals)
- [Non-goals](#non-goals)
- [Design](#design)
  - [File](#file)
  - [Parameters](#parameters)
  - [Resources](#resources)
  - [Outputs](#outputs)
  - [Drift with `docs/iam-policy-template.json`](#drift-with-docsiam-policy-templatejson)
  - [README changes](#readme-changes)
- [User workflow with the new template](#user-workflow-with-the-new-template)
- [Alternatives considered](#alternatives-considered)
- [Testing](#testing)
- [Rollout](#rollout)
- [Open questions](#open-questions)

---

## Motivation

Self-assessment users (running the tool against their own AWS account) currently do this to grant themselves the assessment permissions:

```bash
aws iam create-policy \
  --policy-name AmazonConnectReadOnly \
  --policy-document file://docs/iam-policy-template.json

aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/AmazonConnectReadOnly
```

Two AWS CLI commands with placeholders they have to substitute. If the user is a role rather than a user (e.g. federated), the second command is different (`attach-role-policy`). If they want to reuse the policy across principals, they have to remember which they attached to which. The imperative shape doesn't play well with change control — nothing about the policy state lives in version control on the user's side.

The **cross-account** case avoids all this by shipping a CloudFormation template the customer deploys. `AmazonConnectScanRole.yaml` creates the role, the trust policy, the additions policy, and attaches AWS managed policies, all through one deployment step. Same-account should feel the same.

## Goals

1. Replace the two `aws iam …` commands with a single CloudFormation deployment.
2. Support granting the policy to any combination of a user through a group, a role, or nothing (create the policy standalone for later attachment).
3. Reuse `docs/iam-policy-template.json` as the source of truth for policy contents — no drift between the JSON and the same-account template.
4. Compose cleanly with the existing cross-account template: same repo location (`cloudformation/`), same naming pattern, same drift-detection story.
5. Documented in the README next to the existing self-assessment instructions.

## Non-goals

- Cross-region policy replication. IAM is global; one deployment covers all regions.
- Managing the assessment-running principal itself. The template attaches to an existing user/role; it does not create one.
- Optional `--s3-output` bucket permissions in a separate template. Those are already inline in `AmazonConnectScanRole.yaml` for cross-account and could be added here later if needed — deferred to keep this template minimal.

## Design

### File

`cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`

Same folder as the existing role template, so users find both in one place. The filename mirrors the `AmazonConnect...` naming pattern and clarifies scope (`SelfAssessment` vs `Scan`, and `Policy` vs `Role` — this stack creates a policy, not a role).

### Parameters

| Name | Type | Default | Description |
|---|---|---|---|
| `PolicyName` | `String` | `AmazonConnectReadOnly` | Name of the managed policy. Kept as a parameter so users deploying multiple stacks (rare, but supported) can distinguish. |
| `AttachToUserName` | `String` | `""` (empty) | Optional IAM user to add to the stack-managed group. Empty means "don't grant access to any user." |
| `AttachToRoleName` | `String` | `""` (empty) | Optional IAM role to attach the policy to. Empty means "don't attach to any role." |

`AttachToUserName` and `AttachToRoleName` are independent — a user could set both if they run assessments from both a user principal and a role principal (e.g. an EC2 instance role for CI). Setting neither is valid: the policy is created and its ARN is emitted as a stack output, ready for manual attachment.

`Conditions` use `Fn::Not [Fn::Equals ["", !Ref AttachTo…Name]]` to gate role attachment and optional user group membership. CloudFormation supports conditional list contents via `Fn::If`.

### Resources

**`AmazonConnectReadOnlyPolicy`** — a single `AWS::IAM::ManagedPolicy`.

- `ManagedPolicyName: !Ref PolicyName`
- `Description: Read-only permissions for the Amazon Connect assessment tool (see docs/iam-policy-template.json for the source-of-truth action set).`
- `PolicyDocument`: **inlined verbatim** from `docs/iam-policy-template.json`. The additions policy in `AmazonConnectScanRole.yaml` uses the same approach today; a drift test asserts every canonical action is present.
- `Roles`: conditional list — `[!Ref AttachToRoleName]` when set, `AWS::NoValue` otherwise.

**`AmazonConnectAssessmentGroup`** — conditional `AWS::IAM::Group` created when `AttachToUserName` is set.

- `GroupName`: omitted so CloudFormation generates a stack-scoped name and avoids name collisions.
- `ManagedPolicyArns`: attaches the managed policy to the group.

**`AmazonConnectUserGroupMembership`** — conditional `AWS::IAM::UserToGroupAddition` created when `AttachToUserName` is set.

- `GroupName: !Ref AmazonConnectAssessmentGroup`
- `Users`: `[!Ref AttachToUserName]`

The policy is intentionally not attached directly to an IAM user. User-based access flows through a group to satisfy `cfn-nag` rule F12.

### Outputs

| Output | Value | Purpose |
|---|---|---|
| `PolicyArn` | `!Ref AmazonConnectReadOnlyPolicy` | The ARN to hand to `aws iam attach-…-policy` if the user chose not to auto-attach via parameters. |
| `PolicyName` | `!Ref PolicyName` | Echo the name for readability. |
| `AttachmentStatus` | Human-readable string built from `AttachToUserName` and `AttachToRoleName` | e.g. "Added user alice to group <generated-group-name>", "Attached to role: MyAssessmentRole", "Added user alice to group <generated-group-name> and attached to role MyAssessmentRole", or "Created without attachment — attach manually with the PolicyArn above." |

### Drift with `docs/iam-policy-template.json`

`tests/test_iam_policy_consistency.py` today asserts:

1. `docs/iam-policy-template.json` matches what `iam_permissions.py::render_policy_json()` produces (byte-for-byte).
2. Every canonical action is granted by `AmazonConnectScanRole.yaml` — either inline in the additions policy or by one of the managed policies (`SecurityAudit`, `ViewOnlyAccess`) via `MANAGED_POLICY_ACTIONS`.

This new template adds a third assertion:

3. Every canonical action is present in `AmazonConnectSelfAssessmentPolicy.yaml`. Since this is a same-account template with no managed-policy attachments, `MANAGED_POLICY_ACTIONS` cannot save us — every action must be explicit in the inline policy document.

Implementation sketch for the drift check:

```python
def _extract_actions_from_selfassessment_yaml(path: Path) -> Set[str]:
    """Parse the SelfAssessmentPolicy YAML and return every action listed
    in the single ManagedPolicy's Statements."""
    doc = yaml.safe_load(path.read_text())
    policy = doc["Resources"]["AmazonConnectReadOnlyPolicy"]
    return {
        a
        for stmt in policy["Properties"]["PolicyDocument"]["Statement"]
        for a in stmt["Action"]
    }


def test_self_assessment_policy_matches_canonical():
    canonical = all_actions()  # from iam_permissions.py
    on_policy = _extract_actions_from_selfassessment_yaml(
        REPO_ROOT / "cloudformation" / "AmazonConnectSelfAssessmentPolicy.yaml"
    )
    missing = canonical - on_policy
    assert not missing, (
        f"Actions in the canonical set but missing from "
        f"AmazonConnectSelfAssessmentPolicy.yaml: {sorted(missing)}"
    )
```

The existing cfn-lint CI step already validates syntax; nothing new needed there.

### README changes

Replace the existing "Step 1 — Confirm your CLI access" IAM block in **Setting up AWS access → Option B: Self-assessment**:

**Before:**

```bash
aws iam create-policy \
  --policy-name AmazonConnectReadOnly \
  --policy-document file://docs/iam-policy-template.json

aws iam attach-user-policy \
  --user-name YOUR_USERNAME \
  --policy-arn arn:aws:iam::ACCOUNT_ID:policy/AmazonConnectReadOnly
```

**After:**

> Deploy the same-account CloudFormation template — one step, no CLI substitutions:
>
> ```bash
> aws cloudformation deploy \
>   --stack-name amazon-connect-assessment-permissions \
>   --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
>   --parameter-overrides AttachToUserName=YOUR_USERNAME \
>   --capabilities CAPABILITY_NAMED_IAM \
>   --region us-east-1
> ```
>
> To attach to a role instead of granting access through a user group, pass `AttachToRoleName=YOUR_ROLE_NAME`. To create the policy without auto-attaching (useful for SSO or federated principals), omit both `AttachTo…` parameters and use the stack's `PolicyArn` output.
>
> Or deploy via the AWS Console: **CloudFormation → Create stack → Upload `cloudformation/AmazonConnectSelfAssessmentPolicy.yaml` → set `AttachToUserName` to add the user to the generated group → Deploy**.

## User workflow with the new template

**IAM user, one command:**

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --parameter-overrides AttachToUserName=alice \
  --capabilities CAPABILITY_NAMED_IAM
```

**IAM role (e.g. EC2, Lambda, or an SSO permission set's role):**

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --parameter-overrides AttachToRoleName=AssessmentRunner \
  --capabilities CAPABILITY_NAMED_IAM
```

**Create-only, attach later** (useful for SSO federated principals where you attach to the permission set separately):

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --capabilities CAPABILITY_NAMED_IAM

# Grab the ARN
aws cloudformation describe-stacks \
  --stack-name amazon-connect-permissions \
  --query 'Stacks[0].Outputs[?OutputKey==`PolicyArn`].OutputValue' --output text
```

## Alternatives considered

**Extend `AmazonConnectScanRole.yaml`** with a `SelfAssessment` mode via a condition. Rejected: it would tangle two mental models (cross-account trust vs same-account attachment), and the cross-account template's audience is customers who probably don't want the extra parameters cluttering the form.

**Ship a helper shell script** in `scripts/setup-self-assessment.sh` that runs the two `aws iam` commands. Rejected: still imperative, still hard to keep drift-free with the canonical action set, and yet another shell-script artifact that undermines the "everything is a CloudFormation stack" narrative we already have for cross-account.

**Add a CLI subcommand** `amazon-connect-assessment setup-permissions --user alice`. Rejected: bootstrapping a tool's IAM permissions from within the tool itself is a chicken-and-egg problem — the user needs some permission (at least `iam:CreatePolicy` + `iam:AttachUserPolicy`) before the tool can bootstrap its own. That's a wider grant than what the tool actually needs at runtime, which contradicts the principle of least privilege. CloudFormation avoids this by making the deployment step visible and auditable, and the deployer's permissions are a separate concern.

## Testing

- **New drift test** — `tests/test_iam_policy_consistency.py` gains `test_self_assessment_policy_matches_canonical`, structure sketched above.
- **cfn-lint** — already run in CI on every YAML in `cloudformation/`; the new file gets validated automatically. No CI config change required.
- **Manual smoke** — deploy the template in a dev account with `AttachToUserName` set, run `amazon-connect-assessment --check-permissions`, confirm all permissions present. Repeat with `AttachToRoleName` and with neither parameter (verifying the standalone-policy path).

## Rollout

1. Land the template + drift test + README update as one commit.
2. Existing self-assessment users' `aws iam …`-created policies still work; they can migrate at their own pace. Add a note in the README's Troubleshooting section that CloudFormation is now the recommended path.
3. No breaking changes to any existing artifact.

## Open questions

1. **Policy name collision.** The default `AmazonConnectReadOnly` will collide with users who already ran the two `aws iam` commands. Options: (a) accept the collision — the stack fails, user renames or deletes the old policy; (b) name the CFN-managed policy differently by default (e.g. `AmazonConnectReadOnly-CFN`) to avoid collision. Recommend (a) with a call-out in the README migration note — collision is loud and unambiguous.
2. **SCP interaction.** Some org accounts have SCPs that block `iam:CreatePolicy` or `iam:AttachUserPolicy`. The template will fail with a clear error; nothing this spec can do about it. Documented in the README's Troubleshooting section.
3. **Whether to also generate this template from `iam_permissions.py`.** The cross-account template is hand-maintained today (for the reasons in that file's docstring — intrinsics, trust policy, tags, outputs that don't round-trip). This new template is much simpler; it could plausibly be generated. **Recommendation:** hand-maintain for consistency with the cross-account template and let the drift test catch mistakes. Revisit if a third template ever appears.
