# Amazon Connect Customer Assessment Tool — Threat Model

This document identifies the security boundaries, trust zones, threat actors, attack surfaces, and mitigations for the Amazon Connect Customer Assessment Tool. It follows the STRIDE framework.

> **Architecture note:** The Amazon Connect Customer Assessment Tool is a
> **command-line tool**. It has no
> listening socket or daemon.

## Table of Contents

- [System overview](#system-overview)
- [Trust zones](#trust-zones)
- [Threat actors](#threat-actors)
- [Attack surfaces and mitigations](#attack-surfaces-and-mitigations)
- [STRIDE summary](#stride-summary)
- [Data flow diagram](#data-flow-diagram)
- [Assumptions](#assumptions)
- [Residual risks](#residual-risks)
- [Recommendations for future hardening](#recommendations-for-future-hardening)

---

## System overview

The Amazon Connect Customer Assessment Tool is a **read-only** assessment tool that:
- Runs as a CLI process on a user's workstation, AWS CloudShell, or a CI runner
- Authenticates to AWS using existing credentials (profile, role assumption, or environment variables)
- Makes read-only AWS API calls to Amazon Connect Customer and supporting services
- Produces HTML/JSON/CSV/ASFF reports on the local filesystem
- Optionally (`--s3-output`) uploads those reports to a dedicated, hardened S3 bucket in the assessed account
- Never modifies, creates, or deletes any AWS resource it inspects

The only write operation the tool can perform is creating and writing to its own
`amazon-connect-assessment-report-*` bucket, and only when `--s3-output` is passed.

---

## Trust zones

| Zone | Description | Trust level |
|---|---|---|
| **Z1 — Execution host** | The workstation, CloudShell, or CI runner running the CLI. Has access to AWS credentials, the local filesystem, and report output. | Fully trusted |
| **Z2 — AWS APIs** | Amazon Connect Customer, IAM/STS, CloudTrail, CloudWatch, KMS, Lambda, S3. Data source and (for `--s3-output`) report sink. | Trusted (authenticated, TLS) |
| **Z3 — Generated reports** | HTML files with embedded JavaScript, plus JSON/CSV/ASFF. Opened directly in a browser or shared. | Untrusted content (flow names/parameters from AWS could contain payloads) |
| **Z4 — Contact flow content** | JSON retrieved from the assessed AWS account. Parsed and traversed by the tool. | Untrusted (customer-controlled, potentially adversarial) |

---

## Threat actors

| Actor | Motivation | Access |
|---|---|---|
| **Malicious contact flow author** | Craft flow JSON to exploit the parser, cause DoS, or inject XSS into reports | Controls flow content in the assessed AWS account |
| **Credential thief** | Steal AWS credentials exposed by the tool | Access to the host, log files, or report output |
| **Report recipient** | Trick the assessor by manipulating findings after report generation | Access to the report file or S3 object |

---

## Attack surfaces and mitigations

### AS-1: Contact flow parser and journey mapping

| Threat | Category | Risk | Mitigation |
|---|---|---|---|
| Deeply nested or circular flow graphs cause stack overflow | Denial of Service | High | All graph traversal is **iterative** (explicit stack), never recursive. Depth bounded at 50; paths capped at 200 per entry and 5000 globally. |
| Combinatorial explosion from highly branching flows | Denial of Service | Medium | `max_paths` and `MAX_TOTAL_PATHS` caps prevent unbounded growth. Path enumeration short-circuits once limits are hit. |
| Adversarial flow parameters crafted for XSS in reports | Elevation of Privilege | Medium | Jinja2 autoescaping applied to all template output. JSON encoding uses `<\/` escape. |
| Malformed flow JSON crashes the parser | Denial of Service | Low | Parser validates input type, skips non-dict actions gracefully, and uses `.get()` with defaults throughout. |
| Dynamic attribute references used to confuse graph analysis | Spoofing | Low | Dynamic references are detected and recorded in `dynamic_references` — never followed as if they were static edges. |

### AS-2: AWS credential handling

| Threat | Category | Risk | Mitigation |
|---|---|---|---|
| Credentials leaked into logs | Information Disclosure | High | Credentials are never logged. Logging references operation names, not parameters containing secrets. |
| Credentials leaked into report output | Information Disclosure | High | Reports contain only findings, metadata (account ID, region), and evidence data. No credential material is serialized. |
| Overly broad permissions on the assessment principal | Elevation of Privilege | Medium | The assessment requires only read-only permissions. The CloudFormation template (`AmazonConnectSelfAssessmentPolicy.yaml`) grants a single **inline** least-privilege policy scoped to exactly the actions in `iam_permissions.py` — no AWS managed policies (`SecurityAudit`/`ViewOnlyAccess`) are attached, so every allowed action is explicit and auditable. It is a same-account policy: the tool runs against the caller's own account with its existing credentials; there is no cross-account role assumption or External ID in the code (cross-account support was deliberately removed; see the "Purge cross-account role code paths" refactor). |
| Checkpoint files expose sensitive state | Information Disclosure | Low | Checkpoint directory created `0o700`, files `0o600`. Contains only assessment progress metadata, not credentials. |
| Session token reuse after expiration | Spoofing | Low | boto3 handles credential refresh natively from the caller's configured credentials (profile, environment, or instance/SSO). |

### AS-3: Report output

| Threat | Category | Risk | Mitigation |
|---|---|---|---|
| XSS in HTML report via injected flow names or parameters | Elevation of Privilege | Medium | Jinja2 `select_autoescape(["html", "xml"])` enabled. All dynamic content escaped by default. |
| Local report file accessible to unauthorized users | Information Disclosure | Medium | Reports written to a local directory; access governed by OS file permissions. |
| Report tampering after generation | Tampering | Low | Reports are static, point-in-time snapshots. ASFF output can be verified via Security Hub import validation. |

### AS-4: S3 report publishing (`--s3-output`)

| Threat | Category | Risk | Mitigation |
|---|---|---|---|
| Auto-created report bucket is world-readable | Information Disclosure | High | Buckets are created with S3 Block Public Access (all four flags), default SSE-S3 encryption, and versioning enabled. |
| Over-broad write permissions on the assessment role | Elevation of Privilege | Medium | The default CloudFormation role is read-only and does not grant S3 report-publishing writes. When `--s3-output` is enabled, operators must add a separate policy scoped to `arn:aws:s3:::amazon-connect-assessment-report-*` and its objects. Publishing is opt-in. |
| Bucket-name takeover (global S3 namespace) | Spoofing | Low | `head_bucket` checks ownership before upload; a `403` (owned elsewhere) surfaces an error rather than silently uploading. Operators can override with `--s3-bucket`. |
| Failed upload aborts the assessment | Denial of Service | Low | Upload failures are caught and reported; the assessment still succeeds and local reports remain. |

---

## STRIDE summary

| Category | Key risks | Primary controls |
|---|---|---|
| **Spoofing** | Credential misuse; bucket-name takeover | Same-account read-only inline policy (no cross-account assumption); bucket ownership checked via `head_bucket` before upload |
| **Tampering** | Adversarial flow content | Iterative bounded parsing; Jinja2 autoescaping |
| **Repudiation** | Assessment actions not auditable | All AWS API calls logged in CloudTrail automatically |
| **Information Disclosure** | Credential leakage; public report bucket | No credentials in logs/reports; Block Public Access + SSE on report bucket; restrictive local file permissions |
| **Denial of Service** | Graph explosion | Bounded traversal (depth 50, paths 5000) |
| **Elevation of Privilege** | XSS in reports; over-broad IAM | Jinja2 autoescaping; least-privilege read-only role, with optional S3 writes granted separately and scoped to the report bucket |

---

## Data flow diagram

```
┌──────────────────────────────────────────────────────────────┐
│ Z1: Execution host (workstation / CloudShell / CI runner)     │
│                                                                │
│   ┌──────────────────────┐                                    │
│   │ Assessment CLI        │                                    │
│   │  ├─ Engine            │                                    │
│   │  ├─ Analyzers         │                                    │
│   │  ├─ Checks            │                                    │
│   │  ├─ Journey Mapping   │                                    │
│   │  └─ Report Generator  │                                    │
│   └──────────┬───────────┘                                    │
│              │                                                 │
│      ┌───────┼────────────┐                                   │
│      ▼       ▼            ▼                                    │
│  ┌────────┐ ┌──────────────┐                                  │
│  │ Z3:    │ │ Checkpoint   │                                  │
│  │ Reports│ │ files (0o600)│                                  │
│  └───┬────┘ └──────────────┘                                  │
│      │ optional --s3-output                                   │
└──────┼─────────────────────────────────────────────────────── ┘
       │                          │
       │ HTTPS (TLS)              │ Read-only API calls (TLS)
       ▼                          ▼
┌────────────────────┐  ┌───────────────────────────────┐
│ Z2: S3 report      │  │ Z2: AWS APIs                   │
│ bucket (hardened,  │  │  ├─ Amazon Connect Customer    │
│ BPA + SSE + ver.)  │  │  ├─ IAM / STS                  │
└────────────────────┘  │  ├─ CloudTrail                 │
                        │  ├─ CloudWatch                 │
                        │  ├─ KMS                        │
                        │  └─ Lambda (describe only)     │
                        └──────────────┬────────────────┘
                                       │ Returns
                                       ▼
                        ┌───────────────────────────────┐
                        │ Z4: Contact Flow Content       │
                        │  (customer-controlled JSON)    │
                        │  Parsed → Graph → Scored       │
                        └───────────────────────────────┘
```

---

## Assumptions

1. The execution host is not compromised — if it is, all bets are off (the attacker already has credential access).
2. AWS API responses are authentic (TLS verified by boto3/botocore).
3. Contact flow JSON may contain arbitrary string values but conforms to the Connect flow schema structure (dict with `Actions` array).
4. When `--s3-output` is used, the operator intends to create/write the report bucket in the assessed account.

---

## Residual risks

| Risk | Likelihood | Impact | Acceptance rationale |
|---|---|---|---|
| Local attacker on same host accesses reports | Low | Medium | Standard host security model — mitigate with OS-level access controls |
| Malicious flow name containing JavaScript passes through a future template change that disables autoescaping | Low | Medium | Covered by Jinja2 autoescape default + code review |
| boto3 dependency has a vulnerability | Low | High | Mitigated by dependency scanning in CI and regular updates |
| Large account with 1000+ flows causes high memory during graph construction | Medium | Low | Bounded by MAX_TOTAL_PATHS (5000); graph holds only tier-1/tier-2 flows |
| Report bucket retains historical reports indefinitely | Low | Low | Versioning is enabled by design; operators can apply lifecycle rules |

---

## Recommendations for future hardening

1. **Add HMAC signature to generated reports** — allows recipients to verify report integrity
2. **Add Subresource Integrity (SRI) hashes** if external CDN resources are ever included in reports
3. **Consider encrypting checkpoint files at rest** — currently plain JSON with restrictive permissions
4. **Keep `connect:ListPhoneNumbersV2` in the minimum permission validation** — journey mapping and its phone-number topology require it
5. **Offer a bucket lifecycle policy / KMS (SSE-KMS) option** for the report bucket in regulated environments
6. **Implement output size limits on report generation** — guard against reports exceeding reasonable sizes from extremely large accounts
