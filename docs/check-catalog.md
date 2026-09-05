# Amazon Connect Customer Assessment Tool — Check Catalog

59 registered checks across 5 AWS Well-Architected pillars, plus 4 Caller Journey Mapping findings produced by a separate pipeline (see the Caller Journey Mapping section below — these are not returned by `--list-checks`, which only enumerates the check-registry checks). Every check returns one of five statuses:

- **Pass** — the check evaluated the instance and did not find a problem
- **Fail** — the check evaluated the instance and found a problem to remediate
- **Not Applicable** — the check evaluated and determined it does not apply to this instance (for example, an ACGR audit check when ACGR is not configured). N/A findings are excluded from the pass-rate denominator and rendered with a neutral badge
- **Skipped** — the check could not complete because a required permission, API response, discovery page, lookup, or stable resource state was unavailable. Partial evidence is retained and is never interpreted as an unqualified pass
- **Error** — the check raised an unexpected exception; treat as a bug report

Run `amazon-connect-assessment --list-checks` for the live list at any time.

## Table of Contents

- [Security](#security--22-checks)
- [Resilience](#resilience--13-checks)
- [Caller Journey Map](#caller-journey-map-report-section-not-a-check)
- [Cost Optimization](#cost-optimization--15-checks)
- [Operational Excellence](#operational-excellence--6-checks)
- [Performance Efficiency](#performance-efficiency--3-checks)
- [Caller Journey Mapping](#caller-journey-mapping--4-findings)
  - [How the pipeline works](#how-the-pipeline-works)
  - [Tier classification](#tier-classification)
  - [Configuration](#configuration)
- [Skipped findings](#skipped-findings)
- [Permissions](#permissions)
- [Running a subset of checks](#running-a-subset-of-checks)

---

## Security — 22 checks

| Check ID | Severity | What it evaluates |
|---|---|---|
| `security-iam-001` | Critical | Amazon Connect Customer service role follows least privilege — no wildcard actions, no out-of-scope services |
| `sec-toll-fraud-001` | Critical | Contact flows that transfer to dynamically-determined phone numbers without a validation step (toll fraud vector) |
| `sec-iam-deep-001` | High | Inline and attached policies on the Amazon Connect Customer service role — flags least-privilege violations |
| `sec-storage-001` | High | Each storage config (recordings, transcripts, CTRs, reports) has encryption enabled, preferring CMKs |
| `sec-origins-001` | High / Low | Approved origins allowlist is a domain allowlist for CCP embedding. FAIL at HIGH for wildcards / localhost / broad entries. FAIL at LOW when no allowlist is set — a defect only for customers embedding CCP in a custom agent app; otherwise the safe default. |
| `sec-cloudtrail-001` | High | At least one CloudTrail trail captures Connect management events for audit completeness |
| `sec-profile-audit-001` | High | Non-administrator security profiles don't grant admin-level capabilities |
| `sec-prompt-inject-001` | High | Unsanitized dynamic content (contact attributes, Lambda returns) is not inserted into voice prompts or SSML |
| `sec-sensitive-data-001` | High | Contact flows don't store PII or credentials in contact attributes (visible in CTRs and logs) |
| `sec-pii-prompts-001` | High | Flows don't read back sensitive customer data (account numbers, SSN) in voice without masking |
| `sec-output-handling-001` | High | Lambda/Lex outputs that reach prompts, transfers, or downstream invocations have intermediate validation |
| `sec-ai-lex-001` | High | Lex bot integrations have input validation or guardrail configuration to prevent prompt injection |
| `sec-excessive-agency-001` | High | Lambda functions invoked by contact flows don't have overly broad execution role permissions |
| `ai-ops-guardrail-001` | High | Each associated Q in Connect assistant exposes at least one guardrail summary that is both ACTIVE and PUBLISHED. `wisdom:ListAIGuardrails` proves assistant-scoped availability only; it does not prove AI-agent attachment, enforcement, or specific content/PII filter configuration. |
| `security-data-001` | Medium | Data retention policies, access logging, and privacy controls are configured |
| `sec-lambda-validation-001` | Medium | Contact flows that branch on Lambda return values validate the response shape before branching |
| `sec-ai-lambda-001` | Medium | Lambda functions invoking AI/ML services (Bedrock, SageMaker, Comprehend) are flagged for IAM review |
| `sec-ai-cascade-001` | Medium | Flows chaining 2+ AI components (Lex bot, then a Lambda calling Bedrock/SageMaker/Comprehend, etc.) with no output check between stages — one bad output can propagate unchecked into the next |
| `ai-ops-encryption-001` | Medium | Associated Q in Connect assistants and knowledge bases report a customer-managed KMS key in `serverSideEncryptionConfiguration.kmsKeyId` via `wisdom:GetAssistant` and `wisdom:GetKnowledgeBase` |
| `sec-federation-001` | Low | Reports identity management type as an informational prompt — SAML federation and Connect-managed identity paired with a third-party IdP (Okta, Entra ID) for MFA are both viable; this doesn't mandate one |
| `sec-flow-auth-001` | Low | Contact flows routing to agent queues without an upstream authentication step — optional and depends on whether the destination queue exposes sensitive account operations; AWS's default sample flows are excluded |
| `cx-personalization-001` | Low | Personalization patterns and transfer types per flow (CX quality signal, informational) |

**Note on removed security checks:** two earlier checks were removed after user feedback that they emitted HIGH-severity failures without inspecting the thing they claimed to check.

* `security-encryption-001` (`EncryptionConfigurationCheck`) failed HIGH for every S3 or Lambda integration with the string "requires encryption validation" — but it never fetched the buckets' encryption configuration or the functions' environment encryption. It was a placeholder that shipped as a finding. Real signal now comes from `sec-storage-001`, which actually calls `ListInstanceStorageConfigs` and checks each storage type's encryption settings.
* `security-network-001` (`NetworkSecurityCheck`) failed HIGH for `CONNECT_MANAGED` identity ("ensure strong password policies") and for having both inbound + outbound calling enabled ("ensure proper access controls"). Neither is a network-security defect — the first is an identity choice, the second is the majority Amazon Connect Customer deployment shape. The check inspected zero actual network configuration. Identity-federation posture is now covered by `sec-federation-001`, which is honest about being an identity check and, per reviewer feedback, no longer implies SAML is the only acceptable option — Connect-managed identity paired with a third-party IdP for MFA is also viable.

---

## Resilience — 13 checks

| Check ID | Severity | What it evaluates |
|---|---|---|
| `res-acgr-config-001` | Low | Discovery only: reports whether Amazon Connect Global Resiliency (ACGR) is configured. Returns **Not Applicable** for instances without ACGR (~95% of deployments), so those reports show nothing about ACGR at all. When ACGR is present, the five `res-acgr-*` audit checks below verify each aspect. |
| `res-acgr-identity-001` | High | When ACGR is configured, the instance uses SAML 2.0 identity management. Agents can only fail over via Global Sign-in, which requires SAML — CONNECT_MANAGED and EXISTING_DIRECTORY leave agents stranded on failover. |
| `res-acgr-tdg-status-001` | High | When ACGR is configured, every traffic distribution group is in ACTIVE status. Non-ACTIVE TDGs (CREATION_FAILED, PENDING_DELETION, etc.) cannot serve failover traffic. |
| `res-acgr-traffic-dist-001` | High | When ACGR is configured, traffic is distributed across regions rather than pinned 100% to one region. A 100/0 split leaves the standby region unexercised. |
| `res-acgr-failover-test-001` | High | When ACGR is configured, CloudTrail shows at least one `UpdateTrafficDistribution` event in the last 90 days — evidence the failover path has been exercised recently. |
| `res-acgr-numbers-001` | High | When ACGR is configured, inbound phone numbers are claimed against a TDG ARN rather than the instance ARN. Numbers bound directly to the instance do not fail over. |
| `res-cloudwatch-001` | High | CloudWatch alarms exist for critical Connect metrics (ConcurrentCalls, ThrottledCalls, MissedCalls, CallsPerInterval) |
| `res-flow-errors-001` | High | Error-capable actions in contact flows have defined error transitions (no dead-end paths) |
| `res-carrier-diversity-001` | Medium | Phone numbers span more than one country, or a traffic distribution group is present. FAIL remediation points to Amazon Connect Global Resiliency (ACGR) rather than claiming numbers in another country, which is rarely realistic |
| `res-flow-loops-001` | Medium | No unbounded cycle patterns in contact flows that could trap callers |
| `res-lambda-dependency-001` | Medium | Evaluates every reachable Lambda call site independently and flags a VPC-attached function invocation that lacks an error transition. Unreachable calls are ignored; dynamic references, lookup failures, and partial analysis prevent an unqualified PASS, while a known risk remains FAIL with the limitations recorded. |
| `res-hardcoded-routing-001` | Low | Observational note on customer-authored flows using literal phone numbers/ARNs instead of a contact attribute reference — hardcoding is a normal, common pattern in contact centers, not a defect; AWS's default sample flows are excluded from the count |
| `ai-ops-cross-region-001` | Low | For instances with a Q assistant integration, reports system-defined Bedrock inference profiles in the account/region as planning context. The result proves availability only, not that the Q workload uses cross-region inference; without a Q assistant integration, the check is Not Applicable. |

**About the `res-acgr-*` set:** the six checks work together. When ACGR is configured, `res-acgr-config-001` returns PASS with the TDG names in the evidence, and the five audit sub-checks evaluate identity, TDG status, traffic distribution, failover testing, and phone-number binding. When ACGR is not configured, every check in the set returns **Not Applicable** — instances without ACGR see no findings, no observations, no clutter about ACGR at all. This deliberate design means the tool never nags customers who don't need ACGR, but catches half-configured ACGR — which is worse than no ACGR because the customer believes they have DR they don't.

**Note on removed resilience checks:** three earlier checks (`resilience-multi-az-001`, `resilience-dr-001`, and `resilience-failover-001`) were removed after user feedback that they fired on trivially-true conditions and asserted things the tool cannot verify — contact-flow export cadence, multi-AZ configuration that AWS manages automatically, and routing-profile counts (having only one routing profile isn't a resilience deficiency, it's a deployment shape). Substantive resilience signal now lives in the `res-acgr-*` set and the flow-content checks in `contact_flow_behavior_checks.py`.

---

## Caller Journey Map (report section, not a check)

The HTML report includes an interactive **Caller Journey Map** section for contact flows callers can actually reach. This is a **phone-number-first** view: the assessment enumerates claimed numbers and resolves each number's assigned flow with `connect:ListFlowAssociations`, matching association `ResourceId` to `PhoneNumberArn` across the supported voice, SMS, and WhatsApp phone-number resource types. It does not infer the flow from `ListPhoneNumbersV2.TargetArn`; that field identifies the Connect instance or traffic distribution group that receives inbound traffic, not the flow selected in the console.

Flows that are not associated with an inbound number (subflows, test flows, internal transfer targets, and AWS-provided defaults) are excluded from this report section. Numbers associated with a queue, agent, or no flow are omitted because there is no contact-flow diagram to render. Entries are sorted deterministically by instance display name and phone number. There is no metric-based ranking or top-N cap; every renderable flow-bound number is included, while a flow shared by multiple numbers is rendered once per instance and reused.

**Server-rendered projected map.** The CLI parses the contact flow and projects implementation-level actions into a smaller caller-focused model: caller-visible steps remain explicit, connected internal setup work becomes an inspectable group, duplicate physical transitions share a connector, and technical outcomes receive reader-facing labels. Python computes the deterministic left-to-right node positions and orthogonal connectors while generating the self-contained report. Browser code does not lay out the graph; it switches among already-rendered entries, applies interaction controls, and displays the inspector.

Each card's color represents the customer experience:

| Category | Color | Examples |
|---|---|---|
| **speaks** | green | `PlayPrompt`, `MessageParticipant` |
| **chooses** | blue | `GetUserInput`, `StoreCustomerInput`, `ConnectToLexBot` |
| **waits** | yellow | `TransferToQueue`, `CreateCallback`, `Wait` |
| **terminal** | red | `DisconnectParticipant`, `TransferParticipantToThirdParty`, `TransferToFlow` |
| **processing** | gray dashed | `InvokeLambdaFunction`, `SetContactAttributes`, `CheckAttribute` |

**Interactive legibility.** Diagrams retain their computed native width instead of being compressed to the report panel. Readers can pan a wide map, zoom from 20% to 300%, or use **Fit to window** without relaying out or squishing nodes. Selecting a node or connector opens an inspector with the caller-facing summary, underlying scope, outcomes, and enriched queue or AI resource identity when available. Flows over 150 authored actions use a placeholder rather than an unreadable diagram.

**Portable exports.** Every successfully rendered map can be downloaded as self-contained SVG, browser-generated PNG, or editable diagrams.net/draw.io XML derived from the same accepted server-side layout.

**Configuration.** The HTML map has no `top_n` or metric-ranking setting — it renders every available flow-bound number. The `journey_map.max_paths_per_did`, `journey_map.max_depth`, and `journey_map.max_traffic_flows` settings below apply to the separate journey-scoring pipeline, not the HTML map renderer. `--skip-flow-analysis` (CLI) / `skip_flow_analysis: true` (config) disables both.

**Required IAM.** `connect:ListPhoneNumbersV2` and `connect:ListFlowAssociations` (both already in the standard IAM policy artifacts) discover numbers and their assigned flows, with the existing read permissions fetching flow content. If either operation is denied, the report shows an empty-state explanation naming the missing permission rather than a partial map.

---

## Cost Optimization — 15 checks

| Check ID | Severity | What it evaluates |
|---|---|---|
| `cost-containment-001` | High | Contact flows use self-service automation (IVR, bots, lookups) before routing to agents |
| `cost-wait-time-001` | High | Flows routing to queues offer a callback option (reduces hold-time telephony costs) |
| `cost-inefficient-001` | Medium | Unbalanced queue distributions and suboptimal routing configuration |
| `cost-usage-metrics-001` | Medium | CloudWatch call volume over 30 days — flags unused or under-utilized instances |
| `cost-unused-numbers-001` | Medium | Claimed phone numbers are listed for manual traffic verification because the available Connect metrics do not provide a per-number filter; evidence gives a supported worst-case monthly exposure, not measured savings |
| `cost-occupancy-001` | Medium | Agent occupancy metrics are available — informational flag for staffing cost review |
| `cost-fcr-001` | Medium | Contact flows perform returning-caller detection for routing optimization and FCR tracking |
| `cost-data-continuity-001` | Medium | IVR data (DTMF, bot slots, Lambda lookups) is stored in contact attributes before queue transfer so agents don't re-ask — a real handle-time cost, since every unsaved input means a repeated question |
| `cost-premium-features-001` | Low | Contact Lens, Wisdom, or Cases is enabled in instance attributes but appears unconfigured |
| `cost-unused-001` | Low | Unused security profiles, routing profiles, or queues — an administrative-clarity observation, not a cost-savings estimate; Connect doesn't charge per profile/queue |
| `cost-oversized-001` | Low | Security-profile/routing-profile/queue ratios relative to users — administrative-clarity observation, not a cost-savings estimate. (A prior "high contact flow count" heuristic was removed: AWS recommends more, smaller modular flows, so a high flow count is the expected shape, not a defect.) |
| `cost-hours-mismatch-001` | Low | Hours of Operation vs. CloudWatch call volume patterns — flags scheduling mismatches |
| `cost-acw-001` | Low | ACW duration monitoring — informational flag to review excessive after-call work time |
| `cost-self-service-tier-001` | Low | Evaluates each reachable customer-authored route to an agent queue and identifies DTMF input without Lex on that same route. Lex on another branch does not suppress the opportunity; incomplete or capped analysis is reported as a limitation rather than a clean PASS. |
| `ai-ops-model-cost-001` | Low | Reviews assistant-scoped model IDs from `wisdom:ListAIPrompts` for premium-family hints. A match is a workload-specific cost/quality review signal, not an unconditional recommendation to change models. |

---

## Operational Excellence — 6 checks

| Check ID | Severity | What it evaluates |
|---|---|---|
| `ops-logging-001` | High | Contact flow logging is enabled for CloudWatch Logs (required for troubleshooting) |
| `ai-ops-kb-sync-001` | Medium | Evaluates Q in Connect knowledge-base lifecycle separately from ingestion status using `wisdom:GetKnowledgeBase`. CREATE_FAILED or DELETE_FAILED lifecycle and SYNC_FAILED ingestion are failures; only lifecycle ACTIVE with ingestionStatus SYNC_SUCCESS passes, while transient, inactive, missing, or unknown states are Skipped with bounded evidence. |
| `ai-ops-bedrock-logging-001` | Medium | For instances with a Q assistant integration, verifies that the regional Bedrock model invocation logging configuration has a CloudWatch Logs or S3 destination. It does not prove per-assistant delivery; without a Q assistant integration, the check is Not Applicable. |
| `ops-unreachable-blocks-001` | Low | Traverses default, conditional, and error transitions from a valid entry point to find unreachable customer-authored actions. A known unreachable block remains FAIL even when other discovery is incomplete; incomplete analysis without a known issue is Skipped rather than treated as healthy. |
| `ops-early-media-001` | Low | Early media audio enabled for outbound calls (agents hear ringing/busy signal) |
| `ops-auto-resolve-001` | Low | Reports whether `AUTO_RESOLVE_BEST_VOICES` is enabled so Amazon Connect can substitute an equivalent same-locale Polly voice when a flow's SSML `<voice>` choice is unavailable; this is unrelated to the Task channel |

---

## Performance Efficiency — 3 checks

| Check ID | Severity | What it evaluates |
|---|---|---|
| `perf-lambda-count-001` | Low | Observational Lambda usage structure inventory: authored, reachable, and unreachable Lambda blocks plus the bounded maximum on one simple route. It normalizes both `FunctionArn` and `LambdaFunctionARN`, emits detailed per-action evidence, and does not apply a numerical AWS compliance threshold. |
| `perf-flow-complexity-001` | Low | Observational flow structure inventory: total/reachable actions, longest simple route, integrations, cycles, bounded path enumeration, and module use. It does not apply a numerical AWS compliance threshold. |
| `perf-sequential-lambda-001` | Low | Reachable routes where one Lambda reaches another before a customer-facing interaction. Evidence includes both functions, mode/timeout, intermediate path, transition type, and error branches. |

The Lambda usage structure review follows published Amazon Connect Lambda behavior guidance but does not invent a maximum block count: total authored blocks, reachable blocks, and the bounded maximum on one simple route are presented as distinct observational measures. Its PASS means inventory completed, not that a particular count is optimal. The flow structure review similarly follows guidance to keep flows small, modular, and reusable while acknowledging that AWS does not publish a numerical complexity cutoff. Sequential-Lambda remediation remains conditional on data dependencies and preserves timeout and error-branch semantics.

---

## Caller Journey Mapping — 4 findings

These findings are produced by a separate pipeline (`journey.run_journey_mapping()`, invoked from `AssessmentEngine._compute_journey_findings`) that analyzes the instance-wide caller path topology — they are not part of the check registry and will not appear in `--list-checks` output. They require `connect:ListPhoneNumbersV2` and `connect:ListFlowAssociations` permissions (the latter resolves which flow each number is assigned to — `ListPhoneNumbersV2`'s `TargetArn` is the instance/TDG ARN, not the flow ARN) and are skipped when `--skip-flow-analysis` is used (either the top-level `skip_flow_analysis` config key or the CLI's `--skip-flow-analysis` flag, which is stored under `cli.skip_flow_analysis`).

| Check ID | Severity | What it evaluates |
|---|---|---|
| `journey-sec-001` | High | Caller journey reaches an agent queue without any authentication step (PIN, Lambda verify, DTMF validation). Reports per-phone-number with the count of unauthenticated paths. |
| `journey-cost-001` | High | All enumerated paths from a phone number route to agents without any self-service automation (Lex bot, DTMF menu, Lambda lookup). Indicates zero containment opportunity. |
| `journey-res-001` | High | Dead-end caller path — flow logic disconnects the caller without offering a callback, queue transfer, or bot resolution. Indicates a resilience gap. |
| `journey-scope-001` | Low | More than 5 contact flows are dormant (not reachable from any phone number, zero tier-1/tier-2 traffic). Candidates for cleanup. |

### How the pipeline works

1. **Topology resolution** — discovers all phone numbers (DID + toll-free) associated with the instance and identifies which contact flows they route to.
2. **Super-graph construction** — stitches individual contact flow graphs together at transfer/module boundaries into an instance-wide directed graph.
3. **Path enumeration** — traces every possible caller journey from each phone number entry point to a terminal outcome (agent queue, disconnect, callback, external transfer) using bounded DFS.
4. **Journey scoring** — evaluates each path for security (authentication), self-service automation, callback offerings, personalization, NLU/bot usage, and CX maturity.
5. **Finding generation** — produces the findings above for paths that reach agent queues without authentication, have zero self-service options, or dead-end into disconnects.

### Tier classification

Flows are classified into three tiers to scope analysis and avoid wasted API calls:

- **Tier 1** — directly reachable from a phone number (DID or toll-free) or transitively reachable via transfer edges.
- **Tier 2** — receives traffic but not phone-anchored (future: metric-based detection).
- **Tier 3 (dormant)** — unreachable from any entry point; candidates for cleanup.

### Configuration

```yaml
journey_map:
  max_paths_per_did: 200    # Max paths to enumerate per phone number
  max_depth: 50             # Max DFS depth per path
  max_traffic_flows: 10     # Reserved for tier-2 traffic classification
```

---

## Skipped findings

A check returns **Skipped** (not Fail) when it cannot complete its evaluation. A denied API call names the missing permission; partial pagination, failed detail lookup, incomplete flow analysis, or transient/unknown resource state records a bounded limitation. Grant missing access or resolve the recorded limitation and re-run. Partial observations never become an unqualified PASS.

Common permissions that cause skips if missing:

| Permission | Checks affected |
|---|---|
| `cloudtrail:DescribeTrails` | `sec-cloudtrail-001` |
| `cloudtrail:LookupEvents` | `res-acgr-failover-test-001` |
| `cloudwatch:DescribeAlarms` | `res-cloudwatch-001` |
| `connect:ListTrafficDistributionGroups` | all `res-acgr-*`, `res-carrier-diversity-001` |
| `connect:DescribeTrafficDistributionGroup` | `res-acgr-tdg-status-001` |
| `connect:GetTrafficDistribution` | `res-acgr-traffic-dist-001` |
| `connect:ListPhoneNumbersV2`, `connect:ListFlowAssociations` | `journey-sec-001`, `journey-cost-001`, `journey-res-001`, `journey-scope-001` |
| `connect:ListIntegrationAssociations` | all six `ai-ops-*` checks |
| `iam:GetRolePolicy` | `sec-iam-deep-001`, `sec-excessive-agency-001` |
| `lambda:GetPolicy` | `sec-ai-lambda-001`, `sec-excessive-agency-001` |
| `lambda:GetFunction` | `res-lambda-dependency-001` |
| `kms:DescribeKey` | `sec-storage-001` |
| `wisdom:ListAIGuardrails` | `ai-ops-guardrail-001` |
| `wisdom:GetAssistant` | `ai-ops-encryption-001` |
| `wisdom:GetKnowledgeBase` | `ai-ops-encryption-001`, `ai-ops-kb-sync-001` |
| `wisdom:ListAIPrompts` | `ai-ops-model-cost-001` |
| `bedrock:GetModelInvocationLoggingConfiguration` | `ai-ops-bedrock-logging-001` |
| `bedrock:ListInferenceProfiles` | `ai-ops-cross-region-001` |

## Permissions

[`docs/iam-policy-template.json`](iam-policy-template.json) is the generated canonical IAM policy document for assessment access. [`cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`](../cloudformation/AmazonConnectSelfAssessmentPolicy.yaml) deploys the same action set with attachment options. The IAM artifacts use the `wisdom:*` authorization prefix for Q in Connect control-plane calls even though boto3 exposes the service through its `qconnect` client name.

---

## Running a subset of checks

```bash
# One pillar only
amazon-connect-assessment --pillars security --region us-east-1

# Critical and high only
amazon-connect-assessment --severity critical high --region us-east-1

# Specific check IDs
amazon-connect-assessment --checks sec-toll-fraud-001 res-acgr-config-001 sec-cloudtrail-001

# Exclude checks you've accepted as risk
amazon-connect-assessment --exclude-checks cost-acw-001 ops-auto-resolve-001

# Skip contact-flow content checks and their API calls (faster — skips 26 checks)
amazon-connect-assessment --skip-flow-analysis --region us-east-1
```
