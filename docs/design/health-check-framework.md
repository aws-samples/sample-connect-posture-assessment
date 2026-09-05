# 🏗️ Amazon Connect Customer Health Review Framework

## Comprehensive Programmatic Audit: Reliability, Security, Cost Optimization & CX

> **Status:** Design and reference material. This document describes the broader
> health-review framework and proposed roadmap; it is not the contract for the
> currently implemented scanner. For implemented checks and runtime behavior, use
> [the check catalog](../check-catalog.md), [the configuration guide](../configuration.md),
> and the [development guide](../development-guide.md).

> **Goal**: Run scripts against a customer's Amazon Connect Customer instance to produce a "mirror" of how they use Amazon Connect Customer today — then give actionable recommendations to improve resilience, security, cost efficiency, and end-customer experience. *Consolidated from: AWS Specialist Agent TFC knowledge, Neura Connect Orchestration Agent, and internal SA framework.*

---

## Table of Contents

1. [Reliability & Resilience](#1-reliability--resilience)
2. [Security](#2-security)
3. [Cost Optimization](#3-cost-optimization)
4. [Feature Adoption & CX Optimization](#4-feature-adoption--cx-optimization)
5. [Contact Flow Analysis & Journey Mapping](#5-contact-flow-analysis--journey-mapping)
6. [The Customer Mirror — Report Output](#6-the-customer-mirror)
7. [Implementation Reference](#7-implementation-reference)

---

## 1. Reliability & Resilience

### 1.1 Instance Architecture & Attributes

**API call sequence:**

```python
# Step 1: Enumerate all instances (across all regions for DR check)
connect.list_instances()
# Returns: InstanceSummaryList[].{Id, Arn, InstanceStatus, IdentityManagementType}

# Step 2: Describe each instance
connect.describe_instance(InstanceId=instance_id)
# Returns: Instance.{StatusReason, InboundCallsEnabled, OutboundCallsEnabled, ServiceRole}

# Step 3: Check all instance attributes
for attr in ['INBOUND_CALLS', 'OUTBOUND_CALLS', 'CONTACT_LENS', 'AUTO_RESOLVE_BEST_VOICES',
             'CONTACTFLOW_LOGS', 'CONTACT_RECORDING', 'EARLY_MEDIA', 'USE_CUSTOM_TTS_VOICES',
             'HIGH_VOLUME_OUTBOUND', 'ENHANCED_CONTACT_MONITORING', 'MULTI_PARTY_CONFERENCE']:
    connect.describe_instance_attribute(InstanceId=id, AttributeType=attr)

```

| Check | API / Method | What You're Looking For |
| --- | --- | --- |
| Single-region deployment | `connect:ListInstances` across regions | Instance in only 1 region → **no DR**. Flag as CRITICAL. |
| Identity management type | `DescribeInstance` → `IdentityManagementType` | `CONNECT_MANAGED` or `EXISTING_DIRECTORY` = **ACGR ineligible** (SAML 2.0 required for Global Resiliency) |
| Contact flow logs enabled | `DescribeInstanceAttribute(CONTACTFLOW_LOGS)` | Value = 'false' → no flow execution logs, can't debug failures |
| Contact Lens enabled | `DescribeInstanceAttribute(CONTACT_LENS)` | Value = 'false' → no conversational analytics |
| Instance status | `DescribeInstance` → `InstanceStatus` | ACTIVE expected; anything else = issue |

### 1.2 Global Resiliency (ACGR) Readiness

```python
# Check if Traffic Distribution Groups exist (indicates ACGR adoption)
connect.list_traffic_distribution_groups(InstanceId=instance_arn)
# EMPTY = HIGH RISK — no multi-region capability

# If TDGs found, check current traffic distribution
connect.get_traffic_distribution(Id=tdg_id)
# Returns: TelephonyConfig.{DistributeByPercentage: [{Region, Percentage}]}
# RISK: If one region has 100% — no active-active, purely passive DR

# Check TDG status
connect.describe_traffic_distribution_group(TrafficDistributionGroupId=tdg_id)
# Status values: CREATION_IN_PROGRESS | ACTIVE | CREATION_FAILED | PENDING_DELETION

# Phone number association to TDGs
connect.list_phone_numbers_v2(TargetArn=tdg_arn)

# Failover testing evidence — check CloudTrail for recent failover calls
cloudtrail.lookup_events(
    LookupAttributes=[{'AttributeKey':'EventName','AttributeValue':'UpdateTrafficDistribution'}],
    StartTime=90_days_ago
)
# Zero events in 90 days = MEDIUM risk (untested failover)

```

| Check | What You're Looking For | Severity |
| --- | --- | --- |
| No Traffic Distribution Groups | Instance has no multi-region DR. Failover is manual + DNS. | CRITICAL |
| TDG exists but 100/0 split | Passive DR only — standby not exercised | HIGH |
| TDG present but no test in 90 days | Untested failover plan | MEDIUM |
| `CONNECT_MANAGED` identity | ACGR ineligible — agents can't use Global Sign-in | HIGH |
| Lambda/Lex not deployed in DR region | IVR breaks during failover | HIGH |
| S3 buckets, Kinesis streams not replicated | Data continuity risk | HIGH |
| No BCP runbook or test schedule | Process gap | MEDIUM |

### 1.3 Phone Number & Telephony Resilience

```python
connect.list_phone_numbers_v2(InstanceId=instance_id)
# Check: TargetArn, PhoneNumberStatus, PhoneNumberType

```

| Check | What You're Looking For |
| --- | --- |
| Numbers in only 1 region | SPOF for inbound calls |
| Numbers not mapped to any flow | `TargetArn` = instance but no flow → dead air |
| Critical numbers without fallback flows | Error handling must catch and reroute |
| Numbers pointing to deleted/unpublished flows | Customers hear nothing |
| Over-reliance on single number type | Diversify DID + TF |

### 1.4 Queue & Routing Health

```python
# Real-time metrics
connect.get_current_metric_data(
    InstanceId=id,
    Filters={'Queues': queue_ids},
    CurrentMetrics=[
        {'Name': 'OLDEST_CONTACT_AGE', 'Unit': 'SECONDS'},
        {'Name': 'CONTACTS_IN_QUEUE', 'Unit': 'COUNT'},
        {'Name': 'AGENTS_AVAILABLE', 'Unit': 'COUNT'},
    ]
)

# Historical
connect.get_metric_data_v2(
    ResourceArn=instance_arn,
    Filters=[{'FilterKey': 'QUEUE', 'FilterValues': queue_ids}],
    Metrics=[
        {'Name': 'ABANDONMENT_RATE'},
        {'Name': 'SERVICE_LEVEL'},
        {'Name': 'AVG_QUEUE_ANSWER_TIME'},
    ]
)

```

| Check | Flag |
| --- | --- |
| Queues with no routing profiles assigned | Dead-end routing risk |
| Routing profiles with no agents | Contacts route but nobody answers |
| No callbacks configured on high-volume queues | High abandonment |
| No default customer queue flow (hold music/prompts) | Customers hear silence |
| `OLDEST_CONTACT_AGE` > 5 min regularly | Capacity/routing issue |

### 1.5 CloudWatch Metrics & Alarms

| Metric | Dimension | Risk Threshold | Action |
| --- | --- | --- | --- |
| `ConcurrentCalls` | InstanceId | >80% of service quota | Anomaly detection alarm |
| `ConcurrentCallsPercentage` | InstanceId | >80% | Static + anomaly |
| `CallsBreachingConcurrencyQuota` | InstanceId | >0 (Sum) | Any breach = CRITICAL |
| `ContactFlowErrors` | ContactFlowName | >0 sustained | Per-flow alarm |
| `ContactFlowFatalErrors` | ContactFlowName | >0 | Immediate alert |
| `MisconfiguredPhoneNumbers` | InstanceId | >0 | Immediate |
| `MissedCalls` | InstanceId | >5% of total | Trend-based |
| `QueueSize` | QueueName | >80% of max | Per-queue |
| `LongestQueueWaitTime` | QueueName | >SLA target | Baseline required |
| `CallBackNotDialableNumber` | ContactFlowName | >0 | Alert |
| `ToInstancePacketLossRate` | InstanceId, Stream | >1% | Voice quality degradation |
| `LambdaFunctionErrors` | - | >0 | Flow breakdown indicator |

**Alarm audit:**

```python
cloudwatch.describe_alarms(AlarmNamePrefix='Connect')
# Also: describe_alarms for namespace 'AWS/Connect'
# FINDING: No alarms = blind to operational failures

```

### 1.6 Data Streaming & Backup

| Check | API | Flag |
| --- | --- | --- |
| CTR streaming to Kinesis | `DescribeInstance` → check Kinesis config | Not enabled = compliance/audit risk after 2-year internal limit |
| Agent events streaming | `DescribeInstance` → Kinesis Agent Events | No streaming = no real-time workforce visibility |
| S3 lifecycle policies | `s3:GetBucketLifecycleConfiguration` | No policies = unbounded storage cost |
| Contact flow logs | `CONTACTFLOW_LOGS` attribute | Disabled = can't debug incidents |

---

## 2. Security

### 2.1 Identity & Access Management

```python
# Enumerate security profiles
connect.list_security_profiles(InstanceId=id)
for sp_id in security_profile_ids:
    connect.describe_security_profile(SecurityProfileId=sp_id, InstanceId=id)
    # RED FLAGS in .SecurityProfile.Permissions[]:
    #   - All users on a single "Admin" profile
    #   - Custom profiles with connect:* wildcards
    #   - BasicAgentAccess assigned to supervisors

# Check user-to-profile mapping
connect.list_users(InstanceId=id)
for user_id in user_ids:
    connect.describe_user(UserId=user_id, InstanceId=id)
    # Returns: User.SecurityProfileIds[] — check for multi-profile over-assignment

```

| Check | What You're Looking For | Severity |
| --- | --- | --- |
| Identity type = `CONNECT_MANAGED` | No SSO, no centralized identity governance, no MFA enforcement | HIGH |
| >20% users with Admin security profile | Violation of least privilege | HIGH |
| Single security profile for all users | No role separation | MEDIUM |
| Dormant users (no login in 90+ days) | Stale credentials, wasted cost | MEDIUM |
| Shared user accounts | Multiple agents on one login — audit trail broken | HIGH |
| IAM policies with `connect:*` wildcard | Overly broad — should scope to instance ARN | HIGH |
| No IAM Access Analyzer scoped to Connect role | Cross-account drift undetected | MEDIUM |

### 2.2 Encryption & Data Protection

```python
# Check storage encryption config for each artifact type
for storage_type in ['CALL_RECORDINGS', 'CHAT_TRANSCRIPTS', 'SCHEDULED_REPORTS',
                     'MEDIA_STREAMS', 'CONTACT_TRACE_RECORDS', 'AGENT_EVENTS',
                     'REAL_TIME_CONTACT_ANALYSIS_SEGMENTS']:
    connect.describe_instance_storage_config(
        InstanceId=id, 
        ResourceType=storage_type
    )
    # Check: StorageConfig.S3Config.EncryptionConfig
    # RISK: No EncryptionConfig OR Type='KMS' but KeyId is AWS-managed (aws/s3)
    # BEST PRACTICE: Customer-managed KMS key (CMK) with explicit KeyId ARN

# Also check integrations KMS
connect.list_integration_associations(InstanceId=id)
# Customer Profiles, Cases — verify KMS configuration

# KMS key health
kms.describe_key(KeyId=connect_kms_key_arn)
kms.get_key_rotation_status(KeyId=connect_kms_key_arn)
# Key rotation should be enabled

```

| Check | What You're Looking For | Severity |
| --- | --- | --- |
| Recordings/CTRs without customer-managed KMS | No customer control over key rotation/revocation | CRITICAL |
| AWS-owned keys only (no BYOK) | Compliance gap for regulated industries | HIGH |
| KMS key rotation not enabled | Key management hygiene | MEDIUM |
| S3 bucket without server-side encryption | Data at rest unprotected | CRITICAL |
| S3 bucket with public access | Recordings exposed | CRITICAL |
| Cross-account principals in bucket/KMS policies | Unexpected access | HIGH |
| Data stored outside expected jurisdiction | Data residency violation | HIGH |

### 2.3 Contact Flow Security

```python
# Parse all flows for security issues
for flow in contact_flows:
    content = json.loads(flow['Content'])
    for action in content['Actions']:
        # Check: Lambda ARNs using aliases (not hardcoded versions)
        if action['Type'] == 'InvokeLambdaFunction':
            arn = action['Parameters'].get('LambdaFunctionARN', {}).get('Value', '')
            # Flag if contains explicit region (breaks ACGR)
            # Flag if contains $LATEST or hardcoded version
        
        # Check: DTMF encryption for sensitive inputs
        if action['Type'] == 'StoreCustomerInput':
            encryption = action['Parameters'].get('EncryptionConfig')
            # No encryption = plaintext card numbers/PINs
        
        # Check: Hardcoded credentials in attributes
        if action['Type'] == 'UpdateContactAttributes':
            # Scan for PII patterns, API keys, hardcoded secrets

```

| Check | What You're Looking For | Severity |
| --- | --- | --- |
| `StoreCustomerInput` without encryption | Credit card/PIN digits captured in plaintext (PCI violation) | CRITICAL |
| No Pause/Resume Recording for sensitive inputs | Card numbers in recordings | HIGH |
| Hardcoded credentials/API keys in flow attributes | Secret exposure in logs | CRITICAL |
| Lambda ARN with hardcoded region | Breaks ACGR failover + ops risk | HIGH |
| PII captured in contact attributes without encryption | Data leakage | HIGH |
| No input validation on DTMF (no max-digit limits) | Injection/overflow risk | MEDIUM |

### 2.4 Logging & Auditing

```python
# Verify CloudTrail
cloudtrail.get_trail_status(Name=trail_name)
# Check: IsLogging=True

cloudtrail.describe_trails()
# RISK: Trail S3 bucket in same account — no separation of duties

# CloudTrail log validation
# Check: LogFileValidationEnabled = True

# Contact flow logs per-flow check
for flow in flows:
    content = json.loads(flow['Content'])
    # Look for 'SetLoggingBehavior' blocks or logging enabled flag

```

| Check | What You're Looking For | Severity |
| --- | --- | --- |
| `CONTACTFLOW_LOGS` = false | No flow execution trace — compliance + debug gap | CRITICAL |
| CloudTrail not enabled/logging | No API audit trail | CRITICAL |
| CloudTrail without S3 delivery (console only = 90-day limit) | Audit gap beyond 90 days | HIGH |
| CloudTrail log file validation disabled | Tamper detection missing | MEDIUM |
| No Amazon Macie on recording/transcript S3 buckets | Undetected PII exposure | MEDIUM |
| S3 access logging disabled on sensitive buckets | No data access audit trail | MEDIUM |
| No CloudWatch alarms on Connect metrics | Blind to operational degradation | HIGH |

---

## 3. Cost Optimization

### 3.1 Usage & Spend Visibility

```python
# Cost Explorer
ce.get_cost_and_usage(
    TimePeriod={'Start': '2024-01-01', 'End': '2024-12-31'},
    Filter={'Dimensions': {'Key': 'SERVICE', 'Values': ['Amazon Connect']}},
    Granularity='MONTHLY',
    Metrics=['UnblendedCost']
)

```

| Check | What You're Looking For |
| --- | --- |
| Connect Cost Insight Dashboard deployed? | Built-in visibility tool — often not activated |
| AWS Cost Allocation Tags on Connect instance? | No tags = no cost attribution to business units |
| Per-channel cost breakdown visible? | Voice vs. Chat vs. Tasks — identify channel cost efficiency |

### 3.2 Phone Number & Telephony Cost Leaks

```python
# All claimed numbers
numbers = connect.list_phone_numbers_v2(InstanceId=id)

# Cross-reference with actual usage (CTRs or metrics)
for number in numbers['ListPhoneNumbersSummaryList']:
    # Check if any contacts received in last 90 days
    # Each DID: ~$0.06/day ($1.80/month), TF: ~$0.06/day + per-minute
    pass

# PSTN vs WebRTC analysis
# WebRTC (softphone) calls = zero telephony charges
# Check agent configuration for softphone vs. desk phone

```

| Check | Finding | $ Impact |
| --- | --- | --- |
| Claimed numbers with 0 contacts in 30+ days | Unused rental | ~$1.80/month per DID |
| Numbers not assigned to any flow | Definitely unused | Same |
| High PSTN volume with no WebRTC strategy | Missed cost reduction | Significant (per-min charges) |
| International/premium numbers with low volume | High per-min cost | Varies |
| Outbound campaigns to non-optimized numbers | Premium rates | Check outbound rate cards |

### 3.3 Self-Service Containment (Biggest Cost Lever)

```python
# IVR containment rate calculation
metrics = connect.get_metric_data_v2(
    ResourceArn=instance_arn,
    Metrics=[
        {'Name': 'CONTACTS_HANDLED'},          # Reached an agent
        {'Name': 'CONTACTS_QUEUED'},           # Entered queue
    ]
)
# Containment rate = 1 - (contacts_queued / total_contacts_entering_flow)
# Industry target: >30% self-served

```

| Check | Finding | Recommendation |
| --- | --- | --- |
| Containment rate <20% | Massive self-service opportunity | Deploy Lex/AI agent on top 5 contact reasons |
| No Lex/AI agent on high-volume intents | Agents handling automatable queries | Add self-service for balance checks, status inquiries, FAQ |
| High transfer rate from IVR to agent (>80%) | Self-service gap | Analyze what customers ask for, build intents |
| No AI agents (agentic self-service) deployed | Missing next-gen containment | Implement Amazon Connect Customer AI agents |

### 3.4 Agent Efficiency & Handle Time

```python
connect.get_metric_data_v2(
    ResourceArn=instance_arn,
    Metrics=[
        {'Name': 'AVG_HANDLE_TIME'},
        {'Name': 'AVG_AFTER_CONTACT_WORK_TIME'},
        {'Name': 'AGENT_OCCUPANCY'},
        {'Name': 'AGENT_IDLE_TIME'},
        {'Name': 'CONTACTS_TRANSFERRED_OUT'},
    ]
)

```

| Check | Flag | Recommendation |
| --- | --- | --- |
| High ACW (>3 min average) + no automated summaries | Manual wrap-up cost | Enable Contact Lens auto-summarization |
| High agent idle time + high queue wait simultaneously | Scheduling/forecasting gap | Deploy Forecasting, Capacity Planning & Scheduling |
| Transfer rate >20% | Double-charging (2 agent sessions per contact) | Improve first-contact routing, skills-based routing |
| Increasing AHT trend | Growing cost per contact | Enable real-time agent assist (Q in Connect) |
| Agents <30% utilized consistently | Over-staffed or misrouted | Review routing profiles |

### 3.5 Inactive Users / Wasted Licensing

```python
# Check agent activity via CloudTrail
connect.list_users(InstanceId=id)
for user_id in user_ids:
    # Check CloudTrail for login events in last 90 days
    cloudtrail.lookup_events(
        LookupAttributes=[{'AttributeKey':'Username','AttributeValue':username}],
        StartTime=90_days_ago
    )
    # No events = likely inactive agent seat

# Also check: routing profiles with zero queues assigned
connect.list_routing_profile_queues(RoutingProfileId=rp_id, InstanceId=id)
# Zero queues = agent can never receive contacts = unused seat

```

### 3.6 Storage Cost Optimization

| Check | Finding | Fix |
| --- | --- | --- |
| No S3 lifecycle policies on recording bucket | Recordings accumulate at Standard pricing indefinitely | Transition → S3-IA (30d) → Glacier (90d) → delete at compliance limit |
| Contact Lens enabled on ALL flows including IVR | Analyzing self-service minutes ($$ per analyzed min) | Scope to agent-handled contacts only |
| CloudWatch Logs retention = indefinite | Unbounded log costs | Set 30/90 day retention |
| Recording 100% of calls | Blanket policy when only some require it | Selective recording based on queue/flow |
| No Contact Lens usage despite being enabled | Paying for capability not utilized for QM | Disable or start using for value |
| Outbound Campaigns capacity consistently <20% | Under-utilized licensed capacity | Right-size or increase campaign volume |

---

## 4. Feature Adoption & CX Optimization

### 4.1 Feature Detection Matrix (All API-Driven)

```python
# === TIER 1: Instance-level feature flags ===
feature_flags = {}
attributes_to_check = {
    'CONTACT_LENS': 'Contact Lens (Voice & Chat Analytics)',
    'HIGH_VOLUME_OUTBOUND': 'Outbound Campaigns',
    'CONTACTFLOW_LOGS': 'Flow Logging',
    'CONTACT_RECORDING': 'Call Recording',
    'EARLY_MEDIA': 'Early Media',
    'AUTO_RESOLVE_BEST_VOICES': 'Amazon Polly Neural TTS',
    'USE_CUSTOM_TTS_VOICES': 'Custom TTS Voices',
    'ENHANCED_CONTACT_MONITORING': 'Enhanced Contact Monitoring',
    'MULTI_PARTY_CONFERENCE': 'Multi-Party Conference',
}
for attr_type, label in attributes_to_check.items():
    resp = connect.describe_instance_attribute(InstanceId=id, AttributeType=attr_type)
    feature_flags[label] = resp['Attribute']['Value'] == 'true'

# === TIER 2: Resource existence checks ===

# Amazon Lex bots
connect.list_bots(InstanceId=id, LexVersion='V2')
connect.list_bots(InstanceId=id, LexVersion='V1')
# Empty = no bot integration → missing self-service

# Voice ID
connect.list_integration_associations(InstanceId=id, IntegrationType='VOICE_ID')

# Amazon Q in Connect / Wisdom
connect.list_integration_associations(InstanceId=id, IntegrationType='WISDOM_ASSISTANT')
connect.list_integration_associations(InstanceId=id, IntegrationType='WISDOM_KNOWLEDGE_BASE')

# Cases
connect.list_integration_associations(InstanceId=id, IntegrationType='CASES_DOMAIN')

# Evaluation Forms (QM)
connect.list_evaluation_forms(InstanceId=id)

# Step-by-step Guides (Views)
connect.list_views(InstanceId=id)

# Forecasting & Scheduling
connect.describe_forecasting_planning_scheduling_integration(InstanceId=id)

# Contact flow modules (reuse indicator)
connect.list_contact_flow_modules(InstanceId=id)

# === TIER 3: CloudWatch metrics for channel usage ===
# Chat
cloudwatch.get_metric_statistics(
    Namespace='AWS/Connect', MetricName='ConcurrentActiveChats',
    Dimensions=[{'Name':'InstanceId','Value':id}],
    Statistics=['Maximum'], StartTime=30_days_ago
)
# Tasks
cloudwatch.get_metric_statistics(
    Namespace='AWS/Connect', MetricName='ConcurrentTasks',
    Dimensions=[{'Name':'InstanceId','Value':id}],
    Statistics=['Maximum'], StartTime=30_days_ago
)
# Outbound Campaigns
cloudwatch.get_metric_statistics(
    Namespace='AWS/Connect', MetricName='ConcurrentHighVolumeCalls',
    Dimensions=[{'Name':'InstanceId','Value':id}],
    Statistics=['Maximum'], StartTime=30_days_ago
)

```

### 4.2 Feature Adoption Scoring

| Feature | Detection Method | If Absent → Risk/Opportunity |
| --- | --- | --- |
| **Contact Lens** | `CONTACT_LENS` attribute + storage config | No QM data, blind CX, no auto-summarization |
| **Amazon Q / Wisdom** | `list_integration_associations(WISDOM_ASSISTANT)` | Agents lack AI-powered knowledge assist |
| **Lex V2 bots** | `list_bots(LexVersion='V2')` | Low IVR containment, high agent cost |
| **AI Agents (Agentic)** | Flow analysis for new agent blocks | Missing next-gen self-service |
| **Voice ID** | `list_integration_associations(VOICE_ID)` | No biometric caller authentication |
| **Cases** | `list_integration_associations(CASES_DOMAIN)` | No integrated case tracking |
| **Evaluation Forms** | `list_evaluation_forms()` non-empty | No structured quality assurance |
| **Forecasting/Scheduling** | Integration status = ACTIVE | Understaffing/overstaffing cycles |
| **Chat channel** | CW `ConcurrentActiveChats > 0` over 30d | Single-channel only (voice) |
| **Tasks** | CW `ConcurrentTasks > 0` over 30d | Manual follow-up work, no automation |
| **Step-by-step Guides** | `list_views()` non-empty | High agent ramp time, inconsistent experience |
| **Outbound Campaigns** | `HIGH_VOLUME_OUTBOUND` + CW metric | Missed proactive CX opportunity |
| **Flow Modules** | `list_contact_flow_modules()` > 3 | Low flow reuse, high maintenance risk |
| **Customer Profiles** | `list_integration_associations` type check | No unified customer context at answer |
| **Real-time agent assist** | Q in Connect + Contact Lens real-time | Agents without live guidance |
| **Post-contact summarization** | Contact Lens auto-summary setting | High ACW, manual note-taking |

### 4.3 CX Improvement Opportunities

| Finding | Recommendation | Impact |
| --- | --- | --- |
| No self-service / all paths → queue | Implement Lex bot for FAQ/simple tasks | High (cost + CX) |
| No callback option on long queues | Add callback — reduces abandonment | High (CSAT + cost) |
| No queue-position announcement | Add position/estimated wait time | Medium (perceived wait) |
| No post-call survey | Implement automated CSAT collection | Medium (measurement) |
| No whisper/hold customization | Better hold experience reduces perceived wait | Low-Medium |
| High repeat contact rate (same customer <24h) | Root cause identification needed | High (cost + CX) |
| No priority/VIP routing | Implement customer segment routing | Medium |
| No skills-based routing | All agents get all calls vs. skill matching | High (FCR) |
| No agent assist / knowledge integration | Deploy Q in Connect | High (AHT + quality) |
| No personalisation at entry | Add Customer Profiles lookup — greet by name | Medium (CX) |
| Hardcoded prompts (no dynamic/SSML) | Move to dynamic — enables A/B testing | Low |
| Long IVR menus (>4 options) | Redesign with NLP input (Lex/AI agent) | High (containment) |
| High Lex fallback rate | Retrain with Theme Detection insights from real customer language | Medium |
| Sentiment drops at specific flow block | That block = friction point — redesign | High (CX) |

---

## 5. Contact Flow Analysis & Journey Mapping

### 5.1 Enumerate & Prioritise Flows

```python
# Get all flows
flows = connect.list_contact_flows(InstanceId=instance_id)

# Rank by contact volume (focus on top 10)
# Use GetMetricDataV2 filtered by CONTACT_FLOW to find highest-volume flows

# For each high-volume flow:
resp = connect.describe_contact_flow(
    InstanceId=instance_id,
    ContactFlowId=flow_id
)
content = json.loads(resp['ContactFlow']['Content'])
# content structure:
#   Version, StartAction, Actions[]
#   Each Action: {Identifier, Type, Parameters{}, Transitions{}}

```

### 5.2 Flow JSON Structure — Block Type Reference

| Block Type | What It Represents | What to Check |
| --- | --- | --- |
| `InvokeLambdaFunction` | External data lookup | `NoMatchingError` branch, region in ARN, timeout value |
| `GetUserInput` | IVR menu / Lex bot | `TimedOut`, `NoMatch`, `MaxDigitsEntered` branches |
| `StoreCustomerInput` | Sensitive data capture | Encryption config for DTMF, error branches |
| `TransferToQueue` | Queue routing | `AtCapacity` branch (essential!), callback option |
| `TransferParticipantToThirdParty` | External transfer | Hardcoded phone number, error branch |
| `MessageParticipant` / `PlayPrompt` | Customer hears prompt | Count consecutive (>3 = consolidate) |
| `CheckAttribute` / `CheckContactAttributes` | Branching logic | Covers all values; has `NoMatch` default |
| `SetContactAttributes` / `UpdateContactAttributes` | Sets metadata | Attribute name collision with reserved names, PII |
| `TransferToFlow` | Hands off to another flow | Circular references, deep nesting |
| `Loop` | Retry logic | Infinite loops, no max-iteration |
| `DisconnectParticipant` | Call ends | Unexpected disconnects (dead ends) |
| `SetWorkingQueue` | Queue assignment | Queue doesn't exist or is empty |
| `Wait` | Delay | Excessive wait times |
| `CreateCallback` | Callback offer | Absence when queue wait is high |

### 5.3 Graph Traversal — Building the IVR Map

```python
def build_flow_graph(content):
    """Builds directed graph from flow JSON. Returns adjacency list + dead ends."""
    blocks = {action['Identifier']: action for action in content['Actions']}
    start = content.get('StartAction')
    
    graph = {}
    dead_ends = []
    
    TERMINAL_TYPES = {'DisconnectParticipant', 'TransferToQueue', 
                      'TransferParticipantToThirdParty', 'EndFlowExecution',
                      'TransferToFlow'}
    
    for block_id, block in blocks.items():
        transitions = block.get('Transitions', {})
        next_actions = []
        
        # Success path
        if 'NextAction' in transitions:
            next_actions.append(transitions['NextAction'])
        
        # Error branches
        for err in transitions.get('Errors', []):
            if err.get('NextAction'):
                next_actions.append(err['NextAction'])
        
        # Condition branches (GetUserInput, CheckAttribute, etc.)
        for cond in transitions.get('Conditions', []):
            if cond.get('NextAction'):
                next_actions.append(cond['NextAction'])
        
        graph[block_id] = next_actions
        
        # Dead end detection
        if not next_actions and block['Type'] not in TERMINAL_TYPES:
            dead_ends.append({
                'block_id': block_id,
                'type': block['Type'],
                'params': block.get('Parameters', {})
            })
    
    return graph, dead_ends, start

```

### 5.4 Anti-Pattern Detection Engine

```python
def detect_antipatterns(content):
    blocks = {a['Identifier']: a for a in content['Actions']}
    findings = []
    
    # ── 1. MISSING ERROR HANDLING ──
    for block_id, block in blocks.items():
        transitions = block.get('Transitions', {})
        errors = transitions.get('Errors', [])
        error_types = [e.get('ErrorType') for e in errors]
        
        if block['Type'] == 'InvokeLambdaFunction':
            if 'NoMatchingError' not in error_types:
                findings.append({
                    'type': 'MISSING_LAMBDA_ERROR_BRANCH',
                    'severity': 'HIGH',
                    'blockId': block_id,
                    'detail': 'Lambda block has no error branch — failure silently breaks flow',
                    'fix': 'Add error branch to graceful fallback (queue transfer or retry)'
                })
        
        if block['Type'] in ['GetUserInput', 'StoreCustomerInput']:
            if 'TimedOut' not in error_types:
                findings.append({
                    'type': 'MISSING_TIMEOUT_HANDLING',
                    'severity': 'HIGH',
                    'blockId': block_id,
                    'detail': 'Input block has no Timeout branch — customer gets stuck in silence',
                    'fix': 'Add Timeout branch with re-prompt (max 2 retries) then queue transfer'
                })
            if 'NoMatch' not in error_types:
                findings.append({
                    'type': 'MISSING_NOMATCH_HANDLING',
                    'severity': 'MEDIUM',
                    'blockId': block_id,
                    'detail': 'Input block has no NoMatch branch',
                    'fix': 'Add NoMatch with re-prompt or agent transfer'
                })
    
    # ── 2. SEQUENTIAL PLAY PROMPTS (>3 in a row) ──
    # Traverse graph to find chains of MessageParticipant/PlayPrompt
    play_chains = find_consecutive_blocks(blocks, 
        types=['MessageParticipant', 'PlayPrompt'], min_chain=3)
    if play_chains:
        findings.append({
            'type': 'SEQUENTIAL_PLAY_PROMPTS',
            'severity': 'MEDIUM',
            'detail': f'{len(play_chains)} chains of 3+ consecutive prompts with no input',
            'fix': 'Consolidate into single SSML prompt or use dynamic prompt from S3'
        })
    
    # ── 3. HARDCODED VALUES ──
    for block_id, block in blocks.items():
        params = block.get('Parameters', {})
        
        # Hardcoded phone numbers in transfers
        if block['Type'] == 'TransferParticipantToThirdParty':
            phone = params.get('ThirdPartyPhoneNumber', {}).get('Value', '')
            if phone and not phone.startswith('$.'):
                findings.append({
                    'type': 'HARDCODED_TRANSFER_NUMBER',
                    'severity': 'HIGH',
                    'blockId': block_id,
                    'detail': f'Transfer to hardcoded number {phone}',
                    'fix': 'Use contact attribute or Lambda lookup for dynamic routing'
                })
        
        # Lambda ARN with hardcoded region (breaks ACGR)
        if block['Type'] == 'InvokeLambdaFunction':
            fn_arn = params.get('LambdaFunctionARN', {}).get('Value', '')
            if fn_arn and any(r in fn_arn for r in ['us-east-1', 'us-west-2', 'eu-west-1']):
                findings.append({
                    'type': 'REGION_HARDCODED_LAMBDA',
                    'severity': 'HIGH',
                    'blockId': block_id,
                    'detail': 'Lambda ARN contains explicit region — ACGR failover will break',
                    'fix': 'Use contact attribute set at flow start, or cross-region alias'
                })
    
    # ── 4. NO CALLBACK OFFERED ──
    has_queue_transfer = any(b['Type'] == 'TransferToQueue' for b in blocks.values())
    has_callback = any(b['Type'] == 'TransferToQueue' and 
                      b.get('Parameters', {}).get('TransferType') == 'CALLBACK'
                      for b in blocks.values())
    if has_queue_transfer and not has_callback:
        findings.append({
            'type': 'NO_CALLBACK_OFFERED',
            'severity': 'MEDIUM',
            'detail': 'Flow transfers to queue but offers no callback option',
            'fix': 'Add GetUserInput branch before TransferToQueue offering callback'
        })
    
    # ── 5. EXCESSIVE FLOW DEPTH ──
    max_depth = calculate_max_path_depth(blocks, content.get('StartAction'))
    if max_depth > 25:
        findings.append({
            'type': 'EXCESSIVE_FLOW_DEPTH',
            'severity': 'MEDIUM',
            'detail': f'Flow has {max_depth} blocks deep — complex maintenance, high error risk',
            'fix': 'Refactor into reusable Flow Modules'
        })
    
    # ── 6. NO ERROR/DEFAULT PATH IN CHECK BLOCKS ──
    for block_id, block in blocks.items():
        if block['Type'] in ['CheckAttribute', 'CheckContactAttributes']:
            transitions = block.get('Transitions', {})
            conditions = transitions.get('Conditions', [])
            # Must have a default/else branch
            if not transitions.get('NextAction'):
                findings.append({
                    'type': 'MISSING_DEFAULT_BRANCH',
                    'severity': 'HIGH',
                    'blockId': block_id,
                    'detail': 'Check block has no default path — unmatched values cause dead end',
                    'fix': 'Add default branch routing to fallback'
                })
    
    # ── 7. DTMF WITHOUT ENCRYPTION ──
    for block_id, block in blocks.items():
        if block['Type'] == 'StoreCustomerInput':
            params = block.get('Parameters', {})
            if not params.get('EncryptionConfig'):
                findings.append({
                    'type': 'UNENCRYPTED_DTMF_INPUT',
                    'severity': 'CRITICAL',
                    'blockId': block_id,
                    'detail': 'Customer input captured without encryption — PCI risk',
                    'fix': 'Add customer encryption key for sensitive digit capture'
                })
    
    return findings

```

### 5.5 Customer Journey Mapping (Programmatic)

```python
def build_customer_journey(content, flow_metrics):
    """
    Builds annotated customer experience map:
    - Each node = what customer experiences
    - Edges = transitions with volume/probability
    - Annotations = time estimate, sentiment, drop-off rate
    """
    actions = content.get('Actions', [])
    start_action = content.get('StartAction')
    
    journey = {
        'entry': start_action,
        'nodes': [],
        'edges': [],
        'summary': {
            'total_contacts': 0,
            'self_served_pct': 0,
            'transferred_pct': 0,
            'abandoned_pct': 0,
            'avg_ivr_time_seconds': 0,
        }
    }
    
    for action in actions:
        node = {
            'id': action['Identifier'],
            'type': action['Type'],
            'customer_experience': categorize_customer_experience(action),
            'time_estimate_seconds': estimate_time_at_node(action),
            'volume': flow_metrics.get(action['Identifier'], {}).get('executions', 0),
            'drop_off_rate': flow_metrics.get(action['Identifier'], {}).get('abandonment', 0),
        }
        journey['nodes'].append(node)
        
        # Build edges from transitions
        transitions = action.get('Transitions', {})
        if transitions.get('NextAction'):
            journey['edges'].append({
                'from': action['Identifier'],
                'to': transitions['NextAction'],
                'condition': 'default',
                'probability': 1.0  # enriched from CTR analysis
            })
        for cond in transitions.get('Conditions', []):
            journey['edges'].append({
                'from': action['Identifier'],
                'to': cond.get('NextAction'),
                'condition': str(cond.get('Condition', {})),
                'probability': 0  # enriched from CTR analysis
            })
    
    return journey

def categorize_customer_experience(action):
    """Maps block type to human-readable customer experience."""
    experience_map = {
        'MessageParticipant': 'Hears announcement',
        'PlayPrompt': 'Hears prompt',
        'GetUserInput': 'Makes a choice (DTMF/speech)',
        'StoreCustomerInput': 'Enters sensitive data',
        'TransferToQueue': 'Waits for agent',
        'TransferParticipantToThirdParty': 'Transferred externally',
        'TransferToFlow': 'Enters sub-experience',
        'DisconnectParticipant': 'Call ends',
        'Wait': 'Waits (silence)',
        'InvokeLambdaFunction': '(Background lookup — customer waits)',
        'CheckAttribute': '(Routing decision — transparent to customer)',
    }
    return experience_map.get(action['Type'], f'System: {action["Type"]}')

```

### 5.6 Enriching with Real Metrics

```python
# Queue performance overlay
queue_metrics = connect.get_metric_data_v2(
    ResourceArn=instance_arn,
    StartTime=start_time,
    EndTime=end_time,
    Filters=[{'FilterKey': 'QUEUE', 'FilterValues': queue_ids}],
    Metrics=[
        {'Name': 'AVG_QUEUE_ANSWER_TIME'},
        {'Name': 'AVG_HANDLE_TIME'},
        {'Name': 'AVG_ABANDON_TIME'},
        {'Name': 'ABANDONMENT_RATE'},
        {'Name': 'CONTACTS_QUEUED'},
        {'Name': 'CONTACTS_HANDLED'},
        {'Name': 'SERVICE_LEVEL'},
        {'Name': 'AVG_HOLD_TIME'},
        {'Name': 'CONTACTS_TRANSFERRED_OUT'},
    ]
)

# Contact Lens sentiment (if enabled)
# Analyze sentiment distribution per flow entry point
# Theme detection on contacts routed through each flow

# Contact Flow Logs (CloudWatch) — execution counts per block
# Log group: /aws/connect/{instanceId}
# Parse logs for: block execution counts, error events, timing

# Agent performance per queue
agent_metrics = connect.get_metric_data_v2(
    ResourceArn=instance_arn,
    Filters=[{'FilterKey': 'ROUTING_PROFILE', 'FilterValues': profile_ids}],
    Metrics=[
        {'Name': 'AGENT_OCCUPANCY'},
        {'Name': 'AVG_HOLD_TIME'},
        {'Name': 'CONTACTS_TRANSFERRED_OUT'},
    ]
)

```

### 5.7 Journey Visualization Output

For each top flow, produce:

| Layer | What You Extract |
| --- | --- |
| **Entry** | Phone number → flow mapping, channel (voice/chat/email) |
| **Self-service nodes** | Lex/AI agent blocks — containment rate, fallback rate |
| **Decision branches** | DTMF/NLP inputs — which options customers actually choose |
| **Wait experience** | Queue hold time, hold music, callback offer rate |
| **Agent handoff** | Transfer rate, whisper flow content, screen pop data |
| **Termination** | Disconnect reasons (customer hang-up vs. agent end vs. flow end) |
| **Sentiment overlay** | Conversational Analytics sentiment score at each stage |

**Output format:**

1. **Mermaid/DOT diagram** of the IVR tree with:- Volume at each node (from CTRs/flow logs)

- Drop-off rates at each step
- Average time spent per node
- Color-coded: 🟢 healthy path, 🟡 slow, 🔴 high-abandon

1. **Metrics summary**:- Total contacts entering flow

- % self-served (resolved without agent)
- % transferred (1+ times)
- % abandoned (and at which point)
- Avg total customer experience time (IVR + wait + handle)

### 5.8 Flow-Level Risk Scoring

```python
SEVERITY_WEIGHTS = {'CRITICAL': 25, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 1}

def score_flow(findings):
    score = sum(SEVERITY_WEIGHTS.get(f['severity'], 0) for f in findings)
    if score == 0: return ('HEALTHY', '🟢')
    if score < 10: return ('LOW_RISK', '🟡')
    if score < 25: return ('MEDIUM_RISK', '🟠')
    if score < 50: return ('HIGH_RISK', '🔴')
    return ('CRITICAL', '⛔')

```

---

## 6. The Customer Mirror

### Health Score Card

```
┌─────────────────────────────────────────────────────────────┐
│       AMAZON CONNECT CUSTOMER HEALTH SCORE CARD             │
├─────────────────┬───────┬──────────┬──────┬────────┬───────┤
│ Pillar          │ Score │ Critical │ High │ Medium │ Low   │
├─────────────────┼───────┼──────────┼──────┼────────┼───────┤
│ Reliability     │  62%  │    2     │  3   │   4    │  1    │
│ Security        │  78%  │    1     │  2   │   3    │  2    │
│ Cost Optim.     │  55%  │    0     │  4   │   5    │  3    │
│ CX / Features   │  40%  │    1     │  5   │   7    │  4    │
│ Contact Flows   │  68%  │    1     │  3   │   4    │  2    │
├─────────────────┼───────┼──────────┼──────┼────────┼───────┤
│ OVERALL         │  59%  │    5     │  17  │  23    │  12   │
└─────────────────┴───────┴──────────┴──────┴────────┴───────┘

```

### Report Sections (Delivered to Customer)

```
1. EXECUTIVE SUMMARY
   → Overall health score, top 5 critical findings
   → Estimated cost savings opportunity ($)
   → Estimated CX improvement potential

2. CUSTOMER JOURNEY MAP
   → Visual flow graph of top 5 flows (Mermaid/DOT)
   → Metric overlay: volume, abandonment, sentiment per node
   → Friction points highlighted with recommendations

3. FEATURE UTILISATION HEATMAP
   → Which Connect features are enabled vs. available but unused
   → Estimated value of unused features
     (e.g., "AI agent assist could reduce AHT by ~20%")
   → Adoption maturity score vs. peer benchmark

4. RELIABILITY REPORT
   → DR posture, SPOF identification, failover readiness
   → ACGR eligibility and readiness checklist
   → Missing alarms and monitoring gaps

5. SECURITY REPORT
   → Compliance gaps (PCI, HIPAA, SOC2)
   → Encryption status per data type
   → Access control findings

6. COST OPTIMISATION OPPORTUNITIES
   → Unused phone numbers ($ per month)
   → Self-service containment gap ($ per deflected contact)
   → Storage lifecycle savings estimate
   → WebRTC migration opportunity
   → Agent efficiency improvements

7. PRIORITISED RECOMMENDATION ROADMAP
   → Quick wins (< 1 week):
     Enable features, fix flow errors, set up alarms, release unused numbers
   → Medium term (1-3 months):
     Self-service expansion, AI agent assist, Forecasting/Scheduling
   → Strategic (3-12 months):
     ACGR, full omnichannel, Customer Profiles, Voice ID, Cases

```

---

## 7. Implementation Reference

### Execution Order Per Instance

```
1.  ListInstances → DescribeInstance → DescribeInstanceAttribute (all attrs)
2.  ListTrafficDistributionGroups → GetTrafficDistribution         [RELIABILITY]
3.  ListPhoneNumbersV2 → cross-reference with flow associations    [COST]
4.  ListUsers → DescribeUser → CloudTrail login events             [COST + SECURITY]
5.  ListSecurityProfiles → DescribeSecurityProfile                 [SECURITY]
6.  DescribeInstanceStorageConfig (all types) → KMS check          [SECURITY]
7.  Feature detection batch (all ListIntegrationAssociations)      [FEATURES]
8.  CloudWatch GetMetricStatistics for last 30d                    [RELIABILITY + COST]
9.  ListContactFlows → DescribeContactFlow → parse Content JSON    [FLOWS]
10. CloudTrail LookupEvents for failover tests, admin ops          [RELIABILITY + SECURITY]

```

### IAM Permissions Required

Every action in the policy below is **read-only** (no write, create, or delete
permissions). It uses service-scoped action wildcards and `"Resource": "*"` for
convenience during initial setup; scope both down for production use as
described in the least-privilege note immediately following the policy.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "connect:List*",
        "connect:Describe*",
        "connect:Get*",
        "connect:Search*",
        "cloudwatch:GetMetricData",
        "cloudwatch:GetMetricStatistics",
        "cloudwatch:DescribeAlarms",
        "cloudtrail:LookupEvents",
        "cloudtrail:GetTrailStatus",
        "cloudtrail:DescribeTrails",
        "s3:GetBucketPolicy",
        "s3:GetBucketEncryption",
        "s3:GetBucketLogging",
        "s3:GetBucketLifecycleConfiguration",
        "s3:ListBucket",
        "kms:DescribeKey",
        "kms:GetKeyRotationStatus",
        "iam:ListPolicies",
        "iam:GetPolicyVersion",
        "iam:GetRole",
        "iam:ListAttachedRolePolicies",
        "lex:ListBots",
        "lex:ListBotAliases",
        "wisdom:ListAssistants",
        "voiceid:ListDomains",
        "connect-campaigns:ListCampaigns",
        "profile:ListDomains",
        "cases:ListDomains",
        "servicequotas:GetServiceQuota",
        "ce:GetCostAndUsage"
      ],
      "Resource": "*"
    }
  ]
}

```

> **Least-privilege note (production).** The policy above uses service-scoped
> action wildcards (`connect:List*`, `connect:Describe*`, `connect:Get*`,
> `connect:Search*`) and `"Resource": "*"` for convenience during initial setup.
> Both are read-only, but for production use you should tighten them:
>
> - **Replace the action wildcards** with the exact operations the tool calls
>   (see the *Key APIs Summary* below), so future Connect APIs matching those
>   prefixes are not granted implicitly. For example, replace `connect:List*`,
>   `connect:Describe*`, `connect:Get*`, and `connect:Search*` with the specific
>   operations your assessment run actually invokes — e.g. `connect:ListInstances`,
>   `connect:DescribeInstance`, `connect:GetMetricData`,
>   `connect:SearchContactFlows` — and do the same for the other services.
> - **Scope the resource** to the specific instance(s) you assess, e.g.
>   `"Resource": "arn:aws:connect:REGION:ACCOUNT:instance/INSTANCE-ID"` (and
>   `.../instance/INSTANCE-ID/*` for sub-resources), instead of `"*"`.

### Key APIs Summary

| Category | Primary APIs |
| --- | --- |
| Instance config | `DescribeInstance`, `ListInstances`, `DescribeInstanceAttribute`, `ListInstanceStorageConfigs` |
| Flows | `ListContactFlows`, `DescribeContactFlow`, `ListContactFlowModules` |
| Queues & Routing | `ListQueues`, `ListRoutingProfiles`, `DescribeQueue`, `ListRoutingProfileQueues` |
| Users & Security | `ListUsers`, `ListSecurityProfiles`, `DescribeUser`, `DescribeSecurityProfile` |
| Phone Numbers | `ListPhoneNumbersV2`, `DescribePhoneNumber` |
| Metrics | `GetMetricDataV2`, `GetCurrentMetricData` |
| DR | `ListTrafficDistributionGroups`, `DescribeTrafficDistributionGroup`, `GetTrafficDistribution` |
| Integrations | `ListIntegrationAssociations`, `ListBots` |
| Features | `ListEvaluationForms`, `ListViews`, `ListRules` |
| Cost | Cost Explorer `GetCostAndUsage`, CUR |
| CloudWatch | `GetMetricData` (namespace: `AWS/Connect`), `DescribeAlarms` |
| CloudTrail | `LookupEvents` (source: `connect.amazonaws.com`) |
| Flow Logs | CloudWatch Logs: `/aws/connect/{instanceId}` |

### Sources & References

- [Amazon Connect CloudWatch Metrics Reference](https://docs.aws.amazon.com/connect/latest/adminguide/monitoring-cloudwatch.html)
- [Amazon Connect Global Resiliency Workshop](https://catalog.us-east-1.prod.workshops.aws/workshops/d1f2d09f-5aae-4c90-82d1-c70def1fc8bd/en-US)
- [Amazon Connect API Reference — ListContactFlows](https://docs.aws.amazon.com/connect/latest/APIReference/API_ListContactFlows.html)
- [Amazon Connect API Reference — DescribeContactFlow](https://docs.aws.amazon.com/goto/WebAPI/connect/DescribeContactFlow)
- [Amazon Connect API Reference — ListPhoneNumbersV2](https://docs.aws.amazon.com/en_us/connect/latest/APIReference/API_ListPhoneNumbersV2.html)
- [FSI Services Spotlight: Amazon Connect Security](https://aws.amazon.com/blogs/industries/fsi-services-spotlight-feature-amazon-connect/)

---

### Proposed Build Roadmap

| Phase | Focus | Deliverable |
| --- | --- | --- |
| **Phase 1** | Core scanner | boto3 script → all checks → JSON findings |
| **Phase 2** | Flow parser | Contact flow JSON → graph + anti-pattern detection |
| **Phase 3** | Journey mapper | Graph + metrics → Mermaid visualization |
| **Phase 4** | Scoring engine | Weighted findings → pillar scores + RAG rating |
| **Phase 5** | Report generator | HTML/PDF with embedded diagrams + recommendations |
| **Phase 6** | Benchmarking | Anonymized metrics → peer comparison database |
| **Phase 7** | Remediation | IaC templates (CloudFormation/CDK) for common fixes |
