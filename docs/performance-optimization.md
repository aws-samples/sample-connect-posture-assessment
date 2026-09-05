# Amazon Connect Customer Assessment Tool — Performance Guide

The tool runs with parallel execution enabled by default. This page covers what that means and how to tune it for your environment.

## Table of Contents

- [Default behaviour](#default-behaviour)
- [Tuning flags](#tuning-flags)
  - [Speed it up](#speed-it-up)
  - [Slow it down (rate-limited accounts)](#slow-it-down-rate-limited-accounts)
- [Which checks take the longest](#which-checks-take-the-longest)
- [Journey mapping tuning](#journey-mapping-tuning)
- [Configuration file approach](#configuration-file-approach)

---

## Default behaviour

When you run `amazon-connect-assessment`, the parallel engine is active automatically. It uses `min(32, CPU cores × 2)` worker threads — typically 8–16 on a modern laptop. You don't need to set any flags to get parallel execution.

Expected wall-clock times:

| Account size | Sequential | Parallel (default) |
|---|---|---|
| 1 instance, no flows | ~15 s | ~12 s |
| 1 instance, 50 flows | ~60 s | ~30 s |
| 3–5 instances | ~3–5 min | ~45–90 s |
| 10+ instances | ~10+ min | ~2–4 min |

---

## Tuning flags

### Speed it up

```bash
# More workers (default: auto)
--max-workers 16

# Larger batch size (default: 10)
--batch-size 20

# Skip the 23 contact-flow content checks and ContactFlowAnalyzer API calls
--skip-flow-analysis

# Scope to a single instance
--instance-id <id>

# Scope to one pillar
--pillars security
```

Example — fastest possible run for a first look:
```bash
amazon-connect-assessment \
  --region us-east-1 \
  --instance-id <id> \
  --pillars security resilience \
  --severity critical high \
  --skip-flow-analysis \
  --max-workers 16
```

### Slow it down (rate-limited accounts)

If you see `ThrottlingException` errors:

```bash
# Fewer workers
--max-workers 4 --batch-size 5

# Longer retry delays
--retry-base-delay 2.0 --retry-max-delay 120.0

# Force sequential (no parallelism at all)
--sequential
```

---

## Which checks take the longest

Contact flow content checks (`--skip-flow-analysis` skips these) make one API call per flow to fetch the flow JSON, then parse and graph it. For an instance with 200+ flows, this is the dominant cost.

**Caller Journey Mapping** adds additional time proportional to the number of phone numbers and the branching complexity of your flows. The pipeline:
- Calls `ListPhoneNumbersV2` (paginated, ~1 call per 50 numbers)
- Builds a super-graph from already-parsed flows (in-memory, fast)
- Runs bounded DFS from each phone number entry point (CPU-bound, capped at 200 paths per number and 5000 total)

For a typical instance with 10–50 phone numbers and moderate flow complexity, journey mapping adds 1–3 seconds. For large instances with 500+ numbers and deeply branching flows, it can add 5–10 seconds. The `--skip-flow-analysis` flag skips journey mapping entirely.

Instance-level checks (IAM, encryption, CloudWatch, CloudTrail, Global Resiliency) are fast — each makes 1–3 API calls regardless of instance size.

---

## Journey mapping tuning

The journey mapping pipeline has its own bounds independent of the parallel engine:

| Setting | Default | Effect |
|---|---|---|
| `journey_map.max_paths_per_did` | 200 | Max paths enumerated from a single phone number. Reduce to 50 for faster runs. |
| `journey_map.max_depth` | 50 | Max DFS depth per path. Reduce if your flows are known to be shallow. |
| Global `MAX_TOTAL_PATHS` | 5000 | Hard cap on total paths across all entry points. Prevents memory issues on large topologies. |

Configure via `assessment_config.yaml`:

```yaml
journey_map:
  max_paths_per_did: 100
  max_depth: 30
```

---

## Configuration file approach

For repeated runs with the same tuning, save settings to `config/assessment_config.yaml`:

```yaml
global_settings:
  parallel_execution: true
  max_workers: 12
  batch_size: 15
  timeout: 300
  max_retry_attempts: 5
  retry_base_delay: 1.0
  retry_max_delay: 60.0

journey_map:
  max_paths_per_did: 200
  max_depth: 50
```

Then run:
```bash
amazon-connect-assessment --config config/assessment_config.yaml
```
