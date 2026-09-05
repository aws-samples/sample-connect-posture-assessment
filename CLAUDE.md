# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

Amazon Connect Assessment Tool — evaluates Amazon Connect deployments against the AWS Well-Architected Framework. Checks span 5 pillars (Resilience, Security, Cost Optimization, Performance Efficiency, Operational Excellence) plus Caller Journey Mapping (stitches contact flows into a super-graph and enumerates all caller paths). Runs as a CLI; reads AWS Connect via boto3, never mutates the customer resources it inspects (the only write is the opt-in `--s3-output`, which publishes the report to its own S3 bucket).

## Build and test

```bash
# Setup
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,test]"

# Run tests (pytest.ini enforces --cov-fail-under=65)
pytest -q

# Run without coverage gate (faster, for iterating on one file)
pytest tests/test_contact_flow_parser.py --override-ini="addopts=" -q

# Lint / format / type-check
ruff format . && ruff check . && mypy amazon_connect_assessment

# CLI (console entry point: amazon-connect-assessment = cli:main)
python -m amazon_connect_assessment.cli --help   # or the installed `amazon-connect-assessment`
```

Note: both `pytest.ini` and `pyproject.toml` define pytest config; `pytest.ini` wins. Its comment documents that the 65% coverage floor is a baseline (real coverage ~38%), not the 85% target.

## Architecture

The assessment runs as a pipeline orchestrated by `AssessmentEngine.run_assessment()` (`engine.py`):

1. **Discover** Connect instances via boto3.
2. **Analyze** — each `BaseAnalyzer` (`analyzers/`: instance, contact flow, queue, integration, security profile) enriches a `ConnectInstance` with fetched data.
3. **Execute checks** — every `BaseCheck` runs against a `CheckContext` and returns a `Finding`.
4. **Summarize** into an `AssessmentResult`.

`ParallelAssessmentEngine` (`parallel_engine.py`) subclasses the engine to fan out analysis + checks across a thread pool (default ~2× CPU cores) and configures boto3 clients with elevated connection pools. `ConnectionPoolManager` exists as a utility but is not currently wired into the engine path. CLI picks parallel vs sequential; force sequential for debugging or rate-limited accounts.

Key modules:
- `models.py` — all dataclasses/enums: `Pillar`, `Severity`, `CheckStatus`, `Finding`, `ConnectInstance`, `ContactFlowGraph`, `AssessmentResult`, `Remediation`.
- `aws_client_factory.py` — **all AWS API calls go through `AWSClientFactory.call_api_with_resilience()`** (retries, throttling, error normalization). Uses the caller's own credentials (profile / env / SSO) against their own account — there is no cross-account role assumption or External ID in the code.
- `checks/` — checks grouped by domain, several domains split across files: security (`security_checks.py`, `security_deep_checks.py`), cost (`cost_optimization_checks.py`, `cost_intelligence_checks.py`, `cost_containment_checks.py`), resilience (`resilience_advanced_checks.py`), performance (`performance_efficiency_checks.py`), operational (`operational_excellence_checks.py`), contact-flow behavior/security, AI agent security, and MVP (`mvp_checks.py`, plus `mvp_remediation_enricher.py`). Note `security_checks.py`/`cost_optimization_checks.py` expose check classes that `register_mvp_checks` registers — they have no `register_*()` of their own. `base.py` defines `BaseCheck`/`CheckContext`; `registry.py` holds the registry; `registration.py` is the single `register_all_checks(registry, pillars, skip_flow_analysis)` entry point that calls each module's `register_*()` (flow-content checks — contact-flow security/behavior, AI agent security, cost containment, performance — are only registered when `skip_flow_analysis` is false). `config.py` loads optional YAML/JSON to enable/disable checks and override severities/parameters at runtime.
- `parsers/` — contact flow JSON → directed graph (`flow_graph.py`), plus complexity scoring and pattern detection.
- `journey/` — caller journey pipeline: `topology` → `super_graph` → `path_enumerator` → `journey_scorer`. Entry: `from amazon_connect_assessment.journey import run_journey_mapping`; `AssessmentEngine._compute_journey_findings()` invokes it for journey findings.
- `report/` — exporters: `asff_export.py` (AWS Security Finding Format), `findings_diff.py` (compare runs), `posture_roadmap.py`, `s3_publisher.py` (opt-in `--s3-output` upload). `report_generator.py` produces HTML/JSON/CSV via Jinja2 templates in `templates/`; ASFF is produced by `asff_export.py`.
- `cost/` — `cost_estimator.py` for cost-optimization findings.

## Adding a check

1. Subclass `BaseCheck` in the appropriate `checks/<domain>_checks.py`, implement `execute(context: CheckContext) -> Finding`.
2. Add it to that module's `register_*()` function, which is already wired into `registration.py`.
3. Set `pillar` so `--pillar` filtering and `skip_flow_analysis` gating work correctly (flow-content checks are only registered when flow analysis is enabled).
4. Add a test under `tests/` (suite uses `moto` to mock AWS).

## Code conventions

- Python 3.12+. Ruff (lint + format, replaces black/isort/flake8), 100-char lines. mypy with `disallow_untyped_defs`.
- Comments only when the WHY is non-obvious.
- **Iterative algorithms only — no recursion** for graph traversal (Python stack limits). Traversal is bounded: `max_depth=50`, `max_paths_per_entry=200`, `MAX_TOTAL_PATHS=5000`.
- Security-conscious: subprocess calls use list form, never `shell=True`; Jinja2 autoescaping always on. The report bucket for the opt-in `--s3-output` is created hardened (Block Public Access, SSE-S3, versioning).

## Working style preferences

- Just do the work — implement, test, report. Don't present options for routine tasks.
- When reviewing code: find real bugs, fix them, AND verify with tests.
- After creating or modifying any Python file, run `ruff check .` and `ruff format --check .` (matching CI); fix everything they flag before considering the change done.
- Always run the test suite after changes; set up the environment if deps are missing. Prefer end-to-end verification (run the pipeline with dummy data), not just unit tests.
- Update related documentation in the same pass as code changes.
- Concise communication: results first, details after.
