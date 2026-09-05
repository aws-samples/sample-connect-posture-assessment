# AGENTS.md

This file provides guidance to Codex (Codex.ai/code) when working with code in this repository.

## Project overview

Amazon Connect Assessment Tool — evaluates Amazon Connect deployments against the AWS Well-Architected Framework. Checks span 5 pillars (Resilience, Security, Cost Optimization, Performance Efficiency, Operational Excellence). Runs as a CLI. Assessment operations are read-oriented by default; the opt-in `--s3-output` path creates/hardens an S3 report bucket and uploads generated reports. The HTML report also includes a phone-number-driven Caller Journey Map section, and `AssessmentEngine._compute_journey_findings()` invokes the deeper `journey/` scoring pipeline.

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

Note: both `pytest.ini` and `pyproject.toml` define pytest config; `pytest.ini` wins. Its 65% coverage floor is the enforced baseline; raise it deliberately as coverage improves.

## Architecture

The assessment runs as a pipeline orchestrated by `AssessmentEngine.run_assessment()` (`engine.py`):

1. **Discover** Connect instances via boto3.
2. **Analyze** — each `BaseAnalyzer` (`analyzers/`: instance, contact flow, queue, integration, security profile) enriches a `ConnectInstance` with fetched data.
3. **Execute checks** — every `BaseCheck` runs against a `CheckContext` and returns a `Finding`.
4. **Summarize** into an `AssessmentResult`.

`ParallelAssessmentEngine` (`parallel_engine.py`) subclasses the engine to fan out analysis + checks across a thread pool (default ~2× CPU cores). It configures boto3 clients with elevated `max_pool_connections`; `ConnectionPoolManager` exists as a utility but is not currently wired into the engine path. CLI picks parallel vs sequential; force sequential for debugging or rate-limited accounts.

Key modules:
- `models.py` — all dataclasses/enums: `Pillar`, `Severity`, `CheckStatus`, `Finding`, `ConnectInstance`, `ContactFlowGraph`, `AssessmentResult`, `Remediation`.
- `aws_client_factory.py` — centralizes AWS sessions, clients, retries, throttling, and error normalization. It uses credentials already resolved by boto3 (profile, environment, CloudShell, instance role, OIDC-assumed role, etc.) and does not perform cross-account role assumption itself. AWS service operations in the analyzers should use `AWSClientFactory.call_api_with_resilience()` or a resilient wrapper.
- `checks/` — one file per domain (security, cost, resilience, performance, operational, contact-flow behavior/security, AI agent security, MVP). `base.py` defines `BaseCheck`/`CheckContext`; `registry.py` holds the registry; `registration.py` is the single `register_all_checks(registry, pillars, skip_flow_analysis)` entry point.
- `parsers/` — contact flow JSON → directed graph (`flow_graph.py`), plus complexity scoring and pattern detection.
- `journey/` — deeper caller journey scoring pipeline: `topology` → `super_graph` → `path_enumerator` → `journey_scorer`. Entry: `from amazon_connect_assessment.journey import run_journey_mapping`. `AssessmentEngine._compute_journey_findings()` invokes it for journey findings, while `AssessmentEngine._compute_journey_map()` builds the active HTML journey-map section.
- `report/` — exporters: `asff_export.py` (AWS Security Finding Format), `findings_diff.py` (compare runs), `posture_roadmap.py`. `report_generator.py` produces HTML/JSON/CSV via Jinja2 templates in `templates/`; ASFF is produced by `asff_export.py`.
- `cost/` — `cost_estimator.py` for cost-optimization findings.

## Adding a check

1. Subclass `BaseCheck` in the appropriate `checks/<domain>_checks.py`, implement `execute(context: CheckContext) -> Finding`.
2. Add it to that module's `register_*()` function, which is already wired into `registration.py`.
3. Set `pillar` so `--pillars` filtering works. If the check requires parsed contact flow content, wire it behind `skip_flow_analysis` in `registration.py` or make it safe when no flow content exists. Most flow-content checks are skipped by `--skip-flow-analysis`, but `HardcodedRoutingCheck` remains registered and handles empty flow data. Note: the report's Caller Journey Map has a separate skip check in `AssessmentEngine._compute_journey_map()`; keep CLI/config plumbing aligned if you change that behavior.
4. Add a test under `tests/` (suite uses `moto` to mock AWS).

## Code conventions

- Python 3.12+. Ruff (lint + format, replaces black/isort/flake8), 100-char lines. mypy is configured with `disallow_untyped_defs`, but `ignore_errors = true` is currently set as a baseline.
- Comments only when the WHY is non-obvious.
- **Iterative algorithms only — no recursion** for graph traversal (Python stack limits). Traversal is bounded: `max_depth=50`, `max_paths_per_entry=200`, `MAX_TOTAL_PATHS=5000`.
- Security-conscious: validate user-controlled identifiers against regex before use; subprocess calls use list form, never `shell=True`; Jinja2 autoescaping stays on for HTML reports; any future file-serving path should resolve paths and check `is_relative_to()` before serving.

## Working style preferences

- Just do the work — implement, test, report. Don't present options for routine tasks.
- When reviewing code: find real bugs, fix them, AND verify with tests.
- Always run the test suite after changes; set up the environment if deps are missing. Prefer end-to-end verification (run the pipeline with dummy data), not just unit tests.
- After creating or modifying any Python file, always run both `ruff check .` and `ruff format --check .` before reporting completion.
- Update related documentation in the same pass as code changes.
- Concise communication: results first, details after.
