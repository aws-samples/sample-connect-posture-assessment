# Amazon Connect Customer Assessment Tool — Development Guide

## Table of Contents

- [Setup](#setup)
- [Running tests](#running-tests)
- [Code quality](#code-quality)
- [Developer scripts](#developer-scripts)
- [Adding a new check](#adding-a-new-check)
  - [Create the check class](#1-create-the-check-class)
  - [Register the check](#2-register-the-check)
  - [Write tests](#3-write-tests)
  - [Update the check catalog](#4-update-the-check-catalog)
- [Project architecture](#project-architecture)
  - [Data flow](#data-flow)
- [CI pipeline](#ci-pipeline)
- [Release process](#release-process)

---

## Setup

```bash
git clone <repository-url>
cd amazon-connect-assessment
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev,test]"
```

---

## Running tests

```bash
# Full suite with coverage
pytest

# Specific file
pytest tests/test_engine.py

# Specific test
pytest tests/test_engine.py::TestAssessmentEngine::test_run_assessment

# By marker
pytest -m unit
pytest -m property
pytest -m integration

# Without coverage (faster)
pytest --no-cov
```

Coverage gate is 65%. The htmlcov/ report is written after each run — open `htmlcov/index.html` to browse line-level coverage.

---

## Code quality

All of these run in CI on every push. Fix them locally before pushing:

```bash
# Format (replaces black + isort)
ruff format amazon_connect_assessment/ tests/

# Lint + import order (replaces flake8 + isort; --fix auto-fixes)
ruff check amazon_connect_assessment/ tests/

# Types
mypy amazon_connect_assessment/ --ignore-missing-imports
```

Or run all of the above at once via pre-commit (config in `.pre-commit-config.yaml`):

```bash
pre-commit install            # auto-run on git commit (where core.hooksPath allows)
pre-commit run --all-files    # or run on demand
```

If `core.hooksPath` is set globally, `pre-commit install`
is skipped — run `pre-commit run` manually before committing.

---

## Developer scripts

Standalone utilities in `scripts/` (run directly, not part of the installed package):

```bash
# Benchmark sequential vs. parallel engine and demo parallel features
python scripts/performance_test.py

# Pre-flight environment check (Python version, deps, imports, AWS credentials)
python scripts/validate_environment.py

# Regenerate the local HTML copy of README.md (requires: pip install markdown;
# docs/README.html is generated and is not a source document)
python scripts/generate_readme_html.py
```

---

## Adding a new check

All checks inherit from `BaseCheck`. The pluggable framework handles registration, error wrapping, and report rendering — you only implement `execute()`.

### 1. Create the check class

```python
# amazon_connect_assessment/checks/my_checks.py
from .base import BaseCheck, CheckContext
from ..models import Finding, Pillar, Severity, CheckStatus


class MyNewCheck(BaseCheck):
    def __init__(self):
        super().__init__(
            check_id="my-check-001",
            name="My New Check",
            pillar=Pillar.SECURITY,
            severity=Severity.HIGH,
            description="What this check validates.",
        )

    def execute(self, context: CheckContext) -> Finding:
        instance = context.instance
        client = context.aws_client_factory.get_connect_client()

        # ... your check logic ...

        if compliant:
            return self.create_finding(
                status=CheckStatus.PASS,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
            )
        else:
            return self.create_finding(
                status=CheckStatus.FAIL,
                resource_id=instance.instance_id,
                resource_type="ConnectInstance",
                description="Specific description of what failed.",
                evidence={"key": "value"},
                remediation="Prescriptive steps to fix this.",
            )
```

For insufficient-permission scenarios, use the built-in helper instead of returning ERROR:

```python
except ClientError as e:
    if e.response["Error"]["Code"] == "AccessDeniedException":
        return self.skipped_for_access_denied(
            context, required_permission="connect:DescribeInstanceAttribute"
        )
    raise
```

### 2. Register the check

Add it to `amazon_connect_assessment/checks/registration.py`:

```python
from .my_checks import register_my_checks   # add a register function

def register_all_checks(registry, pillars=None, skip_flow_analysis=False):
    # ... existing registrations ...
    register_my_checks(registry)
```

With the register function in your module:

```python
def register_my_checks(registry):
    registry.register_check(MyNewCheck())
```

### 3. Write tests

```python
# tests/test_my_checks.py
from unittest.mock import Mock
from amazon_connect_assessment.checks.my_checks import MyNewCheck
from amazon_connect_assessment.models import CheckStatus


def test_passes_when_compliant(make_check_context):
    ctx = make_check_context()
    ctx.aws_client_factory.get_connect_client.return_value.describe_instance_attribute\
        .return_value = {"Attribute": {"Value": "true"}}

    result = MyNewCheck().execute(ctx)

    assert result.status == CheckStatus.PASS


def test_fails_when_not_compliant(make_check_context):
    ctx = make_check_context()
    ctx.aws_client_factory.get_connect_client.return_value.describe_instance_attribute\
        .return_value = {"Attribute": {"Value": "false"}}

    result = MyNewCheck().execute(ctx)

    assert result.status == CheckStatus.FAIL
    assert "specific description" in result.description.lower()
```

Use `make_check_context` from `conftest.py` — it builds a `CheckContext` with sensible defaults and accepts overrides.

For AWS API mocking, use `moto`:

```python
from moto import mock_aws
import boto3

@mock_aws
def test_with_real_connect_api():
    # set up moto resources
    conn = boto3.client("connect", region_name="us-east-1")
    # ... create moto resources ...
    # run check
```

### 4. Update the check catalog

Add your check to `docs/check-catalog.md`.

---

## Project architecture

```
amazon_connect_assessment/
├── cli.py                    # Entry point — argument parsing, component wiring
├── engine.py                 # Orchestrates discovery → analysis → checks → results
├── parallel_engine.py        # Parallel execution (default, extends engine.py)
├── aws_client_factory.py     # boto3 session management, credential handling
├── models.py                 # Dataclasses: Finding, ConnectInstance, AssessmentResult, etc.
├── report_generator.py       # Jinja2 → HTML, JSON, CSV output; ASFF uses report/asff_export.py
├── network_resilience.py     # Retry logic, exponential backoff, rate limit detection
├── logging_config.py         # Structured logging setup
│
├── analyzers/                # Collect raw data from AWS APIs into ConnectInstance
│   ├── base.py               # BaseAnalyzer with safe_analyze()
│   ├── connect_instance_analyzer.py
│   ├── contact_flow_analyzer.py
│   ├── queue_analyzer.py
│   ├── security_profile_analyzer.py
│   └── integration_analyzer.py
│
├── checks/                   # Assessment logic — one file per domain
│   ├── base.py               # BaseCheck, CheckContext, create_finding(), skipped_for_access_denied()
│   ├── registry.py           # CheckRegistry — stores and retrieves checks
│   ├── registration.py       # register_all_checks() — central loader
│   ├── mvp_checks.py         # 5 original MVP checks + register_priority_checks()
│   ├── security_checks.py / security_deep_checks.py / contact_flow_security_checks.py
│   ├── ai_agent_security_checks.py
│   ├── resilience_advanced_checks.py  # resilience_checks.py was removed — see its module docstring history
│   ├── cost_optimization_checks.py / cost_intelligence_checks.py / cost_containment_checks.py
│   ├── operational_excellence_checks.py
│   ├── performance_efficiency_checks.py
│   └── mvp_remediation_enricher.py  # Enriches MVP findings with structured remediation
│
├── parsers/                  # Contact flow graph analysis
│   ├── contact_flow_parser.py   # Parses flow JSON into FlowAction / FlowTransition
│   ├── flow_graph.py            # DFS, cycle detection, reachability
│   ├── flow_complexity.py       # Complexity scoring
│   └── flow_patterns.py        # Pattern detection (auth, personalization, transfer)
│
├── journey/                  # Caller Journey Mapping — discovery experience
│   ├── __init__.py           # run_journey_mapping() — pipeline orchestrator
│   ├── models.py             # PhoneNumberEntry, SuperGraph, JourneyPath, JourneyScore
│   ├── topology.py           # Phone number → flow resolution, tier classification
│   ├── super_graph.py        # Stitches flows at transfer edges into instance-wide graph
│   ├── path_enumerator.py    # Bounded iterative DFS, global cap at 5000 paths
│   └── journey_scorer.py     # Security/CX/cost scoring per path + finding generation
│
├── report/
│   ├── asff_export.py        # AWS Security Finding Format for Security Hub
│   ├── findings_diff.py      # Cross-run comparison
│   ├── posture_roadmap.py    # Roadmap generation
│   └── s3_publisher.py       # Optional upload of reports to an S3 bucket (--s3-output)
│
└── templates/                # Jinja2 templates for HTML report
    ├── html/assessment_report.html
    ├── html/partials/
    ├── css/
    └── js/report-controller.js

cloudformation/
└── AmazonConnectSelfAssessmentPolicy.yaml # Deploy to grant your account the required IAM permissions

tests/                        # pytest suite (moto for AWS mocking)
config/                       # assessment_config.yaml template
docs/                         # This file and companions
```

### Data flow

```
CLI args + config file
        ↓
AWSClientFactory (credentials, boto3 sessions)
        ↓
AssessmentEngine.run_assessment()
    ├── discover_instances()        → [ConnectInstance, ...]
    ├── analyze_instance()          → ConnectInstance (populated with flows, queues, users...)
    ├── execute_checks()            → [Finding, ...]
    └── run_journey_mapping()       → JourneyMappingOutput (findings + topology + scored paths)
            ├── resolve_topology()      → phone numbers → flows → tier classification
            ├── build_super_graph()     → instance-wide directed graph (stitched at transfers)
            ├── enumerate_journeys()    → bounded DFS from each entry point
            ├── score_journeys()        → security / CX / cost scoring per path
            └── generate_findings()     → [Finding, ...]
                                         ↓
                                   ReportGenerator
                                         ↓
                               HTML / JSON / CSV / ASFF
```

---

## CI pipeline

GitHub Actions runs on every push and PR to `main`:

- **Test** — pytest on Python 3.12
- **Lint** — `ruff check` (lint + import order) and `ruff format --check`
- **Type check** — mypy
- **Security audit** — pip-audit on dependencies

See `.github/workflows/ci.yml` for the full definition.

---

## Release process

1. Update `__version__` in `amazon_connect_assessment/__init__.py` and `pyproject.toml`
2. Run the full test suite: `pytest`
3. Commit: `git commit -m "Release v0.x.0"`
4. Tag: `git tag v0.x.0 && git push origin v0.x.0`
