# Documentation Index

This directory contains the current user guides, implementation references, and
design records for the Amazon Connect Customer Assessment Tool.

## Table of Contents

- [Start Here](#start-here)
- [Current Behavior](#current-behavior)
- [Contributors and Maintainers](#contributors-and-maintainers)
- [Design and Historical Reference](#design-and-historical-reference)
- [Source-of-Truth Rules](#source-of-truth-rules)

## Start Here

- [Project README](../README.md) — installation, AWS access, common CLI usage, and report overview.
- [User guide](user-guide.md) — detailed installation, AWS access, CLI usage, report operations, and CI/CD.
- [Deployment architecture](architecture.svg) — rendered deployment diagram;
  [editable Draw.io source](architecture.drawio).
- [Configuration guide](configuration.md) — YAML/JSON settings, precedence, output naming, and execution tuning.
- [Troubleshooting guide](troubleshooting.md) — installation, credentials, permissions, runtime, and report failures.

## Current Behavior

- [Check catalog](check-catalog.md) — implemented checks, journey findings, required permissions, and subset selection.
- [Report formats](report-formats.md) — HTML, JSON, CSV, and ASFF output contracts.
- [Performance guide](performance-optimization.md) — parallel execution, retry tuning, and journey-scoring bounds.
- [IAM policy template](iam-policy-template.json) — canonical read permissions for the assessment.

## Contributors and Maintainers

- [Development guide](development-guide.md) — setup, tests, code quality, architecture, and adding checks.
- [Threat model](threat-model.md) — current trust boundaries, attack surfaces, and mitigations.

## Design and Historical Reference

These documents describe design intent, decisions, or broader future capabilities. They
should not override the current behavior documented in the check catalog and
configuration guide.

- [Health-check framework](design/health-check-framework.md) — broader customer health-review model and proposed roadmap.
- [Same-account IAM CloudFormation spec](design/specs/same-account-iam-cloudformation-spec.md) — implementation record and design rationale.

## Source-of-Truth Rules

- Runtime behavior: source code and tests.
- Implemented checks and findings: [check catalog](check-catalog.md).
- Configuration keys and precedence: [configuration guide](configuration.md).
- Required read permissions: `iam_permissions.py`, [IAM policy template](iam-policy-template.json), and the consistency tests.
- Design proposals: documents under `design/`; they may describe capabilities not yet implemented.
