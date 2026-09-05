# Configuration Documentation

## Table of Contents

- [Canonical Configuration Guide](#canonical-configuration-guide)
- [Sample Configuration Files](#sample-configuration-files)

## Canonical Configuration Guide

The canonical configuration guide is now maintained at
[docs/configuration.md](../docs/configuration.md).

## Sample Configuration Files

The sample configuration files in this directory remain the starting point for
new assessments:

- `assessment_config.yaml`
- `assessment_config.json`
- `performance_config.yaml`

The live `checks` entries in the assessment configuration samples contain only
the currently supported `enabled` and `severity` overrides. Proposed
`parameters` and `remediation_template` values are retained under
`future_only.check_overrides` and are ignored by the current runtime.
