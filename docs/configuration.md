# Amazon Connect Customer Assessment Tool Configuration

[Back to the documentation index](README.md)

This is the canonical configuration reference for the Amazon Connect Customer Assessment Tool.
The sample configuration files remain in `config/`; `config/README.md` points here.
Configuration controls assessment behavior, check selection, execution settings, and
report generation.

## Table of Contents

- [Configuration File Formats](#configuration-file-formats)
- [Main Configuration Structure](#main-configuration-structure)
  - [Global Settings](#global-settings)
  - [AWS Configuration](#aws-configuration)
  - [Output Configuration](#output-configuration)
  - [Pillar and Severity Filtering](#pillar-and-severity-filtering)
  - [Individual Check Configuration](#individual-check-configuration)
- [Performance Configuration](#performance-configuration)
  - [Parallel Execution and Network Resilience Settings](#parallel-execution-and-network-resilience-settings)
- [Using Configuration Files](#using-configuration-files)
  - [Command Line Usage](#command-line-usage)
  - [Configuration File Search Order](#configuration-file-search-order)
  - [Environment Variable Overrides](#environment-variable-overrides)
- [Configuration Examples](#configuration-examples)
  - [Minimal Configuration](#minimal-configuration)
  - [Development Configuration](#development-configuration)
  - [Production Configuration](#production-configuration)
- [Check Configuration Options](#check-configuration-options)
  - [Required Fields](#required-fields)
  - [Optional Fields](#optional-fields)
- [Configuration Validation](#configuration-validation)
- [Best Practices](#best-practices)
- [Troubleshooting](#troubleshooting)
  - [Common Issues](#common-issues)
  - [Debug Configuration Loading](#debug-configuration-loading)

## Configuration File Formats

The tool supports both JSON and YAML configuration formats:

- `assessment_config.json` - JSON format configuration
- `assessment_config.yaml` - YAML format configuration (recommended for readability)
- `performance_config.yaml` - Example of the performance-tuning keys. **Note:** this file is not loaded on its own — the tool only auto-discovers/loads `assessment_config.{yaml,json}` (or the file passed to `--config`). Put these keys under `global_settings` in your main config, or pass most of them as CLI flags (`--max-workers`, `--batch-size`, `--sequential`, retry flags).

## Main Configuration Structure

### Global Settings

Global settings affect the overall assessment execution:

```yaml
global_settings:
  timeout: 300                    # Timeout in seconds for AWS API calls
  retry_count: 3                  # Number of retries for failed API calls
  max_retry_attempts: 5           # Maximum retry attempts for network operations
  retry_base_delay: 1.0          # Base delay between retries in seconds
  retry_max_delay: 60.0          # Maximum delay between retries in seconds
  enable_rate_limiting: true      # Enable automatic rate limiting for AWS API calls
  parallel_execution: true        # Enable parallel check execution
  max_workers: null              # Maximum worker threads (null = auto-detect)
  batch_size: 10                 # Number of checks per batch
  log_level: "INFO"              # Logging level (DEBUG, INFO, WARNING, ERROR)
```

### AWS Configuration

Configure AWS credentials and region settings:

```yaml
aws:
  region: null                   # AWS region (null = use AWS_REGION env var)
  profile: null                  # AWS profile (null = use AWS_PROFILE env var)
```

### Output Configuration

Control report generation and output:

```yaml
output:
  format: ['html']               # Output formats: html, json, csv, asff
  directory: './reports'         # Output directory
  filename_template: 'connect_assessment_{timestamp}_{account_id}'
                                  # Tokens: {timestamp}, {account_id}, {region}, {assessment_id}
                                  # Filename only; directory separators are not allowed
```

The CLI `--output-dir`, `--output-format`, and `--output-filename` flags override
these values only when explicitly supplied. If `--output-format` is omitted, the
configured `output.format` value is preserved. When neither CLI nor configuration
specifies a format, HTML is generated.

### Pillar and Severity Filtering

Control which assessment pillars and severity levels are included:

```yaml
# Enable specific AWS Well-Architected Framework pillars
enabled_pillars:
  - "resilience"
  - "security"
  - "cost_optimization"

# Enable specific severity levels
enabled_severities:
  - "critical"
  - "high"
  - "medium"
  - "low"
```

### Individual Check Configuration

Configure whether specific checks are enabled and override their severity:

```yaml
checks:
  security-iam-001:
    enabled: true                    # Enable/disable this check
    severity: "critical"             # Override default severity
```

The configuration loader currently applies `enabled` and `severity`. The
`parameters`, `remediation_template`, and `description` keys are not applied by
the current check registry and should not be used as if they changed execution.
The sample files preserve examples of these unsupported fields under the
top-level `future_only.check_overrides` section; that section is intentionally
ignored at runtime.

## Performance Configuration

`performance_config.yaml` illustrates the settings for optimizing assessment execution. As noted above, it is **not** auto-loaded as a standalone file — place these keys under `global_settings` in your main `assessment_config.yaml`, or pass them as CLI flags. The keys below are the ones the tool actually reads:

### Parallel Execution and Network Resilience Settings

```yaml
global_settings:
  parallel_execution: true
  max_workers: null              # Auto-detect based on CPU count
  batch_size: 10
  max_retry_attempts: 5
  retry_base_delay: 1.0
  retry_max_delay: 60.0
  timeout: 300
  enable_rate_limiting: true
```

These settings are read from `global_settings`; the standalone
`parallel_execution` and `network_resilience` blocks are not loaded.

## Using Configuration Files

### Command Line Usage

```bash
# Run assessment with custom configuration
amazon-connect-assessment --config config/assessment_config.yaml

# Run with JSON configuration
amazon-connect-assessment --config config/assessment_config.json

# Override specific settings via CLI
amazon-connect-assessment --config config/assessment_config.yaml --region us-west-2 --max-workers 8
```

CLI flags override configuration values only when explicitly supplied. For example,
omitting `--output-format` preserves `output.format` from the configuration file.

### Configuration File Search Order

The tool searches for configuration files in this order:
1. File specified with `--config` option
2. `./assessment_config.yaml`
3. `./assessment_config.json`
4. `./config/assessment_config.yaml`
5. `./config/assessment_config.json`
6. `~/.amazon-connect-assessment/config.yaml`
7. `~/.amazon-connect-assessment/config.json`

### Environment Variable Overrides

Configuration can be overridden using environment variables:

```bash
export CONNECT_ASSESSMENT_LOG_LEVEL=DEBUG
export CONNECT_ASSESSMENT_TIMEOUT=600
export CONNECT_ASSESSMENT_MAX_WORKERS=16
export AWS_REGION=us-east-1
export AWS_PROFILE=my-profile
```

## Configuration Examples

### Minimal Configuration

```yaml
# Enable only critical security checks
enabled_pillars:
  - "security"
enabled_severities:
  - "critical"

checks:
  security-iam-001:
    enabled: true
  sec-storage-001:
    enabled: true
```

### Development Configuration

```yaml
# Development settings with verbose logging
global_settings:
  log_level: "DEBUG"
  timeout: 600
  parallel_execution: false  # Disable for easier debugging
  max_workers: 1

# Enable all checks for comprehensive testing
enabled_pillars:
  - "resilience"
  - "security"
  - "cost_optimization"
enabled_severities:
  - "critical"
  - "high"
  - "medium"
  - "low"
```

### Production Configuration

```yaml
# Production settings optimized for performance
global_settings:
  timeout: 300
  retry_count: 5
  max_retry_attempts: 3
  parallel_execution: true
  max_workers: 16
  batch_size: 20
  log_level: "INFO"

# Focus on critical and high severity issues
enabled_severities:
  - "critical"
  - "high"

# Configure output for multiple formats
output:
  format: ["html", "json", "csv", "asff"]
  directory: "/var/reports/connect-assessments"

# Caller journey scoring tuning (path discovery; does not change HTML map entries)
journey_map:
  max_paths_per_did: 200   # Max paths per phone number (reduce for speed)
  max_depth: 50            # Max DFS depth per path
  max_traffic_flows: 10    # Reserved for future traffic-based tier classification
```

The HTML Caller Journey Map is phone-number driven: it renders every available
contact flow targeted by an inbound number. It has no `top_n` setting. The
`journey_map` values above control the separate journey-scoring pipeline and its
findings.

## Check Configuration Options

### Required Fields

- `check_id`: Unique identifier for the check (must match the check implementation)

### Optional Fields

- `enabled`: Boolean to enable/disable the check (default: true)
- `severity`: Override the default severity level ("critical", "high", "medium", "low")
`parameters`, `remediation_template`, and `description` are not currently
consumed by the check registry.

The following fields are reserved for future support and are not live settings:
`parameters`, `remediation_template`, and `description`. Keep them under
`future_only.check_overrides` if documenting proposed per-check behavior.

## Configuration Validation

The configuration system includes validation to ensure settings are correct. Invalid configurations will be reported during startup.

## Best Practices

1. **Use YAML format** for better readability and comments
2. **Version control** your configuration files
3. **Test configurations** in development before using in production
4. **Use environment-specific** configurations (dev, staging, prod)
5. **Keep sensitive data** out of configuration files (use environment variables)
6. **Start with defaults** and only override what you need to change
7. **Use performance config** for large-scale assessments

## Troubleshooting

### Common Issues

1. **File not found**: Ensure the configuration file path is correct
2. **Invalid YAML/JSON**: Use a validator to check file syntax
3. **Unknown check IDs**: Verify check IDs match implemented checks
4. **Invalid severity levels**: Use only "critical", "high", "medium", "low"
5. **Invalid pillar names**: Use only "resilience", "security", "cost_optimization", "operational_excellence", "performance_efficiency"
6. **Performance issues**: Adjust `max_workers` and `batch_size` in performance config

### Debug Configuration Loading

Enable debug logging to see detailed configuration loading information:

```bash
amazon-connect-assessment --config config/assessment_config.yaml --verbose --verbose
```

This will show detailed logging about configuration loading and any issues encountered.
