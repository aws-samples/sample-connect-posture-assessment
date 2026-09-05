# Amazon Connect Customer Assessment Tool — User Guide

[Back to the documentation index](README.md)

This guide covers installation, AWS access, assessment execution, report
operations, and CI/CD usage. For configuration keys, see
[configuration.md](configuration.md). For implemented checks, see
[check-catalog.md](check-catalog.md).

## Table of Contents

- [Installation](#installation)
  - [pipx](#pipx)
  - [AWS CloudShell](#aws-cloudshell)
  - [Contributor virtual environment](#contributor-virtual-environment)
- [AWS Access](#aws-access)
- [Running Assessments](#running-assessments)
- [Report Operations](#report-operations)
- [CI/CD](#cicd)
- [Further Help](#further-help)

## Installation

Choose the installation path that matches how you will use the tool.

### pipx

Recommended for repeated workstation use:

```bash
# Install pipx once
brew install pipx                          # macOS
python3 -m pip install --user pipx         # Linux / Windows
python3 -m pipx ensurepath                 # Linux / Windows

# Clone and install
git clone <repository-url>
cd amazon-connect-assessment
pipx install .
```

Upgrade later with:

```bash
cd amazon-connect-assessment
git pull
pipx reinstall amazon-connect-assessment
```

Remove it with:

```bash
pipx uninstall amazon-connect-assessment
```

### AWS CloudShell

CloudShell has Python and the AWS CLI available and uses the credentials of the
signed-in AWS Console session.

```bash
git clone <repository-url>
cd amazon-connect-assessment
pip3 install --user .
amazon-connect-assessment --region us-east-1 --output-dir ./reports
```

Download generated reports from the CloudShell **Actions → Download file**
menu. CloudShell sessions are ephemeral, so this path is best for one-off runs.

### Contributor virtual environment

Use a virtual environment when modifying the tool:

```bash
git clone <repository-url>
cd amazon-connect-assessment
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -e ".[dev,test]"
```

For installation failures, see [troubleshooting.md](troubleshooting.md).

## AWS Access

The assessment is read-only against the Amazon Connect Customer resources it inspects. The
optional `--s3-output` feature writes only to its report bucket.

Confirm the active identity and region access:

```bash
aws sts get-caller-identity
aws connect list-instances --region us-east-1
```

If access is denied, deploy the self-assessment policy:

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-assessment-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --parameter-overrides AttachToUserName=YOUR_USERNAME \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

To attach the policy to a role instead:

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-assessment-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --parameter-overrides AttachToRoleName=YOUR_ROLE_NAME \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1
```

To create the policy without attaching it:

```bash
aws cloudformation deploy \
  --stack-name amazon-connect-assessment-permissions \
  --template-file cloudformation/AmazonConnectSelfAssessmentPolicy.yaml \
  --capabilities CAPABILITY_NAMED_IAM \
  --region us-east-1

aws cloudformation describe-stacks \
  --stack-name amazon-connect-assessment-permissions \
  --query 'Stacks[0].Outputs[?OutputKey==`PolicyArn`].OutputValue' \
  --output text
```

The complete read permission source is
[iam-policy-template.json](iam-policy-template.json). The CloudFormation
template does not grant the additional S3 write permissions required by
`--s3-output`.

### Profiles, SSO, and environment variables

```bash
# Default profile
amazon-connect-assessment --region us-east-1 --output-dir ./reports

# Named profile
amazon-connect-assessment --profile my-profile --region us-east-1

# SSO profile
aws sso login --profile my-sso-profile
amazon-connect-assessment --profile my-sso-profile --region us-east-1
```

For CI/CD or temporary credentials:

```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_DEFAULT_REGION="us-east-1"
export AWS_SESSION_TOKEN="..."   # temporary credentials only

amazon-connect-assessment --output-dir ./reports
```

Validate access before a long run:

```bash
amazon-connect-assessment --check-permissions --region us-east-1
amazon-connect-assessment --dry-run --region us-east-1
```

## Running Assessments

Basic assessment:

```bash
amazon-connect-assessment --region us-east-1 --output-dir ./reports
```

Common options:

```bash
# Assess one instance
amazon-connect-assessment \
  --region us-east-1 \
  --instance-id <id> \
  --output-dir ./reports

# Select pillars and severities
amazon-connect-assessment \
  --region us-east-1 \
  --pillars security resilience \
  --severity critical high

# Skip flow analysis, including ContactFlowAnalyzer API calls
amazon-connect-assessment \
  --region us-east-1 \
  --skip-flow-analysis

# Generate all report formats
amazon-connect-assessment \
  --region us-east-1 \
  --output-format html json csv asff

# Tune journey-scoring bounds
amazon-connect-assessment \
  --region us-east-1 \
  --config config/assessment_config.yaml
```

Use `amazon-connect-assessment --help` for the complete CLI reference,
including check selection, worker controls, retries, logging, checkpoints,
configuration inspection, and report options.

## Report Operations

### Open a report

```bash
open reports/connect_assessment_*.html        # macOS
xdg-open reports/connect_assessment_*.html    # Linux
```

The HTML report is self-contained and can be viewed offline. The Caller
Journey Map renders contact flows targeted by inbound phone numbers. See
[report-formats.md](report-formats.md) for the output contracts.

### Publish reports to S3

```bash
amazon-connect-assessment \
  --region us-east-1 \
  --output-format html json \
  --s3-output
```

The default bucket is
`amazon-connect-assessment-report-<account_id>`. Override it with
`--s3-bucket`. The bucket is created with Block Public Access, SSE-S3
encryption, and versioning enabled.

Required additional permissions include:

- `s3:CreateBucket`
- `s3:PutObject`
- `s3:ListBucket`
- `s3:PutBucketPublicAccessBlock`
- `s3:PutEncryptionConfiguration`
- `s3:PutBucketVersioning`

Local reports remain available if an S3 upload fails.

### Compare assessment runs

Generate a JSON baseline, then compare a later run:

```bash
# Baseline
amazon-connect-assessment \
  --region us-east-1 \
  --output-format html json \
  --output-dir ./reports

# Later run
amazon-connect-assessment \
  --region us-east-1 \
  --output-format html \
  --diff reports/connect_assessment_<baseline>.json \
  --output-dir ./reports
```

The command reports resolved, new, and persistent findings.

## CI/CD

The CLI exits with code `0` on success and `1` on failure.

### GitHub Actions

```yaml
name: Amazon Connect Assessment Tool

on:
  schedule:
    - cron: "0 6 * * 1"
  workflow_dispatch:

permissions:
  id-token: write
  contents: read

jobs:
  assess:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Install
        run: pip install .
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AMAZON_CONNECT_ROLE_ARN }}
          aws-region: us-east-1
      - name: Run assessment
        run: |
          amazon-connect-assessment \
            --region us-east-1 \
            --output-format html json \
            --output-dir ./reports \
            --quiet
      - name: Upload report
        uses: actions/upload-artifact@v4
        with:
          name: amazon-connect-report-${{ github.run_id }}
          path: reports/
          retention-days: 90
```

## Further Help

- [Configuration](configuration.md)
- [Check catalog](check-catalog.md)
- [Report formats](report-formats.md)
- [Performance guide](performance-optimization.md)
- [Troubleshooting](troubleshooting.md)
