# Amazon Connect Customer Assessment Tool — Troubleshooting Guide

## Table of Contents

- [Quick diagnostic](#quick-diagnostic)
- [Installation issues](#installation-issues)
- [AWS credential issues](#aws-credential-issues)
- [Assessment issues](#assessment-issues)
- [Report issues](#report-issues)
- [Getting more information](#getting-more-information)

---

## Quick diagnostic

Before anything else:

```bash
# Validate Python, dependencies, AWS credentials, and permissions
python scripts/validate_environment.py

# Check credentials and list missing permissions
amazon-connect-assessment --check-permissions --region us-east-1

# Validate without running checks
amazon-connect-assessment --dry-run --region us-east-1
```

---

## Installation issues

### `ModuleNotFoundError: No module named 'amazon_connect_assessment'`

The package isn't installed in the active Python environment.

```bash
# Activate the virtual environment first
source venv/bin/activate        # Windows: venv\Scripts\activate

# Then install
pip install -e .

# Confirm
amazon-connect-assessment --version
```

### `ModuleNotFoundError: No module named 'jinja2'` (or any other dep)

Dependencies aren't installed.

```bash
pip install -r requirements.txt
```

---

## AWS credential issues

### `NoCredentialsError` or `Unable to locate credentials`

No credentials are configured.

```bash
# Check what credentials are active
aws sts get-caller-identity

# Configure if missing
aws configure
# or
aws configure --profile my-profile
```

### `ProfileNotFound: The config profile (name) could not be found`

The profile name doesn't exist in `~/.aws/config`.

```bash
# List available profiles
aws configure list-profiles

# Use one that exists, or configure a new one
aws configure --profile new-profile-name
```

### `TokenExpiredError` or `ExpiredTokenException`

Temporary credentials (SSO, assumed role, CloudShell session) have expired.

```bash
# Refresh SSO login
aws sso login --profile my-sso-profile

# Or re-export new temporary credentials
```

---

## Assessment issues

### "No Amazon Connect Customer instances found" / `InstanceSummaryList: []`

Credentials work but no instances are returned.

1. **Wrong region** — Amazon Connect Customer instances are region-specific. Confirm with:
   ```bash
   aws connect list-instances --region us-east-1
   ```
2. **Missing permission** — `connect:ListInstances` must be in the IAM policy.
3. **Wrong account** — the assumed role may be in a different account than where Connect is deployed.

### Checks return `Skipped` instead of Pass/Fail

The IAM role is missing the permission for that specific API. The finding description names it exactly. Grant the permission and re-run.

For the full read-only assessment permission set, see
`docs/iam-policy-template.json` or deploy
`cloudformation/AmazonConnectSelfAssessmentPolicy.yaml`. The opt-in
`--s3-output` path additionally requires the S3 write permissions listed in
the user guide; those are intentionally not included in the read-only policy.
The read-only artifacts are kept in sync with the canonical permission
catalog in `amazon_connect_assessment/iam_permissions.py` (the JSON file is
generated from it — see that module's docstring to add a permission).

### Assessment produces findings but the HTML report is empty

The report generator couldn't find its Jinja2 templates. Ensure the package is installed correctly:

```bash
pip install -e .
# Confirm templates exist
ls amazon_connect_assessment/templates/html/
```

### Assessment is very slow

Several options:

```bash
# Target one instance instead of all
amazon-connect-assessment --region us-east-1 --instance-id <id>

# Skip contact flow content checks and ContactFlowAnalyzer API calls
# (~40% faster on flow-heavy accounts)
amazon-connect-assessment --region us-east-1 --skip-flow-analysis

# Increase parallelism (default is 2x CPU cores)
amazon-connect-assessment --region us-east-1 --max-workers 16 --batch-size 20

# Focus on one pillar
amazon-connect-assessment --region us-east-1 --pillars security
```

### `ThrottlingException` / rate limiting errors

The tool is hitting AWS API rate limits. Reduce parallelism:

```bash
amazon-connect-assessment \
  --region us-east-1 \
  --max-workers 4 \
  --batch-size 5 \
  --retry-base-delay 2.0 \
  --retry-max-delay 120.0
```

---

## Report issues

### HTML report doesn't open / shows blank

The report is a self-contained HTML file — open it directly in a browser:

```bash
open reports/connect_assessment_*.html        # macOS
xdg-open reports/connect_assessment_*.html   # Linux
start reports\connect_assessment_*.html       # Windows
```

Don't double-click from a file manager on some systems — drag it into the browser instead.

### Charts don't render in the report

The report loads Chart.js from a CDN. If you're offline, charts fall back to an "unavailable" placeholder — all findings text is still present and functional.

### `--s3-output`: upload didn't complete

The assessment still succeeds and local reports are written even if the S3 upload fails. Common causes:

- **Missing permissions** — the identity needs `s3:CreateBucket`, `s3:PutObject`, `s3:ListBucket`, and the bucket-hardening puts (`s3:PutBucketPublicAccessBlock`, `s3:PutEncryptionConfiguration`, `s3:PutBucketVersioning`) on `arn:aws:s3:::amazon-connect-assessment-report-*`. These are separate from the read-only assessment policy and must be granted explicitly when `--s3-output` is enabled.
- **Bucket name taken** — S3 bucket names are globally unique. If `amazon-connect-assessment-report-<account_id>` is already owned elsewhere, pass `--s3-bucket <your-unique-name>`.
- **Wrong region** — the bucket is created in the run region (`--region`). A pre-existing bucket in another region will report a region mismatch; use `--s3-bucket` to point at the right one.

---

## Getting more information

```bash
# Verbose output — shows each step
amazon-connect-assessment --region us-east-1 -v

# Debug output — shows every API call
amazon-connect-assessment --region us-east-1 -vv

# Save all output to a file
amazon-connect-assessment --region us-east-1 -vv --log-file debug.log 2>&1

# JSON log format (useful for piping to jq or a log aggregator)
amazon-connect-assessment --region us-east-1 --log-format json
```
