"""
AWS Security Finding Format (ASFF) export for Security Hub integration.

Converts assessment findings into ASFF-compliant JSON that can be imported
into AWS Security Hub via BatchImportFindings.
"""

import json
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from ..models import AssessmentResult, CheckStatus, Finding, Pillar, Severity
from ..report_generator import validate_report_filename

# ASFF severity label mapping
_SEVERITY_MAP = {
    Severity.CRITICAL: {"Label": "CRITICAL", "Normalized": 90},
    Severity.HIGH: {"Label": "HIGH", "Normalized": 70},
    Severity.MEDIUM: {"Label": "MEDIUM", "Normalized": 40},
    Severity.LOW: {"Label": "LOW", "Normalized": 10},
}

# ASFF compliance status mapping. NOT_APPLICABLE findings are dropped
# entirely before mapping (see ``export_asff``), so no entry is needed here.
_STATUS_MAP = {
    CheckStatus.PASS: "PASSED",
    CheckStatus.FAIL: "FAILED",
    CheckStatus.ERROR: "NOT_AVAILABLE",
    CheckStatus.SKIPPED: "NOT_AVAILABLE",
}

# Pillar to ASFF type mapping
_TYPE_PREFIX = "Software and Configuration Checks/AWS Well-Architected"
_PILLAR_TYPE_MAP = {
    Pillar.SECURITY: f"{_TYPE_PREFIX}/Security",
    Pillar.RESILIENCE: f"{_TYPE_PREFIX}/Reliability",
    Pillar.COST_OPTIMIZATION: f"{_TYPE_PREFIX}/Cost Optimization",
    Pillar.OPERATIONAL_EXCELLENCE: f"{_TYPE_PREFIX}/Operational Excellence",
    Pillar.PERFORMANCE_EFFICIENCY: f"{_TYPE_PREFIX}/Performance Efficiency",
}

# ASFF field length limits (BatchImportFindings rejects the whole finding
# if any of these are exceeded). Finding descriptions and remediation text
# in this tool are markdown-authored and can run well past these limits —
# without truncation, BatchImportFindings would reject the finding outright
# rather than importing a truncated-but-usable version of it.
_MAX_TITLE_LENGTH = 256
_MAX_DESCRIPTION_LENGTH = 1024
_MAX_REMEDIATION_TEXT_LENGTH = 512


def _truncate(text: str, max_length: int) -> str:
    """Truncate ``text`` to fit an ASFF field length limit, with an ellipsis marker."""
    if not text:
        return text
    if len(text) <= max_length:
        return text
    marker = "... [truncated]"
    return text[: max_length - len(marker)] + marker


def finding_to_asff(
    finding: Finding,
    account_id: str,
    region: str,
    generator_id: str = "amazon-connect-assessment",
) -> Dict[str, Any]:
    """Convert a single Finding to an ASFF-compliant dict."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    finding_timestamp = finding.timestamp.strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    severity_info = _SEVERITY_MAP.get(finding.severity, {"Label": "INFORMATIONAL", "Normalized": 0})

    return {
        "SchemaVersion": "2018-10-08",
        "Id": f"{generator_id}/{finding.check_id}/{finding.resource_id}",
        "ProductArn": f"arn:aws:securityhub:{region}:{account_id}:product/{account_id}/default",
        "GeneratorId": generator_id,
        "AwsAccountId": account_id,
        "Types": [_PILLAR_TYPE_MAP.get(finding.pillar, _TYPE_PREFIX)],
        "CreatedAt": finding_timestamp,
        "UpdatedAt": now,
        "Severity": severity_info,
        "Title": _truncate(finding.check_name, _MAX_TITLE_LENGTH),
        "Description": _truncate(finding.description, _MAX_DESCRIPTION_LENGTH),
        "Remediation": {
            "Recommendation": {
                "Text": _truncate(finding.remediation, _MAX_REMEDIATION_TEXT_LENGTH),
            }
        },
        "Resources": [
            {
                # ASFF requires Resources[].Type to be one of a fixed enum
                # of resource types Security Hub recognizes (AwsEc2Instance,
                # AwsS3Bucket, AwsIamRole, etc — see the ASFF resource type
                # reference). "AwsConnect<resource_type>" is not a member of
                # that enum for ANY value of resource_type (there is no
                # "AwsConnectInstance"/"AwsConnectContactFlow" in the ASFF
                # spec), so BatchImportFindings would reject every finding
                # this export produces with a schema validation error. Use
                # the generic "Other" type, which is a real enum member,
                # and preserve the specific Connect resource type/id as
                # resource Details/Tags instead so the information isn't
                # lost — just moved somewhere ASFF actually allows it.
                "Type": "Other",
                "Id": finding.resource_id,
                "Region": region,
                "Tags": {"ConnectResourceType": finding.resource_type},
            }
        ],
        "Compliance": {
            "Status": _STATUS_MAP.get(finding.status, "NOT_AVAILABLE"),
        },
        "RecordState": "ACTIVE",
        "Workflow": {"Status": "NEW"},
    }


def export_asff(
    result: AssessmentResult,
    output_dir: str,
    filename_template: Optional[str] = None,
) -> str:
    """
    Export assessment results as ASFF JSON (one file, array of findings).

    Args:
        result: Assessment result to export.
        output_dir: Directory to save the report.
        filename_template: Optional filename template with assessment
            placeholders.

    Returns the path to the generated file.
    """
    findings_asff = []
    for finding in result.findings:
        if finding.status in (
            CheckStatus.PASS,
            CheckStatus.SKIPPED,
            CheckStatus.NOT_APPLICABLE,
        ):
            continue
        asff = finding_to_asff(
            finding,
            account_id=result.account_id,
            region=result.region,
        )
        findings_asff.append(asff)

    timestamp = result.timestamp.strftime("%Y%m%d_%H%M%S")
    template = filename_template or "connect_assessment_asff_{timestamp}_{account_id}"
    filename = template.format(
        timestamp=timestamp,
        account_id=result.account_id,
        region=result.region,
        assessment_id=result.assessment_id,
    )
    if not filename.endswith(".json"):
        filename = f"{filename}.json"
    filename = validate_report_filename(filename)
    filepath = os.path.join(output_dir, filename)

    with open(filepath, "w") as f:
        json.dump({"Findings": findings_asff}, f, indent=2)

    return filepath
