"""
HTML report generator for Amazon Connect Assessment Tool.

This module provides comprehensive HTML report generation with interactive features,
modern UI design, and offline viewing capabilities. Reports include executive summaries,
detailed findings, remediation guidance, and interactive filtering controls.
"""

import json
import logging
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from jinja2 import Environment, TemplateNotFound, select_autoescape

from .models import (
    AssessmentResult,
    CheckStatus,
    ConnectInstance,
    Finding,
    Pillar,
    Severity,
)


def validate_report_filename(filename: str) -> str:
    """Reject path components so report names remain files, not paths."""
    if (
        not filename
        or filename in {".", ".."}
        or "\x00" in filename
        or "/" in filename
        or "\\" in filename
    ):
        raise ValueError("Report filename must be a filename, not a path")
    return filename


class ReportGenerator:
    """
    Generates rich HTML reports with interactive features for Amazon Connect assessments.

    Features:
    - Modern, responsive UI design
    - Interactive filtering by severity and status
    - Pillar-based organization
    - Executive summary with charts and statistics
    - Detailed findings with remediation guidance
    - Embedded CSS/JavaScript for offline viewing
    - Color-coded status indicators and visual elements
    """

    def __init__(self, template_dir: Optional[str] = None):
        """
        Initialize the report generator.

        Args:
            template_dir: Optional custom template directory path
        """
        self.logger = logging.getLogger("report_generator")
        self.template_env = self._setup_template_environment(template_dir)

    def _setup_template_environment(self, template_dir: Optional[str]) -> Environment:
        """Set up Jinja2 template environment with FileSystemLoader."""
        from jinja2 import FileSystemLoader, PackageLoader

        if template_dir and os.path.exists(template_dir):
            # Use custom template directory if provided
            loader = FileSystemLoader(template_dir)
            self.logger.info(f"Using custom template directory: {template_dir}")
        else:
            # Use package templates
            try:
                loader = PackageLoader("amazon_connect_assessment", "templates/html")
                self.logger.info("Using package templates")
            except Exception as e:
                self.logger.error(f"Failed to load package templates: {e}")
                # Fallback to relative path for development
                template_path = Path(__file__).parent / "templates" / "html"
                if template_path.exists():
                    loader = FileSystemLoader(str(template_path))
                    self.logger.info(f"Using development templates: {template_path}")
                else:
                    raise TemplateNotFound(f"Could not find templates at {template_path}")

        env = Environment(
            loader=loader,
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )

        # Add custom filters
        env.filters["format_datetime"] = self._format_datetime
        env.filters["format_duration"] = self._format_duration
        env.filters["severity_color"] = self._get_severity_color
        env.filters["status_color"] = self._get_status_color
        env.filters["pillar_icon"] = self._get_pillar_icon
        env.filters["json_encode"] = self._safe_json_encode
        # Remediation reference URLs are hardcoded https doc links today, but
        # they land in an ``href`` attribute — the ``| safe_url`` filter
        # scheme-allowlists them so a non-http(s) URI (``javascript:``,
        # ``data:``) can never reach the DOM even if a future URL is dynamic.
        env.filters["safe_url"] = self._safe_url
        # Reviewer feedback: the report's "Resource ID" line only showed
        # the raw instance UUID, with no way to tell which instance that
        # is without cross-referencing the executive summary. Every
        # Finding.resource_id is exactly instance.instance_id (verified —
        # no check ever composes a different value), so this filter takes
        # a UUID plus the alias-lookup dict built once per render in
        # _prepare_template_context (see "instance_alias_by_id" in the
        # context) and renders "'alias' (uuid)" the same way
        # ConnectInstance.display_name does, falling back to the bare
        # UUID if it isn't found.
        env.filters["instance_label"] = self._render_instance_label
        # Finding descriptions + remediations are authored in markdown so
        # they can use paragraph breaks, bullet lists, fenced code blocks,
        # and inline code samples. Templates run the string through
        # ``| markdown | safe`` — the filter renders to HTML and disables
        # raw-HTML passthrough so untrusted flow content can't smuggle
        # ``<script>`` into the page (Autoescape is on globally, but the
        # rendered markdown HTML has to bypass it — hence ``| safe`` —
        # which is why the filter itself must be XSS-safe).
        env.filters["markdown"] = self._render_markdown
        # Evidence dicts get their own filter — see _render_evidence for
        # the pattern-matching logic that turns list-of-dicts keys into
        # tables and scalar keys into a definition list.
        env.filters["evidence"] = self._render_evidence

        return env

    def generate_html_report(
        self,
        assessment_result: AssessmentResult,
        output_path: Optional[str] = None,
        include_raw_data: bool = False,
    ) -> str:
        """
        Generate a complete HTML report from assessment results.

        Args:
            assessment_result: Complete assessment results
            output_path: Optional path to save the report
            include_raw_data: Whether to embed raw JSON data in report (default: False)

        Returns:
            HTML content as string (always returns content, saves to file if output_path provided)
        """
        self.logger.info(f"Generating HTML report for assessment {assessment_result.assessment_id}")

        try:
            # Prepare template context
            context = self._prepare_template_context(assessment_result, include_raw_data)

            # Render the main template
            template = self.template_env.get_template("assessment_report.html")
            html_content = template.render(**context)

            # Save to file if path provided
            if output_path:
                self._save_report(html_content, output_path)
                self.logger.info(f"Report saved to: {output_path}")

            return html_content

        except Exception as e:
            self.logger.error(f"Failed to generate HTML report: {str(e)}")
            raise

    def generate_json_report(
        self,
        assessment_result: AssessmentResult,
        output_dir: str,
        filename_template: Optional[str] = None,
    ) -> str:
        """
        Generate a JSON report from assessment results.

        Args:
            assessment_result: Complete assessment results
            output_dir: Directory to save the report
            filename_template: Optional filename template

        Returns:
            Path to the generated JSON report
        """
        self.logger.info(f"Generating JSON report for assessment {assessment_result.assessment_id}")

        try:
            # Generate filename
            if not filename_template:
                filename_template = "connect_assessment_{timestamp}_{account_id}.json"

            filename = self._generate_filename(filename_template, assessment_result, "json")
            output_path = os.path.join(output_dir, filename)

            # Ensure directory exists
            os.makedirs(output_dir, exist_ok=True)

            # Convert assessment result to dictionary
            registered_checks = assessment_result.summary.registered_checks
            if registered_checks is None:
                registered_checks = (
                    assessment_result.summary.total_checks
                    - assessment_result.summary.journey_findings
                )
            report_data = {
                "assessment_id": assessment_result.assessment_id,
                "timestamp": assessment_result.timestamp.isoformat(),
                "account_id": assessment_result.account_id,
                "region": assessment_result.region,
                "journey_map_entries": json.loads(
                    self._journey_map_entries_json(assessment_result)
                ),
                "journey_map_status": getattr(assessment_result, "journey_map_status", None),
                "summary": {
                    "total_checks": assessment_result.summary.total_checks,
                    "passed_checks": assessment_result.summary.passed_checks,
                    "failed_checks": assessment_result.summary.failed_checks,
                    "error_checks": assessment_result.summary.error_checks,
                    "skipped_checks": assessment_result.summary.skipped_checks,
                    "not_applicable_checks": assessment_result.summary.not_applicable_checks,
                    "critical_findings": assessment_result.summary.critical_findings,
                    "high_findings": assessment_result.summary.high_findings,
                    "medium_findings": assessment_result.summary.medium_findings,
                    "low_findings": assessment_result.summary.low_findings,
                    "registered_checks": registered_checks,
                    "journey_findings": assessment_result.summary.journey_findings,
                },
                "instances": [
                    {
                        "instance_id": instance.instance_id,
                        "instance_arn": instance.instance_arn,
                        "identity_management_type": instance.identity_management_type,
                        "inbound_calls_enabled": instance.inbound_calls_enabled,
                        "outbound_calls_enabled": instance.outbound_calls_enabled,
                        "instance_alias": getattr(instance, "instance_alias", None),
                        "service_role": getattr(instance, "service_role", None),
                        "status": getattr(instance, "status", None),
                    }
                    for instance in assessment_result.instances
                ],
                "findings": [
                    {
                        "check_id": finding.check_id,
                        "check_name": finding.check_name,
                        "pillar": finding.pillar.value,
                        "severity": finding.severity.value,
                        "status": finding.status.value,
                        "resource_id": finding.resource_id,
                        "resource_type": finding.resource_type,
                        "description": finding.description,
                        "remediation": finding.remediation,
                        "structured_remediation": self._serialize_remediation(
                            finding.structured_remediation
                        ),
                        "evidence": finding.evidence,
                        "timestamp": finding.timestamp.isoformat(),
                    }
                    for finding in assessment_result.findings
                ],
                "metadata": {
                    "tool_version": assessment_result.metadata.tool_version,
                    "execution_time_seconds": assessment_result.metadata.execution_time_seconds,
                    "aws_account_id": assessment_result.metadata.aws_account_id,
                    "aws_region": assessment_result.metadata.aws_region,
                    "execution_environment": assessment_result.metadata.execution_environment,
                    "python_version": assessment_result.metadata.python_version,
                },
                "execution_errors": assessment_result.execution_errors,
            }

            # Save JSON report
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report_data, f, indent=2, ensure_ascii=False)

            self.logger.info(f"JSON report saved to: {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"Failed to generate JSON report: {str(e)}")
            raise

    def _serialize_remediation(self, remediation) -> Optional[Dict[str, Any]]:
        """
        Serialize a structured Remediation into a JSON-friendly dict.

        Returns None when no structured remediation is present, preserving the
        existing report shape for findings that only carry the flat string.
        """
        if remediation is None:
            return None
        return {
            "summary": remediation.summary,
            "steps": [
                {
                    "order": step.order,
                    "instruction": step.instruction,
                    "command": step.command,
                    "console_path": step.console_path,
                }
                for step in sorted(remediation.steps, key=lambda s: s.order)
            ],
            "target_resources": list(remediation.target_resources),
            "references": [{"title": ref.title, "url": ref.url} for ref in remediation.references],
            "applies_if": remediation.applies_if,
            "placeholders": list(remediation.placeholders),
        }

    def generate_csv_report(
        self,
        assessment_result: AssessmentResult,
        output_dir: str,
        filename_template: Optional[str] = None,
    ) -> str:
        """
        Generate a CSV report from assessment results.

        Args:
            assessment_result: Complete assessment results
            output_dir: Directory to save the report
            filename_template: Optional filename template

        Returns:
            Path to the generated CSV report
        """
        self.logger.info(f"Generating CSV report for assessment {assessment_result.assessment_id}")

        try:
            import csv

            # Generate filename
            if not filename_template:
                filename_template = "connect_assessment_{timestamp}_{account_id}.csv"

            filename = self._generate_filename(filename_template, assessment_result, "csv")
            output_path = os.path.join(output_dir, filename)

            # Ensure directory exists
            os.makedirs(output_dir, exist_ok=True)

            # Define CSV headers
            headers = [
                "Assessment ID",
                "Timestamp",
                "Account ID",
                "Region",
                "Instance ID",
                "Instance Alias",
                "Check ID",
                "Check Name",
                "Pillar",
                "Severity",
                "Status",
                "Resource Type",
                "Resource ID",
                "Description",
                "Remediation",
                "Remediation Targets",
                "Evidence",
            ]

            # UUID -> instance_alias, so each row shows a human-readable
            # name alongside the raw UUID rather than the UUID alone
            # (reviewer feedback on the HTML report applies equally here).
            alias_by_id = {
                inst.instance_id: inst.instance_alias
                for inst in assessment_result.instances
                if inst.instance_alias
            }

            # Write CSV report
            with open(output_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(headers)

                for finding in assessment_result.findings:
                    # Find the instance for this finding
                    instance_id = "unknown"
                    for instance in assessment_result.instances:
                        if finding.resource_id.startswith(instance.instance_id):
                            instance_id = instance.instance_id
                            break

                    writer.writerow(
                        [
                            assessment_result.assessment_id,
                            finding.timestamp.isoformat(),
                            assessment_result.account_id,
                            assessment_result.region,
                            instance_id,
                            alias_by_id.get(instance_id, ""),
                            finding.check_id,
                            finding.check_name,
                            finding.pillar.value,
                            finding.severity.value,
                            finding.status.value,
                            finding.resource_type,
                            finding.resource_id,
                            finding.description,
                            finding.remediation,
                            (
                                ", ".join(finding.structured_remediation.target_resources)
                                if finding.structured_remediation
                                else ""
                            ),
                            json.dumps(finding.evidence) if finding.evidence else "",
                        ]
                    )

            self.logger.info(f"CSV report saved to: {output_path}")
            return output_path

        except Exception as e:
            self.logger.error(f"Failed to generate CSV report: {str(e)}")
            raise

    def _generate_filename(
        self,
        template: str,
        assessment_result: AssessmentResult,
        extension: str,
    ) -> str:
        """
        Generate filename from template with variable substitution.

        Args:
            template: Filename template with placeholders
            assessment_result: Assessment result for variable substitution
            extension: File extension

        Returns:
            Generated filename
        """
        # Extract variables for substitution
        timestamp = assessment_result.timestamp.strftime("%Y%m%d_%H%M%S")
        account_id = assessment_result.account_id
        region = assessment_result.region
        assessment_id = assessment_result.assessment_id

        # Substitute variables in template
        filename = template.format(
            timestamp=timestamp,
            account_id=account_id,
            region=region,
            assessment_id=assessment_id,
        )

        # Ensure proper extension
        if not filename.endswith(f".{extension}"):
            filename = f"{filename}.{extension}"

        return validate_report_filename(filename)

    def _prepare_template_context(
        self, assessment_result: AssessmentResult, include_raw_data: bool
    ) -> Dict[str, Any]:
        # Prepare comprehensive template context with all report data

        # Generate summary statistics
        summary_stats = self._generate_summary_statistics(assessment_result)

        # Organize findings by pillar
        findings_by_pillar = self._organize_findings_by_pillar(assessment_result.findings)

        # Generate charts data
        charts_data = self._generate_charts_data(assessment_result)

        # Create executive summary
        executive_summary = self._create_executive_summary(assessment_result)

        context = {
            # Core assessment data
            "assessment": assessment_result,
            "findings": assessment_result.findings,
            "instances": assessment_result.instances,
            # Organized data
            "findings_by_pillar": findings_by_pillar,
            "summary_stats": summary_stats,
            "executive_summary": executive_summary,
            # Caller Journey Map — one entry per inbound phone number
            # (DID / toll-free) that terminates on a contact flow.
            # Populated by AssessmentEngine._compute_journey_map. The
            # template renders two dropdowns (instance -> phone number)
            # driving a single Mermaid diagram + JS-free fallback.
            #
            # When entries is empty, ``journey_map_status`` carries a
            # plain-English explanation of why (skipped by config, no
            # numbers claimed, numbers point at queues not flows,
            # missing ListPhoneNumbersV2 permission, etc.) so the
            # template can render a diagnostic instead of hiding the
            # section.
            #
            # ``journey_map_entries_json`` is the same data serialised
            # as a JSON string so the initializer JavaScript in
            # assessment_report.html can read it from a
            # ``<script type="application/json">`` island.
            "journey_map_entries": self._journey_map_entries(assessment_result),
            "journey_map_entries_json": self._journey_map_entries_json(assessment_result),
            "journey_map_instances": self._journey_map_instance_list(assessment_result),
            "journey_map_status": getattr(assessment_result, "journey_map_status", None),
            # Interactive elements
            "charts_data": charts_data,
            "charts_data_json": json.dumps(charts_data).replace("</", "<\\/"),
            "filter_options": self._get_filter_options(
                assessment_result.findings, assessment_result.instances
            ),
            # UUID -> instance_alias (bare alias, not the full display_name
            # with the UUID already appended) for the "instance_label"
            # filter used in findings.html's "Resource ID" line. Built
            # once per render rather than per finding.
            "instance_alias_by_id": {
                inst.instance_id: inst.instance_alias
                for inst in assessment_result.instances
                if inst.instance_alias
            },
            # Metadata
            "generation_timestamp": datetime.now(),
            "report_title": f"Amazon Connect Assessment Tool Report - {assessment_result.account_id}",
            # Raw data (optional)
            "raw_data": (
                json.dumps(assessment_result, default=str, indent=2) if include_raw_data else None
            ),
            # Styling and assets
            "embedded_css": self._load_external_css(),
            "embedded_js": self._load_external_js(),
        }

        return context

    def _generate_summary_statistics(self, assessment_result: AssessmentResult) -> Dict[str, Any]:
        # Generate comprehensive summary statistics for the report
        findings = assessment_result.findings
        summary = assessment_result.summary
        registered_checks = summary.registered_checks
        if registered_checks is None:
            registered_checks = summary.total_checks - summary.journey_findings

        # Pass rate reflects the checks that actually assessed something.
        # Exclude SKIPPED (couldn't evaluate — usually AccessDenied) and
        # NOT_APPLICABLE (evaluated and determined the check doesn't apply)
        # from the denominator, so those don't distort the score.
        evaluated_checks = (
            summary.total_checks - summary.skipped_checks - summary.not_applicable_checks
        )
        pass_rate = (summary.passed_checks / evaluated_checks * 100) if evaluated_checks > 0 else 0

        # Risk score calculation (weighted by severity)
        risk_score = self._calculate_risk_score(findings)

        # Findings by status
        status_breakdown = {
            "passed": summary.passed_checks,
            "failed": summary.failed_checks,
            "error": summary.error_checks,
            "skipped": summary.skipped_checks,
            "not_applicable": summary.not_applicable_checks,
        }

        # Findings by severity (failed only)
        severity_breakdown = {
            "critical": summary.critical_findings,
            "high": summary.high_findings,
            "medium": summary.medium_findings,
            "low": summary.low_findings,
        }

        # Top issues by pillar
        pillar_issues = {}
        for pillar in Pillar:
            pillar_findings = [
                f for f in findings if f.pillar == pillar and f.status == CheckStatus.FAIL
            ]
            pillar_issues[pillar.value] = len(pillar_findings)

        return {
            "total_checks": summary.total_checks,
            "registered_checks": registered_checks,
            "journey_findings": summary.journey_findings,
            "pass_rate": round(pass_rate, 1),
            "risk_score": risk_score,
            "status_breakdown": status_breakdown,
            "severity_breakdown": severity_breakdown,
            "pillar_issues": pillar_issues,
            "instances_assessed": len(assessment_result.instances),
            "execution_time": assessment_result.metadata.execution_time_seconds,
            "has_critical_issues": summary.critical_findings > 0,
            "has_high_issues": summary.high_findings > 0,
        }

    def _calculate_risk_score(self, findings: List[Finding]) -> int:
        # Calculate overall risk score based on failed findings and their severity
        failed_findings = [f for f in findings if f.status == CheckStatus.FAIL]

        if not failed_findings:
            return 0

        # Weight by severity: Critical=10, High=7, Medium=4, Low=1
        severity_weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 1,
        }

        total_weight = sum(severity_weights.get(f.severity, 1) for f in failed_findings)
        max_possible = len(failed_findings) * 10  # If all were critical

        # Scale to 0-100
        risk_score = min(100, int((total_weight / max_possible) * 100)) if max_possible > 0 else 0

        return risk_score

    def _organize_findings_by_pillar(self, findings: List[Finding]) -> Dict[str, List[Finding]]:
        # Organize findings by AWS Well-Architected Framework pillar
        organized = {}

        for pillar in Pillar:
            pillar_findings = [f for f in findings if f.pillar == pillar]
            # Sort by severity (critical first) then by status (failed first)
            pillar_findings.sort(
                key=lambda x: (
                    0 if x.status == CheckStatus.FAIL else 1,  # Failed first
                    ["critical", "high", "medium", "low"].index(x.severity.value),  # Severity order
                )
            )
            organized[pillar.value] = pillar_findings

        return organized

    def _generate_charts_data(self, assessment_result: AssessmentResult) -> Dict[str, Any]:
        # Generate data for interactive charts and visualizations
        findings = assessment_result.findings
        summary = assessment_result.summary

        # Status distribution for pie chart
        status_chart = {
            "labels": ["Passed", "Failed", "Error", "Skipped", "N/A"],
            "data": [
                summary.passed_checks,
                summary.failed_checks,
                summary.error_checks,
                summary.skipped_checks,
                summary.not_applicable_checks,
            ],
            "colors": ["#28a745", "#dc3545", "#ffc107", "#6c757d", "#adb5bd"],
        }

        # Severity distribution for failed findings
        severity_chart = {
            "labels": ["Critical", "High", "Medium", "Low"],
            "data": [
                summary.critical_findings,
                summary.high_findings,
                summary.medium_findings,
                summary.low_findings,
            ],
            "colors": ["#dc3545", "#fd7e14", "#ffc107", "#17a2b8"],
        }

        # Pillar breakdown
        pillar_data = {}
        for pillar in Pillar:
            pillar_findings = [f for f in findings if f.pillar == pillar]
            failed_count = sum(1 for f in pillar_findings if f.status == CheckStatus.FAIL)
            total_count = len(pillar_findings)
            pillar_data[pillar.value] = {
                "total": total_count,
                "failed": failed_count,
                "passed": total_count - failed_count,
                "pass_rate": (
                    round((total_count - failed_count) / total_count * 100, 1)
                    if total_count > 0
                    else 0
                ),
            }

        return {
            "status_distribution": status_chart,
            "severity_distribution": severity_chart,
            "pillar_breakdown": pillar_data,
        }

    def _create_executive_summary(self, assessment_result: AssessmentResult) -> Dict[str, Any]:
        # Create executive summary with key insights and recommendations
        findings = assessment_result.findings
        summary = assessment_result.summary

        # Key insights
        insights = []

        if summary.critical_findings > 0:
            insights.append(
                {
                    "type": "critical",
                    "message": f"Found {summary.critical_findings} critical security or compliance issues requiring immediate attention.",
                }
            )

        if summary.high_findings > 0:
            insights.append(
                {
                    "type": "warning",
                    "message": f"Identified {summary.high_findings} high-priority issues that should be addressed soon.",
                }
            )

        # Pass rate for insight thresholds — exclude NOT_APPLICABLE and SKIPPED
        # from the denominator so the number reflects checks that actually
        # assessed something.
        evaluated_checks = (
            summary.total_checks - summary.skipped_checks - summary.not_applicable_checks
        )
        pass_rate = (summary.passed_checks / evaluated_checks * 100) if evaluated_checks > 0 else 0

        if pass_rate >= 90:
            insights.append(
                {
                    "type": "success",
                    "message": f"Excellent compliance rate of {pass_rate:.1f}% indicates a well-configured Connect deployment.",
                }
            )
        elif pass_rate >= 75:
            insights.append(
                {
                    "type": "info",
                    "message": f"Good compliance rate of {pass_rate:.1f}% with room for improvement in some areas.",
                }
            )
        else:
            insights.append(
                {
                    "type": "warning",
                    "message": f"Compliance rate of {pass_rate:.1f}% indicates significant configuration issues need attention.",
                }
            )

        # Top recommendations
        recommendations = []

        # Get top failed checks by severity
        failed_findings = [f for f in findings if f.status == CheckStatus.FAIL]
        critical_findings = [f for f in failed_findings if f.severity == Severity.CRITICAL]
        high_findings = [f for f in failed_findings if f.severity == Severity.HIGH]

        if critical_findings:
            recommendations.append(
                {
                    "priority": "critical",
                    "title": "Address Critical Security Issues",
                    "description": f"Immediately review and remediate {len(critical_findings)} critical findings to ensure security and compliance.",
                    "findings_count": len(critical_findings),
                }
            )

        if high_findings:
            recommendations.append(
                {
                    "priority": "high",
                    "title": "Resolve High-Priority Configuration Issues",
                    "description": f"Address {len(high_findings)} high-priority findings to improve system reliability and performance.",
                    "findings_count": len(high_findings),
                }
            )

        # Pillar-specific recommendations
        for pillar in Pillar:
            pillar_failed = [f for f in failed_findings if f.pillar == pillar]
            if len(pillar_failed) >= 3:  # Only recommend if significant issues
                pillar_name = pillar.value.replace("_", " ").title()
                recommendations.append(
                    {
                        "priority": "medium",
                        "title": f"Improve {pillar_name}",
                        "description": f"Focus on {pillar_name.lower()} improvements with {len(pillar_failed)} findings to address.",
                        "findings_count": len(pillar_failed),
                    }
                )

        return {
            "insights": insights,
            "recommendations": recommendations[:5],  # Limit to top 5
            "assessment_date": assessment_result.timestamp,
            "instances_count": len(assessment_result.instances),
            "total_findings": len(failed_findings),
        }

    # ------------------------------------------------------------------
    # Caller Journey Map template helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _journey_map_entries(assessment_result: AssessmentResult) -> List[Dict[str, Any]]:
        """Return the raw journey-map entries the engine attached."""
        return getattr(assessment_result, "journey_map_entries", []) or []

    def _journey_map_entries_json(self, assessment_result: AssessmentResult) -> str:
        """Serialize journey entries safely for an HTML JSON data island."""
        entries = self._journey_map_entries(assessment_result)
        serialized = json.dumps(entries, ensure_ascii=False)
        return (
            serialized.replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
        )

    @staticmethod
    def _journey_map_instance_list(
        assessment_result: AssessmentResult,
    ) -> List[Dict[str, str]]:
        """
        Return one entry per unique instance appearing in the journey
        map, preserving the deterministic order the engine produced.
        Used to populate the first dropdown ("Which instance?").
        """
        seen: Set[str] = set()
        out: List[Dict[str, str]] = []
        for entry in getattr(assessment_result, "journey_map_entries", []) or []:
            instance_id = entry.get("instance_id", "")
            if instance_id in seen:
                continue
            seen.add(instance_id)
            out.append(
                {
                    "id": instance_id,
                    "label": entry.get("instance_display_name", instance_id),
                }
            )
        return out

    def _get_filter_options(
        self,
        findings: List[Finding],
        instances: List[ConnectInstance],
    ) -> Dict[str, Any]:
        """
        Build the filter dropdown options.

        For the instance filter we return a list of ``{"id", "label"}`` dicts
        so the dropdown can display the friendly alias (``label``) while the
        option's underlying value stays as the UUID (``id``). That preserves
        matching against ``finding.resource_id`` which is still a raw UUID.
        Instances discovered in the assessment take precedence for label
        resolution; instances that only appear in findings (e.g. from
        historical data) fall back to the UUID.
        """
        severities = list(set(f.severity.value for f in findings))
        statuses = list(set(f.status.value for f in findings))
        pillars = list(set(f.pillar.value for f in findings))
        default_status = CheckStatus.FAIL.value if CheckStatus.FAIL.value in statuses else "all"

        failed_severities = {
            finding.severity for finding in findings if finding.status == CheckStatus.FAIL
        }
        if Severity.CRITICAL in failed_severities:
            default_severity = Severity.CRITICAL.value
        elif Severity.HIGH in failed_severities:
            default_severity = Severity.HIGH.value
        else:
            default_severity = "all"

        # Build UUID → display_name from the instance list so we can attach
        # friendly labels to the dropdown options.
        alias_by_id: Dict[str, str] = {inst.instance_id: inst.display_name for inst in instances}

        instance_ids = sorted(
            {f.resource_id for f in findings if f.resource_type == "ConnectInstance"}
        )
        instance_options = [{"id": iid, "label": alias_by_id.get(iid, iid)} for iid in instance_ids]

        return {
            "severities": sorted(
                severities, key=lambda x: ["critical", "high", "medium", "low"].index(x)
            ),
            "default_severity": default_severity,
            "statuses": sorted(statuses),
            "default_status": default_status,
            "pillars": sorted(pillars),
            "instances": instance_options,
        }

    def _save_report(self, html_content: str, output_path: str) -> None:
        # Save HTML report to specified path
        try:
            # Ensure directory exists (only if there's a directory component)
            output_dir = os.path.dirname(output_path)
            if output_dir:
                os.makedirs(output_dir, exist_ok=True)

            with open(output_path, "w", encoding="utf-8") as f:
                f.write(html_content)

        except Exception as e:
            self.logger.error(f"Failed to save report to {output_path}: {str(e)}")
            raise

    @staticmethod
    def _safe_json_encode(value) -> str:
        """JSON-encode a value, escaping sequences that could break out of script tags."""
        return json.dumps(value).replace("</", "<\\/")

    @staticmethod
    def _render_instance_label(resource_id: str, alias_by_id: Dict[str, str]) -> str:
        """
        Render a Finding.resource_id as "'alias' (uuid)" when the alias is
        known, otherwise just the bare UUID.

        ``alias_by_id`` is built once per report in
        ``_prepare_template_context`` from the assessment's instance list
        (see ``instance_alias_by_id`` in the template context) — this
        keeps the filter itself a pure function of its arguments rather
        than reaching back into instance state, so it's trivial to test
        and doesn't depend on render order.
        """
        alias = alias_by_id.get(resource_id)
        if alias:
            return f"'{alias}' ({resource_id})"
        return resource_id

    # ------------------------------------------------------------------
    # Markdown filter
    # ------------------------------------------------------------------
    #
    # The instance is built lazily and cached because parser construction
    # is expensive relative to the per-finding render cost; the same
    # parser is safe to reuse across renders (stateless per call).
    _MARKDOWN_PARSER = None

    @classmethod
    def _get_markdown_parser(cls):
        """Return a shared, XSS-safe markdown-it parser."""
        if cls._MARKDOWN_PARSER is None:
            from markdown_it import MarkdownIt

            # ``commonmark`` preset with html=False means the parser
            # renders ``<script>`` in source as literal escaped text,
            # never as an HTML tag. That's the security posture we
            # need since a finding description can interpolate flow-
            # authored strings (queue names, prompt text, attribute
            # names) which we do not fully trust.
            cls._MARKDOWN_PARSER = MarkdownIt("commonmark", {"html": False, "breaks": False})
        return cls._MARKDOWN_PARSER

    @classmethod
    def _render_markdown(cls, text) -> str:
        """
        Convert a markdown string to HTML for embedding in a template.

        Non-string / empty / None values pass through as empty strings so
        the filter never crashes a template render. Callers who want a
        placeholder for empty descriptions should handle that in the
        template rather than here.
        """
        if not text:
            return ""
        if not isinstance(text, str):
            text = str(text)
        return cls._get_markdown_parser().render(text)

    # ------------------------------------------------------------------
    # Evidence renderer
    # ------------------------------------------------------------------
    #
    # Checks stash raw diagnostics on ``Finding.evidence`` — dicts of
    # scalars, lists of dicts, ARNs, nested dicts. The old template just
    # dumped this as one big JSON blob in a ``<pre>`` block. That was
    # unreadable once evidence grew past a handful of fields; a 10-item
    # ``hardcoded_details`` list plus a couple of scalars ran ~60 lines
    # of dense JSON.
    #
    # This filter turns evidence into structured HTML: a definition list
    # for top-level scalars, a real HTML table for any list-of-dicts key
    # (one row per entry, columns pulled from the union of keys), and
    # nested sub-blocks for dict-of-dict evidence. ARN-shaped values are
    # abbreviated in-place with the full value kept in a ``title=``
    # tooltip so the reader can hover to see the full string but doesn't
    # get a wall of ``arn:aws:connect:us-east-1:...`` on screen.
    #
    # Falls back to pretty-printed JSON only for shapes it can't
    # recognise (rare in practice; every check we ship uses one of the
    # patterns above).

    _EVIDENCE_ARN_ABBREV = 60
    _EVIDENCE_LONG_STRING_ABBREV = 100

    @classmethod
    def _render_evidence(cls, evidence) -> str:
        """Render a Finding's evidence dict as structured HTML."""
        if not evidence:
            return ""
        if not isinstance(evidence, dict):
            # A check may have stashed a non-dict for legacy reasons —
            # render as JSON so nothing crashes.
            return cls._render_evidence_fallback(evidence)
        return cls._render_evidence_dict(evidence, depth=0)

    @classmethod
    def _render_evidence_dict(cls, evidence: Dict[str, Any], depth: int = 0) -> str:
        """
        Turn a dict into an HTML fragment:

          * scalar keys go into a ``<dl class="evidence-scalars">``
          * list-of-dicts keys become tables (one per key)
          * list-of-scalars keys become ``<ul>``
          * nested dict keys become sub-sections with a heading and a
            recursive call
        """
        scalar_items: List[tuple] = []
        list_of_dicts: List[tuple] = []
        list_of_scalars: List[tuple] = []
        nested_dicts: List[tuple] = []

        for key, value in evidence.items():
            if isinstance(value, dict):
                nested_dicts.append((key, value))
            elif isinstance(value, list):
                if value and all(isinstance(v, dict) for v in value):
                    list_of_dicts.append((key, value))
                else:
                    list_of_scalars.append((key, value))
            else:
                scalar_items.append((key, value))

        parts: List[str] = []
        if scalar_items:
            parts.append(cls._render_scalar_dl(scalar_items))
        for key, rows in list_of_dicts:
            parts.append(cls._render_table(key, rows))
        for key, values in list_of_scalars:
            parts.append(cls._render_scalar_list(key, values))
        for key, sub in nested_dicts:
            parts.append(cls._render_nested_dict(key, sub, depth + 1))
        return "".join(parts) if parts else cls._render_evidence_fallback(evidence)

    @classmethod
    def _render_scalar_dl(cls, items: List[tuple]) -> str:
        """Definition list for scalar key/value pairs."""
        rows: List[str] = ['<dl class="evidence-scalars">']
        for key, value in items:
            rows.append(f"<dt>{cls._humanize_key(key)}</dt>")
            rows.append(f"<dd>{cls._format_scalar_value(value)}</dd>")
        rows.append("</dl>")
        return "".join(rows)

    @classmethod
    def _render_table(cls, key: str, rows: List[Dict[str, Any]]) -> str:
        """
        HTML table for a list of dicts. Column order = keys of the first
        row, then any additional keys any subsequent row introduces (in
        insertion order). Cells format ARN-shaped and long-string values
        with hover tooltips.
        """
        # Collect column keys preserving first-appearance order.
        columns: List[str] = []
        seen: set = set()
        for row in rows:
            for k in row.keys():
                if k not in seen:
                    seen.add(k)
                    columns.append(k)
        header_cells = "".join(f"<th>{cls._humanize_key(c)}</th>" for c in columns)
        body_rows = []
        for row in rows:
            cells = "".join(f"<td>{cls._format_scalar_value(row.get(c, ''))}</td>" for c in columns)
            body_rows.append(f"<tr>{cells}</tr>")
        title = cls._humanize_key(key)
        count = len(rows)
        # A caveat next to the count reminds the reader that the check
        # only preserves the first N entries in evidence (see the checks —
        # most cap at 10) so nothing looks like the full universe.
        return (
            '<div class="evidence-section">'
            f'<h6 class="evidence-heading">{title} '
            f'<span class="evidence-count">({count} row{"s" if count != 1 else ""})</span></h6>'
            '<div class="evidence-table-wrap">'
            f'<table class="evidence-table"><thead><tr>{header_cells}</tr></thead>'
            f"<tbody>{''.join(body_rows)}</tbody></table>"
            "</div></div>"
        )

    @classmethod
    def _render_scalar_list(cls, key: str, values: List[Any]) -> str:
        """Unordered list for a list-of-scalars."""
        items = "".join(f"<li>{cls._format_scalar_value(v)}</li>" for v in values)
        title = cls._humanize_key(key)
        return (
            '<div class="evidence-section">'
            f'<h6 class="evidence-heading">{title} '
            f'<span class="evidence-count">({len(values)})</span></h6>'
            f'<ul class="evidence-list">{items}</ul>'
            "</div>"
        )

    @classmethod
    def _render_nested_dict(cls, key: str, sub: Dict[str, Any], depth: int) -> str:
        """Sub-section for a nested dict value."""
        title = cls._humanize_key(key)
        return (
            f'<div class="evidence-section evidence-nested">'
            f'<h6 class="evidence-heading">{title}</h6>'
            f"{cls._render_evidence_dict(sub, depth=depth)}"
            "</div>"
        )

    @classmethod
    def _render_evidence_fallback(cls, value: Any) -> str:
        """Pretty-print JSON as a last resort."""
        try:
            body = json.dumps(value, indent=2, default=str)
        except TypeError:
            body = str(value)
        # HTML-escape the JSON — this is unstructured content going into
        # a <pre>; no filter chain protects us here.
        import html as _html

        return f'<pre class="evidence-json">{_html.escape(body)}</pre>'

    @staticmethod
    def _humanize_key(key: Any) -> str:
        """Turn ``hardcoded_details`` into ``Hardcoded details``."""
        import html as _html

        s = str(key).replace("_", " ").strip()
        return _html.escape(s[:1].upper() + s[1:]) if s else ""

    @classmethod
    def _format_scalar_value(cls, value: Any) -> str:
        """
        Format a scalar for display inside a table cell or <dd>.

        Abbreviates ARNs and very long strings with a hover tooltip
        carrying the full value. Boolean / numeric / None pass through
        with type-appropriate rendering.
        """
        import html as _html

        if value is None:
            return '<span class="evidence-null">—</span>'
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return _html.escape(str(value))
        if isinstance(value, (list, tuple)):
            # Inline mini-list, comma-separated.
            return ", ".join(cls._format_scalar_value(v) for v in value) or "—"
        if isinstance(value, dict):
            # Nested dict inside a cell — render as key=value pairs.
            return ", ".join(
                f"{_html.escape(str(k))}={cls._format_scalar_value(v)}" for k, v in value.items()
            )
        s = str(value)
        if s.startswith("arn:aws:"):
            return (
                f'<code class="evidence-arn" title="{_html.escape(s)}">'
                f"{_html.escape(cls._abbrev_arn(s))}"
                "</code>"
            )
        if len(s) > cls._EVIDENCE_LONG_STRING_ABBREV:
            return (
                f'<span class="evidence-abbrev" title="{_html.escape(s)}">'
                f"{_html.escape(s[: cls._EVIDENCE_LONG_STRING_ABBREV - 1])}\u2026"
                "</span>"
            )
        return _html.escape(s)

    @classmethod
    def _abbrev_arn(cls, arn: str) -> str:
        """
        Shorten a Connect / Lambda / etc ARN for on-screen readability.

        Keep the service name and the *last* segment of the resource
        path so the reader can tell what it points at (flow id, function
        name, etc) — the account ID and region live in the tooltip.
        """
        # arn:aws:<svc>:<region>:<acct>:<resource path>
        parts = arn.split(":", 5)
        if len(parts) < 6:
            return arn if len(arn) <= cls._EVIDENCE_ARN_ABBREV else arn[:57] + "\u2026"
        svc = parts[2]
        resource = parts[5]
        tail = resource.rsplit("/", 1)[-1] if "/" in resource else resource
        prefix = resource.rsplit("/", 1)[0] if "/" in resource else ""
        # Show the resource type (e.g. "contact-flow") when it fits.
        if prefix and "/" in prefix:
            resource_type = prefix.rsplit("/", 1)[-1]
            short = f"{svc}:…/{resource_type}/{tail}"
        elif prefix:
            short = f"{svc}:{prefix}/{tail}"
        else:
            short = f"{svc}:{tail}"
        if len(short) > cls._EVIDENCE_ARN_ABBREV:
            short = short[: cls._EVIDENCE_ARN_ABBREV - 1] + "\u2026"
        return short

    # Template filter functions
    def _safe_url(self, url: Any) -> str:
        """
        Return ``url`` only if it uses a safe scheme, else ``"#"``.

        Guards ``href`` sinks against ``javascript:``/``data:``/``vbscript:``
        URIs. Allows absolute http(s) links and root-relative paths; anything
        else (including scheme-relative ``//host`` and unparseable values)
        collapses to ``"#"``. Autoescaping still handles quote/entity
        escaping — this only constrains the scheme.
        """
        if not isinstance(url, str):
            return "#"
        candidate = url.strip()
        if candidate.startswith("/") and not candidate.startswith("//"):
            return candidate
        try:
            scheme = urlparse(candidate).scheme.lower()
        except ValueError:
            return "#"
        return candidate if scheme in ("http", "https", "mailto") else "#"

    def _format_datetime(self, dt: datetime) -> str:
        # Format datetime for display
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            except (ValueError, AttributeError):
                return dt
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC") if dt else ""

    def _format_duration(self, seconds: float) -> str:
        # Format duration in seconds to human readable format
        if seconds < 60:
            return f"{seconds:.1f}s"
        elif seconds < 3600:
            return f"{seconds / 60:.1f}m"
        else:
            return f"{seconds / 3600:.1f}h"

    def _get_severity_color(self, severity: str) -> str:
        # Get color code for severity level
        colors = {
            "critical": "#dc3545",
            "high": "#fd7e14",
            "medium": "#ffc107",
            "low": "#17a2b8",
        }
        return colors.get(severity.lower(), "#6c757d")

    def _get_status_color(self, status: str) -> str:
        # Get color code for check status
        colors = {
            "pass": "#28a745",
            "fail": "#dc3545",
            "error": "#ffc107",
            "skipped": "#6c757d",
            "not_applicable": "#adb5bd",
        }
        return colors.get(status.lower(), "#6c757d")

    def _get_pillar_icon(self, pillar: str) -> str:
        # Get icon class for pillar
        icons = {
            "resilience": "fas fa-shield-alt",
            "security": "fas fa-lock",
            "cost_optimization": "fas fa-dollar-sign",
        }
        return icons.get(pillar.lower(), "fas fa-cog")

    def _load_external_css(self) -> str:
        """Load CSS from external template files."""
        try:
            template_base = Path(__file__).parent / "templates" / "css"
            css_files = [
                "main.css",
                "components.css",
                "findings.css",
                "charts.css",
                # journey_map.css styles the Caller Journey Map section
                # (top-N flows + Mermaid diagrams). Loaded after findings
                # so its dark-mode overrides win where the two overlap.
                "journey_map.css",
                "responsive.css",
            ]

            combined_css = []
            for css_file in css_files:
                css_path = template_base / css_file
                if css_path.exists():
                    with open(css_path, "r", encoding="utf-8") as f:
                        combined_css.append(f.read())
                else:
                    self.logger.warning(f"CSS file not found: {css_path}")

            return "\n\n".join(combined_css)
        except Exception as e:
            self.logger.error(f"Failed to load external CSS: {e}")
            return ""

    def _load_external_js(self) -> str:
        """Load JavaScript from external template files."""
        try:
            template_base = Path(__file__).parent / "templates" / "js"
            js_path = template_base / "report-controller.js"

            if js_path.exists():
                with open(js_path, "r", encoding="utf-8") as f:
                    return f.read()
            else:
                self.logger.warning(f"JavaScript file not found: {js_path}")
                return ""
        except Exception as e:
            self.logger.error(f"Failed to load external JavaScript: {e}")
            return ""
