"""
Tests for the HTML report generator.

This module tests the ReportGenerator class functionality including
HTML generation, template rendering, and interactive features.
"""

import json
import os
import tempfile
from datetime import datetime
from unittest.mock import patch

import pytest

from amazon_connect_assessment.models import (
    AssessmentMetadata,
    AssessmentResult,
    AssessmentSummary,
    CheckStatus,
    ConnectInstance,
    Finding,
    Pillar,
    Severity,
)
from amazon_connect_assessment.report_generator import ReportGenerator


@pytest.fixture
def sample_assessment_result():
    """Create a sample assessment result for testing."""

    # Create sample Connect instance
    instance = ConnectInstance(
        instance_id="test-instance-123",
        instance_arn="arn:aws:connect:us-east-1:123456789012:instance/test-instance-123",
        identity_management_type="CONNECT_MANAGED",
        inbound_calls_enabled=True,
        outbound_calls_enabled=True,
        instance_alias="test-instance",
        status="ACTIVE",
    )

    # Create sample findings
    findings = [
        Finding(
            check_id="SEC-001",
            check_name="Test Security Check",
            pillar=Pillar.SECURITY,
            severity=Severity.CRITICAL,
            status=CheckStatus.FAIL,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description="Test security finding description",
            remediation="Test remediation guidance",
            evidence={"test_key": "test_value"},
            timestamp=datetime.now(),
        ),
        Finding(
            check_id="RES-001",
            check_name="Test Resilience Check",
            pillar=Pillar.RESILIENCE,
            severity=Severity.HIGH,
            status=CheckStatus.PASS,
            resource_id=instance.instance_id,
            resource_type="ConnectInstance",
            description="Test resilience finding description",
            remediation="Configuration is compliant",
            evidence={},
            timestamp=datetime.now(),
        ),
    ]

    # Create summary
    summary = AssessmentSummary(
        total_checks=2,
        passed_checks=1,
        failed_checks=1,
        error_checks=0,
        skipped_checks=0,
        critical_findings=1,
        high_findings=0,
        medium_findings=0,
        low_findings=0,
    )

    # Create metadata
    metadata = AssessmentMetadata(
        tool_version="0.1.0",
        execution_time_seconds=30.5,
        aws_account_id="123456789012",
        aws_region="us-east-1",
        execution_environment="Test Environment",
        python_version="3.12.7",
    )

    # Create assessment result
    return AssessmentResult(
        assessment_id="test-assessment-123",
        timestamp=datetime.now(),
        account_id="123456789012",
        region="us-east-1",
        instances=[instance],
        findings=findings,
        summary=summary,
        metadata=metadata,
        execution_errors=[],
    )


class TestReportGenerator:
    """Test ReportGenerator functionality."""

    def test_report_generator_initialization(self):
        """Test ReportGenerator initialization."""
        generator = ReportGenerator()
        assert generator is not None
        assert generator.template_env is not None

    def test_filename_template_rejects_paths(self, sample_assessment_result):
        generator = ReportGenerator()

        with pytest.raises(ValueError, match="filename, not a path"):
            generator._generate_filename(
                "../../outside/report",
                sample_assessment_result,
                "json",
            )

    def test_generate_html_report_basic(self, sample_assessment_result):
        """Test basic HTML report generation."""
        generator = ReportGenerator()

        html_content = generator.generate_html_report(
            assessment_result=sample_assessment_result, include_raw_data=False
        )

        # Verify HTML content contains expected elements
        assert "<!DOCTYPE html>" in html_content
        assert "Amazon Connect Assessment Tool Report" in html_content
        assert sample_assessment_result.assessment_id in html_content
        assert sample_assessment_result.account_id in html_content
        assert "Test Security Check" in html_content
        assert "Test Resilience Check" in html_content

    def test_generate_json_report_includes_journey_map_data(
        self, sample_assessment_result, tmp_path
    ):
        sample_assessment_result.journey_map_entries = [
            {
                "instance_id": "test-instance-123",
                "phone_number": "+18005551234",
                "flow_id": "flow-1",
                "mermaid_diagram": "flowchart LR",
            }
        ]
        sample_assessment_result.journey_map_status = {
            "reason": "no_phone_numbers",
            "message": "No inbound phone numbers were found.",
            "hint": "Assign a phone number to a contact flow.",
        }

        path = ReportGenerator().generate_json_report(sample_assessment_result, str(tmp_path))

        with open(path, encoding="utf-8") as report_file:
            report_data = json.load(report_file)

        assert report_data["journey_map_entries"] == sample_assessment_result.journey_map_entries
        assert report_data["journey_map_status"] == sample_assessment_result.journey_map_status

    def test_html_report_resource_id_shows_instance_alias(self, sample_assessment_result):
        """
        Regression test: the "Resource ID" line in each finding card used
        to render only the raw instance UUID, with no way to tell which
        instance that was without cross-referencing the executive
        summary. It should now show the friendly alias alongside the
        UUID, matching ConnectInstance.display_name's format.
        """
        generator = ReportGenerator()
        html_content = generator.generate_html_report(
            assessment_result=sample_assessment_result, include_raw_data=False
        )
        instance = sample_assessment_result.instances[0]
        assert instance.instance_alias == "test-instance"
        expected = f"&#39;{instance.instance_alias}&#39; ({instance.instance_id})"
        assert expected in html_content

    def test_instance_label_filter_falls_back_to_bare_id(self):
        """No alias known for a UUID -> render the bare UUID, not 'None (uuid)'."""
        label = ReportGenerator._render_instance_label("unknown-uuid", {})
        assert label == "unknown-uuid"

    def test_instance_label_filter_uses_alias_when_present(self):
        label = ReportGenerator._render_instance_label("abc-123", {"abc-123": "prod-cc"})
        assert label == "'prod-cc' (abc-123)"

    def test_generate_html_report_with_raw_data(self, sample_assessment_result):
        """Test HTML report generation with raw data included."""
        generator = ReportGenerator()

        html_content = generator.generate_html_report(
            assessment_result=sample_assessment_result, include_raw_data=True
        )

        # Verify raw data is included
        assert "raw-data-section" in html_content
        assert "assessment_id" in html_content  # From JSON data

    def test_generate_csv_report_includes_instance_alias(self, sample_assessment_result):
        """
        Regression test: same alias-visibility gap as the HTML report
        applied to CSV export — the "Instance ID" column had the raw UUID
        with no alias anywhere in the row.
        """
        import csv

        generator = ReportGenerator()
        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = generator.generate_csv_report(sample_assessment_result, temp_dir)
            with open(output_path, newline="", encoding="utf-8") as f:
                rows = list(csv.reader(f))

        headers = rows[0]
        assert "Instance Alias" in headers
        alias_idx = headers.index("Instance Alias")
        instance_id_idx = headers.index("Instance ID")
        instance = sample_assessment_result.instances[0]
        for row in rows[1:]:
            assert row[instance_id_idx] == instance.instance_id
            assert row[alias_idx] == instance.instance_alias

    def test_generate_html_report_with_file_output(self, sample_assessment_result):
        """Test HTML report generation with file output."""
        generator = ReportGenerator()

        with tempfile.TemporaryDirectory() as temp_dir:
            output_path = os.path.join(temp_dir, "test_report.html")

            html_content = generator.generate_html_report(
                assessment_result=sample_assessment_result,
                output_path=output_path,
                include_raw_data=False,
            )

            # Verify file was created
            assert os.path.exists(output_path)

            # Verify file content matches returned content
            with open(output_path, "r", encoding="utf-8") as f:
                file_content = f.read()

            assert file_content == html_content

    def test_summary_statistics_generation(self, sample_assessment_result):
        """Test summary statistics generation."""
        generator = ReportGenerator()

        stats = generator._generate_summary_statistics(sample_assessment_result)

        assert stats["total_checks"] == 2
        assert stats["registered_checks"] == 2
        assert stats["journey_findings"] == 0
        assert stats["pass_rate"] == 50.0  # 1 passed out of 2
        assert stats["status_breakdown"]["passed"] == 1
        assert stats["status_breakdown"]["failed"] == 1
        assert stats["severity_breakdown"]["critical"] == 1
        assert stats["has_critical_issues"] is True

    def test_risk_score_calculation(self, sample_assessment_result):
        """Test risk score calculation."""
        generator = ReportGenerator()

        # Test with critical finding
        risk_score = generator._calculate_risk_score(sample_assessment_result.findings)
        assert risk_score > 0  # Should have some risk due to critical finding

        # Test with no failed findings
        passed_findings = [
            f for f in sample_assessment_result.findings if f.status == CheckStatus.PASS
        ]
        risk_score_no_failures = generator._calculate_risk_score(passed_findings)
        assert risk_score_no_failures == 0

    def test_findings_organization_by_pillar(self, sample_assessment_result):
        """Test findings organization by pillar."""
        generator = ReportGenerator()

        organized = generator._organize_findings_by_pillar(sample_assessment_result.findings)

        assert "security" in organized
        assert "resilience" in organized
        assert len(organized["security"]) == 1
        assert len(organized["resilience"]) == 1
        assert organized["security"][0].check_name == "Test Security Check"
        assert organized["resilience"][0].check_name == "Test Resilience Check"

    def test_charts_data_generation(self, sample_assessment_result):
        """Test charts data generation."""
        generator = ReportGenerator()

        charts_data = generator._generate_charts_data(sample_assessment_result)

        # Verify status distribution chart
        assert "status_distribution" in charts_data
        status_chart = charts_data["status_distribution"]
        assert "labels" in status_chart
        assert "data" in status_chart
        assert "colors" in status_chart

        # Verify severity distribution chart
        assert "severity_distribution" in charts_data
        severity_chart = charts_data["severity_distribution"]
        assert severity_chart["data"][0] == 1  # 1 critical finding

        # Verify pillar breakdown
        assert "pillar_breakdown" in charts_data
        pillar_data = charts_data["pillar_breakdown"]
        assert "security" in pillar_data
        assert "resilience" in pillar_data

    def test_executive_summary_creation(self, sample_assessment_result):
        """Test executive summary creation."""
        generator = ReportGenerator()

        summary = generator._create_executive_summary(sample_assessment_result)

        assert "insights" in summary
        assert "recommendations" in summary
        assert "assessment_date" in summary
        assert "instances_count" in summary
        assert "total_findings" in summary

        # Should have insights about critical findings
        insights = summary["insights"]
        critical_insight = next((i for i in insights if i["type"] == "critical"), None)
        assert critical_insight is not None

    def test_filter_options_generation(self, sample_assessment_result):
        """Test filter options generation."""
        generator = ReportGenerator()

        # _get_filter_options takes instances too now so the report can
        # show the customer-chosen alias in the instance dropdown rather
        # than the raw UUID. Pass the fixture's instance list through.
        options = generator._get_filter_options(
            sample_assessment_result.findings,
            sample_assessment_result.instances,
        )

        assert "severities" in options
        assert "statuses" in options
        assert "pillars" in options
        assert "instances" in options

        assert "critical" in options["severities"]
        assert "high" in options["severities"]
        assert "pass" in options["statuses"]
        assert "fail" in options["statuses"]
        assert "security" in options["pillars"]
        assert "resilience" in options["pillars"]
        # Instance entries are {id, label} pairs — the UUID is the option
        # value (so filtering matches finding.resource_id), the label is
        # the friendly alias.
        for entry in options["instances"]:
            assert "id" in entry
            assert "label" in entry

    def test_template_filters(self, sample_assessment_result):
        """Test custom template filters."""
        generator = ReportGenerator()

        # Test datetime formatting
        dt = datetime(2023, 1, 15, 10, 30, 45)
        formatted = generator._format_datetime(dt)
        assert "2023-01-15 10:30:45 UTC" in formatted

        # Test duration formatting
        assert generator._format_duration(30.5) == "30.5s"
        assert generator._format_duration(90) == "1.5m"
        assert generator._format_duration(3700) == "1.0h"

        # Test color functions
        assert generator._get_severity_color("critical") == "#dc3545"
        assert generator._get_status_color("pass") == "#28a745"
        assert generator._get_pillar_icon("security") == "fas fa-lock"


class TestMarkdownFilter:
    """
    Finding descriptions are authored in markdown. The template runs
    them through ``_render_markdown`` and marks the result safe — so
    that filter has to (a) produce readable HTML for the paragraph +
    list + code-block subset we use, and (b) never emit raw HTML from
    the source string, because untrusted flow content (queue names,
    prompt text) gets interpolated into these descriptions.
    """

    def test_paragraph_break_produces_paragraph_tags(self):
        out = ReportGenerator._render_markdown("First para.\n\nSecond para.")
        assert "<p>First para.</p>" in out
        assert "<p>Second para.</p>" in out

    def test_bullet_list_renders_ul(self):
        src = "Intro line.\n\n* item one\n* item two\n* item three\n"
        out = ReportGenerator._render_markdown(src)
        assert "<ul>" in out
        assert "<li>item one</li>" in out
        assert "<li>item three</li>" in out

    def test_numbered_list_renders_ol(self):
        src = "1. first\n2. second\n3. third\n"
        out = ReportGenerator._render_markdown(src)
        assert "<ol>" in out
        assert "<li>first</li>" in out

    def test_fenced_code_block_renders_pre_code(self):
        src = "Before.\n\n```\nsome preformatted text\n```\n"
        out = ReportGenerator._render_markdown(src)
        assert "<pre><code>" in out
        assert "some preformatted text" in out

    def test_inline_code_renders_code_tags(self):
        out = ReportGenerator._render_markdown("Set `$.Attributes.foo` to something.")
        assert "<code>$.Attributes.foo</code>" in out

    def test_bold_renders_strong(self):
        out = ReportGenerator._render_markdown("This is **important** text.")
        assert "<strong>important</strong>" in out

    def test_raw_html_in_source_is_escaped(self):
        # Untrusted flow content might contain angle brackets or a
        # <script> tag — markdown-it-py with html=False must render
        # those as text, never as active HTML.
        malicious = "Look at <script>alert(1)</script> and <img src=x onerror=alert(1)>."
        out = ReportGenerator._render_markdown(malicious)
        assert "<script>" not in out
        assert "&lt;script&gt;" in out
        assert "onerror=" not in out or "&lt;img" in out  # tag is escaped

    def test_ssml_in_code_block_survives_intact(self):
        # A common pattern in the injection-check description shows an
        # SSML injection example inside a fenced code block. The angle
        # brackets should render as escaped text so the reader sees
        # them, and no HTML actually enters the page.
        src = "```\n<speak>Hello</speak>\n```\n"
        out = ReportGenerator._render_markdown(src)
        assert "&lt;speak&gt;" in out
        assert "<speak>" not in out

    def test_none_and_empty_pass_through(self):
        assert ReportGenerator._render_markdown(None) == ""
        assert ReportGenerator._render_markdown("") == ""

    def test_non_string_input_coerced_to_string(self):
        # Defensive: numeric or None-ish inputs shouldn't crash the
        # template render — a check that stashed an int in the wrong
        # field is a bug, but not a report-breaking one.
        out = ReportGenerator._render_markdown(42)
        assert "42" in out

    def test_parser_is_cached_across_calls(self):
        ReportGenerator._MARKDOWN_PARSER = None
        first = ReportGenerator._get_markdown_parser()
        second = ReportGenerator._get_markdown_parser()
        assert first is second


class TestEvidenceRenderer:
    """
    Evidence dicts stashed on findings get rendered by ``_render_evidence``
    into structured HTML. The old template dumped raw JSON; this filter
    turns the same data into a scalar definition list plus tables for any
    list-of-dicts keys, with ARN abbreviation and hover tooltips.
    """

    def test_scalar_keys_render_as_definition_list(self):
        out = ReportGenerator._render_evidence({"hardcoded_count": 10, "flows_analyzed": 27})
        assert '<dl class="evidence-scalars">' in out
        assert "<dt>Hardcoded count</dt>" in out
        assert "<dd>10</dd>" in out
        assert "<dt>Flows analyzed</dt>" in out
        assert "<dd>27</dd>" in out

    def test_list_of_dicts_renders_as_table(self):
        out = ReportGenerator._render_evidence(
            {
                "hardcoded_details": [
                    {"flow": "IVR", "action_type": "TransferToFlow"},
                    {"flow": "Sales", "action_type": "TransferToFlow"},
                ]
            }
        )
        assert '<table class="evidence-table">' in out
        # Column headers pulled from row keys and humanized.
        assert "<th>Flow</th>" in out
        assert "<th>Action type</th>" in out
        # Cells rendered as <td> not JSON.
        assert "<td>IVR</td>" in out
        assert "<td>Sales</td>" in out

    def test_arn_values_are_abbreviated_with_tooltip(self):
        out = ReportGenerator._render_evidence(
            {
                "hardcoded_details": [
                    {
                        "hardcoded_value": (
                            "arn:aws:connect:us-east-1:819205311151:instance/"
                            "6b050445-2dee-4475-9f78-399ad0a69aac"
                        )
                    }
                ]
            }
        )
        # Full ARN preserved in the tooltip so the reader can hover.
        assert 'title="arn:aws:connect:us-east-1:819205311151' in out
        # But the visible text is a shortened form so the table stays
        # readable.
        assert 'class="evidence-arn"' in out
        assert "instance/" in out
        # And full ARN should NOT appear as visible text between > and <.
        # Simple guard: the visible cell text must be shorter than the
        # full ARN.
        assert "connect:" in out

    def test_none_and_empty_evidence_pass_through(self):
        assert ReportGenerator._render_evidence(None) == ""
        assert ReportGenerator._render_evidence({}) == ""

    def test_bool_scalars_render_as_lowercase(self):
        out = ReportGenerator._render_evidence({"auth_enabled": True, "encrypted": False})
        assert "<dd>true</dd>" in out
        assert "<dd>false</dd>" in out

    def test_null_scalar_renders_as_em_dash(self):
        out = ReportGenerator._render_evidence({"queue": None})
        assert "evidence-null" in out
        assert "\u2014" in out

    def test_nested_dict_renders_as_subsection(self):
        out = ReportGenerator._render_evidence(
            {
                "flows_analyzed": 10,
                "analysis_limits": {"paths_per_flow": 100, "route_states": 20000},
            }
        )
        assert 'class="evidence-section evidence-nested"' in out
        assert "<dt>Paths per flow</dt>" in out
        assert "<dd>100</dd>" in out

    def test_non_dict_evidence_falls_back_to_pretty_json(self):
        # A check may (mistakenly) stash a list at the top level;
        # renderer should not crash, but produce readable JSON.
        out = ReportGenerator._render_evidence([1, 2, 3])
        assert 'class="evidence-json"' in out
        assert "[" in out and "]" in out

    def test_html_in_values_is_escaped(self):
        # If a flow name or attribute name contains angle brackets
        # (unlikely but possible with adversarial content), they must
        # be escaped rather than emitted as live HTML.
        out = ReportGenerator._render_evidence({"note": "<script>alert(1)</script>"})
        assert "<script>alert(1)</script>" not in out
        assert "&lt;script&gt;" in out

    def test_embedded_css_and_javascript(self):
        """Test embedded CSS and JavaScript generation."""
        generator = ReportGenerator()

        css = generator._load_external_css()
        assert len(css) > 0
        assert "report-header" in css
        assert "finding-card" in css

        js = generator._load_external_js()
        assert len(js) > 0
        assert "AssessmentReportController" in js
        assert "applyFilters" in js

    def test_embedded_css_includes_dark_journey_palette(self):
        # Arrange
        generator = ReportGenerator()

        # Act
        css = generator._load_external_css()

        # Assert
        assert "--jm-surface-canvas: #0f172a" in css
        assert (
            "body.dark-mode .journey-map-section .journey-map-diagram,\n"
            "body.dark-mode .journey-map-section .jm-canvas"
        ) in css
        assert "body.dark-mode .journey-map-section .jm-node-speaks" in css
        assert "body.dark-mode .journey-map-section .jm-edge-label.jm-edge-primary" in css
        assert "body.dark-mode .journey-map-section .jm-node:focus-visible" in css

    def test_save_report_with_subdirectory(self, sample_assessment_result):
        """Test saving report with subdirectory creation."""
        generator = ReportGenerator()

        with tempfile.TemporaryDirectory() as temp_dir:
            # Create path with subdirectory
            output_path = os.path.join(temp_dir, "reports", "subdir", "test_report.html")

            generator.generate_html_report(
                assessment_result=sample_assessment_result,
                output_path=output_path,
                include_raw_data=False,
            )

            # Verify file and directories were created
            assert os.path.exists(output_path)
            assert os.path.isdir(os.path.join(temp_dir, "reports", "subdir"))

    def test_error_handling_invalid_output_path(self, sample_assessment_result):
        """Test error handling for invalid output path.

        Uses a mock for os.makedirs to force the failure deterministically —
        relying on a real filesystem path (e.g. "/invalid/...") is not
        portable: a process running as root (as CI containers typically do)
        can create that directory, so the test would pass locally but fail
        in CI (or vice versa).
        """
        generator = ReportGenerator()
        invalid_path = "/invalid/path/that/does/not/exist/report.html"

        with patch("os.makedirs", side_effect=OSError("Permission denied")):
            with pytest.raises(Exception):
                generator.generate_html_report(
                    assessment_result=sample_assessment_result,
                    output_path=invalid_path,
                    include_raw_data=False,
                )


class TestJourneyMapExportReportIntegration:
    @staticmethod
    def _entry(drawio_content: str = "<mxfile><diagram/></mxfile>"):
        return {
            "instance_id": "test-instance-123",
            "instance_display_name": "test-instance",
            "phone_number": "+18005551212",
            "phone_type": "TOLL_FREE",
            "phone_country_code": "US",
            "phone_description": "Main line",
            "flow_id": "flow-ivr",
            "flow_name": "Main IVR",
            "flow_type": "CONTACT_FLOW",
            "diagram_html": '<div class="jm-canvas" style="width:100px;height:100px;"></div>',
            "diagram_model": {"nodes": {}, "edges": {}, "primary_path": []},
            "exports": {
                "schema_version": 1,
                "formats": {
                    "svg": {
                        "content": '<svg xmlns="http://www.w3.org/2000/svg"></svg>',
                        "media_type": "image/svg+xml;charset=utf-8",
                        "width": 100,
                        "height": 100,
                    },
                    "drawio": {
                        "content": drawio_content,
                        "media_type": "application/vnd.jgraph.mxfile;charset=utf-8",
                    },
                },
            },
        }

    def test_journey_map_json_mixed_case_script_end_tag_stays_inside_data_island(
        self, sample_assessment_result
    ):
        # Arrange
        hostile = "</ScRiPt><script>alert(1)</script>"
        sample_assessment_result.journey_map_entries = [self._entry(hostile)]
        generator = ReportGenerator()

        # Act
        serialized = generator._journey_map_entries_json(sample_assessment_result)
        decoded = json.loads(serialized)

        # Assert
        assert "</script" not in serialized.lower()
        assert "<script" not in serialized.lower()
        assert decoded[0]["exports"]["formats"]["drawio"]["content"] == hostile

    def test_journey_map_report_keeps_inspector_reader_focused_and_provenance_hidden(
        self, sample_assessment_result
    ):
        # Arrange
        entry = self._entry()
        entry["diagram_model"] = {
            "nodes": {
                "n0": {
                    "title": "System work · 2 internal actions",
                    "category": "processing",
                    "summary": "Groups internal actions.",
                    "scope": [
                        "Looks up customer data with customer-lookup",
                        "Sets contact attributes",
                    ],
                    "ai": {
                        "technology": "Amazon Lex",
                        "identity": "CustomerServiceBot",
                        "subtype": "V2 bot",
                        "alias": "Production",
                    },
                    "is_group": True,
                    "is_entry": True,
                    "is_primary": True,
                    "actions": [
                        {"id": "lookup", "type": "InvokeLambdaFunction", "detail": "Looks up data"},
                        {
                            "id": "attributes",
                            "type": "SetContactAttributes",
                            "detail": "Sets attributes",
                        },
                    ],
                    "absorbed_outcomes": [
                        {
                            "label": "Catch-all error route",
                            "raw_label": "NoMatchingError",
                            "route_type": "exception",
                            "transition_type": "error",
                            "meaning": (
                                "A configured catch-all route used only if the action fails and "
                                "no specific error condition matches. This does not mean an error "
                                "was observed."
                            ),
                            "source_action_id": "lookup",
                            "source_action_type": "InvokeLambdaFunction",
                            "source_action_label": "Looks up data",
                            "target_action_id": "attributes",
                            "target_action_type": "SetContactAttributes",
                            "target_action_label": "Sets attributes",
                        }
                    ],
                }
            },
            "edges": {},
            "primary_path": ["n0"],
        }
        sample_assessment_result.journey_map_entries = [entry]
        generator = ReportGenerator()

        # Act
        serialized = generator._journey_map_entries_json(sample_assessment_result)
        decoded_route = json.loads(serialized)[0]["diagram_model"]["nodes"]["n0"][
            "absorbed_outcomes"
        ][0]
        html_content = generator.generate_html_report(sample_assessment_result)

        # Assert
        assert decoded_route["source_action_id"] == "lookup"
        assert decoded_route["source_action_label"] == "Looks up data"
        assert decoded_route["target_action_id"] == "attributes"
        assert decoded_route["target_action_label"] == "Sets attributes"
        assert "Selected step or route" in html_content
        assert "What this setup does" in html_content
        assert "What this block does" in html_content
        assert "journey-map-inspector-scope-heading" in html_content
        assert "AI agent" in html_content
        assert "Array.isArray(detail.scope)" in html_content
        assert "detail.ai" in html_content
        assert "detail.is_group" in html_content
        assert "detail.actions" not in html_content
        assert "This route ' + movement + ' from '" in html_content
        assert "inspectorSummary.hidden = !summary" in html_content
        assert "journey-map-inspector-details" not in html_content
        assert "Journey role" not in html_content
        assert "Step type" not in html_content
        assert "Underlying Connect action(s)" not in html_content
        assert "Route type" not in html_content
        assert "Underlying outcome(s)" not in html_content
        assert "Connect value:" not in html_content
        assert "Configured internal error routes (" not in html_content
        assert "These are configured flow rules, not observed incidents." not in html_content
        assert "Handled inside this group" not in html_content
        assert "Technical error (Connect value:" not in html_content

    def test_journey_map_report_with_exports_renders_download_controls(
        self, sample_assessment_result
    ):
        # Arrange
        sample_assessment_result.journey_map_entries = [self._entry()]
        generator = ReportGenerator()

        # Act
        html_content = generator.generate_html_report(sample_assessment_result)

        # Assert
        assert 'id="journey-map-download-svg"' in html_content
        assert 'id="journey-map-download-png"' in html_content
        assert 'id="journey-map-download-drawio"' in html_content
        assert 'id="journey-map-export-status"' in html_content
        assert "safeFilenamePart" in html_content
        assert "downloadPngExport" in html_content

    def test_journey_map_report_export_payload_is_data_not_live_markup(
        self, sample_assessment_result
    ):
        # Arrange
        sample_assessment_result.journey_map_entries = [self._entry()]
        generator = ReportGenerator()

        # Act
        html_content = generator.generate_html_report(sample_assessment_result)
        island_start = html_content.index('<script id="journey-map-data"')
        island_end = html_content.index("</script>", island_start)
        island = html_content[island_start:island_end]

        # Assert
        assert "<mxfile" not in island
        assert "<svg xmlns" not in island
        assert "\\u003cmxfile" in island
        assert "\\u003csvg" in island
