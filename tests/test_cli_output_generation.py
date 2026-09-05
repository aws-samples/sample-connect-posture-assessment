from types import SimpleNamespace
from unittest.mock import Mock, patch

from amazon_connect_assessment.cli import run_assessment


class _FakeEngine:
    def __init__(self, result):
        self.result = result

    def run_assessment(self):
        return self.result


def _sample_result():
    return SimpleNamespace(
        assessment_id="assessment-123",
        account_id="123456789012",
        region="us-east-1",
        summary=SimpleNamespace(
            total_checks=0,
            passed_checks=0,
            failed_checks=0,
            critical_findings=0,
            high_findings=0,
        ),
    )


def test_run_assessment_passes_filename_template_to_report_generators(tmp_path):
    result = _sample_result()
    filename_template = "assessment_{account_id}_{region}"
    report_generator = Mock()
    report_generator._generate_filename.return_value = "assessment_123456789012_us-east-1.html"
    report_generator.generate_json_report.return_value = str(tmp_path / "reports" / "report.json")
    report_generator.generate_csv_report.return_value = str(tmp_path / "reports" / "report.csv")

    config = {
        "output": {
            "format": ["html", "json", "csv"],
            "directory": str(tmp_path / "custom-reports"),
            "filename_template": filename_template,
        },
        "cli": {},
    }

    with patch("amazon_connect_assessment.cli.ReportGenerator", return_value=report_generator):
        assert run_assessment(_FakeEngine(result), config) is True

    report_generator.generate_html_report.assert_called_once_with(
        result,
        str(tmp_path / "custom-reports" / "assessment_123456789012_us-east-1.html"),
    )
    report_generator.generate_json_report.assert_called_once_with(
        result,
        str(tmp_path / "custom-reports"),
        filename_template=filename_template,
    )
    report_generator.generate_csv_report.assert_called_once_with(
        result,
        str(tmp_path / "custom-reports"),
        filename_template=filename_template,
    )
    assert (tmp_path / "custom-reports").is_dir()
