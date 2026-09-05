"""Regression tests for assessment finding diff behavior."""

from amazon_connect_assessment.report.findings_diff import compute_diff


def _finding(check_id: str, resource_id: str, suffix: str) -> dict:
    return {
        "check_id": check_id,
        "resource_id": resource_id,
        "status": "FAIL",
        "evidence": suffix,
    }


def test_duplicate_findings_are_counted_and_preserved():
    baseline = [
        _finding("check-a", "resource-1", "baseline-1"),
        _finding("check-a", "resource-1", "baseline-2"),
    ]
    current = [
        _finding("check-a", "resource-1", "current-1"),
        _finding("check-a", "resource-1", "current-2"),
        _finding("check-b", "resource-2", "new"),
    ]

    diff = compute_diff(baseline, current)

    assert diff.baseline_total == 2
    assert diff.current_total == 3
    assert len(diff.persistent) == 2
    assert len(diff.resolved) == 0
    assert len(diff.new) == 1
    assert diff.new[0]["check_id"] == "check-b"


def test_duplicate_count_decrease_marks_excess_records_resolved():
    baseline = [
        _finding("check-a", "resource-1", "baseline-1"),
        _finding("check-a", "resource-1", "baseline-2"),
    ]
    current = [_finding("check-a", "resource-1", "current-1")]

    diff = compute_diff(baseline, current)

    assert diff.baseline_total == 2
    assert diff.current_total == 1
    assert len(diff.persistent) == 1
    assert len(diff.resolved) == 1
    assert diff.resolved[0]["evidence"] == "baseline-2"
