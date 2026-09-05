"""
Findings diff — compare two assessment runs and show what changed.

Identifies resolved findings (present in baseline, absent now), new findings
(absent in baseline, present now), and persistent findings (present in both).
"""

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Dict, List


@dataclass
class DiffResult:
    resolved: List[Dict[str, Any]]
    new: List[Dict[str, Any]]
    persistent: List[Dict[str, Any]]
    baseline_total: int
    current_total: int

    @property
    def summary(self) -> str:
        lines = [
            f"Baseline: {self.baseline_total} findings | Current: {self.current_total} findings",
            f"  Resolved: {len(self.resolved)}",
            f"  New:      {len(self.new)}",
            f"  Persistent: {len(self.persistent)}",
        ]
        return "\n".join(lines)


def _finding_key(finding: Dict[str, Any]) -> str:
    """Unique key for matching findings across runs."""
    return f"{finding.get('check_id', '')}::{finding.get('resource_id', '')}"


def load_findings_from_json(filepath: str) -> List[Dict[str, Any]]:
    """Load findings from a previously generated JSON report."""
    with open(filepath) as f:
        data = json.load(f)

    if "findings" in data:
        return data["findings"]
    # Flat list format
    if isinstance(data, list):
        return data
    return []


def compute_diff(
    baseline_findings: List[Dict[str, Any]],
    current_findings: List[Dict[str, Any]],
) -> DiffResult:
    """Compare baseline vs current findings and categorize changes."""

    # Only count FAIL findings for comparison
    def failure_groups(findings: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
        groups = defaultdict(list)
        for finding in findings:
            if finding.get("status") in ("fail", "FAIL"):
                groups[_finding_key(finding)].append(finding)
        return groups

    baseline_groups = failure_groups(baseline_findings)
    current_groups = failure_groups(current_findings)
    resolved: List[Dict[str, Any]] = []
    new: List[Dict[str, Any]] = []
    persistent: List[Dict[str, Any]] = []

    # Treat duplicate records as a multiset. This preserves repeated findings
    # while still matching records by their stable check/resource identity.
    for key in sorted(set(baseline_groups) | set(current_groups)):
        baseline_records = baseline_groups.get(key, [])
        current_records = current_groups.get(key, [])
        shared_count = min(len(baseline_records), len(current_records))
        persistent.extend(current_records[:shared_count])
        resolved.extend(baseline_records[shared_count:])
        new.extend(current_records[shared_count:])

    return DiffResult(
        resolved=resolved,
        new=new,
        persistent=persistent,
        baseline_total=sum(len(records) for records in baseline_groups.values()),
        current_total=sum(len(records) for records in current_groups.values()),
    )


def diff_from_files(baseline_path: str, current_path: str) -> DiffResult:
    """Load two JSON reports and compute their diff."""
    baseline = load_findings_from_json(baseline_path)
    current = load_findings_from_json(current_path)
    return compute_diff(baseline, current)


def print_diff(diff: DiffResult) -> None:
    """Print a human-readable diff summary to stdout."""
    print("\n=== Assessment Findings Diff ===")
    print(diff.summary)

    if diff.resolved:
        print(f"\n--- Resolved ({len(diff.resolved)}) ---")
        for f in diff.resolved[:20]:
            print(f"  [RESOLVED] {f.get('check_id')}: {f.get('resource_id')}")
        if len(diff.resolved) > 20:
            print(f"  ... and {len(diff.resolved) - 20} more")

    if diff.new:
        print(f"\n--- New ({len(diff.new)}) ---")
        for f in diff.new[:20]:
            sev = f.get("severity", "?").upper()
            print(f"  [NEW {sev}] {f.get('check_id')}: {f.get('resource_id')}")
        if len(diff.new) > 20:
            print(f"  ... and {len(diff.new) - 20} more")

    if not diff.resolved and not diff.new:
        print("\n  No changes between runs.")
