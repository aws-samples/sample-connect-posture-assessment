"""
Check catalog documentation generator (Task 16 / Requirement 36).

Generates ``docs/check-catalog.md`` from the populated CheckRegistry,
producing a summary table and per-check detail entries organized by pillar.
"""

from typing import List

from .checks.base import BaseCheck
from .checks.registry import CheckRegistry
from .models import Pillar


class DocsGenerator:
    """Generates check catalog documentation from registry."""

    def generate_catalog(self, registry: CheckRegistry, output_path: str) -> None:
        """
        Generate check-catalog.md from all registered checks.

        Args:
            registry: A populated CheckRegistry.
            output_path: File path to write the catalog markdown.
        """
        checks = registry.get_all_checks()
        checks_by_pillar = self._group_by_pillar(checks)

        lines = [
            "# Amazon Connect Assessment — Check Catalog",
            "",
            "This document catalogs every check the assessment tool performs, "
            "organized by AWS Well-Architected pillar. For each check, it lists "
            "what is evaluated, why it matters for Amazon Connect, and prescriptive "
            "remediation guidance.",
            "",
            "## Summary Table",
            "",
            self._generate_summary_table(checks),
            "",
        ]

        for pillar in Pillar:
            pillar_checks = checks_by_pillar.get(pillar, [])
            if not pillar_checks:
                continue
            lines.append(f"## {pillar.value.replace('_', ' ').title()}")
            lines.append("")
            for check in sorted(pillar_checks, key=lambda c: c.check_id):
                lines.append(self._format_check_entry(check))
            lines.append("")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(lines))

    def _group_by_pillar(self, checks: List[BaseCheck]):
        grouped = {}
        for check in checks:
            grouped.setdefault(check.pillar, []).append(check)
        return grouped

    def _generate_summary_table(self, checks: List[BaseCheck]) -> str:
        rows = [
            "| Check ID | Pillar | Severity | Description |",
            "|----------|--------|----------|-------------|",
        ]
        for check in sorted(checks, key=lambda c: (c.pillar.value, c.check_id)):
            desc = (check.description or "")[:80]
            rows.append(
                f"| `{check.check_id}` | "
                f"{check.pillar.value.replace('_', ' ').title()} | "
                f"{check.severity.value.title()} | "
                f"{desc} |"
            )
        return "\n".join(rows)

    def _format_check_entry(self, check: BaseCheck) -> str:
        lines = [
            f"### `{check.check_id}` — {check.name}",
            "",
            f"**Severity:** {check.severity.value.title()}",
            "",
            f"**What it checks:** {check.description}",
            "",
            f"**Remediation:** {check.remediation_template or 'See structured remediation in findings.'}",  # noqa: E501
            "",
        ]
        return "\n".join(lines)
