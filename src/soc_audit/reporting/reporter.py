"""Reporting utilities for rendering module results."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Mapping

from soc_audit.core.engine import EngineResult


class ReportRenderer:
    """Build text and JSON reports from module outputs."""

    def render_text(self, result: EngineResult) -> str:
        lines = ["SOC Audit Report", "=" * 60]
        for module_result in result.module_results:
            findings = list(module_result.findings)
            lines.append(f"\nModule: {module_result.module_name}")
            lines.append(f"Findings: {len(findings)}")
            for finding in findings:
                lines.append(f"- {finding.title} ({finding.severity})")
                lines.append(f"  {finding.description}")
                if finding.recommendation:
                    lines.append(f"  Recommendation: {finding.recommendation}")
        return "\n".join(lines)

    def render_json(self, result: EngineResult) -> Mapping[str, Any]:
        return {
            "modules": [
                {
                    "module_name": module_result.module_name,
                    "started_at": module_result.started_at.isoformat(),
                    "completed_at": module_result.completed_at.isoformat(),
                    "findings": [asdict(finding) for finding in module_result.findings],
                    "metadata": dict(module_result.metadata),
                }
                for module_result in result.module_results
            ]
        }
