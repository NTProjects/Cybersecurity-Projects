"""Reporting utilities for rendering module results."""
from __future__ import annotations

from dataclasses import asdict
from typing import Any, Iterable, Mapping

from soc_audit.core.engine import EngineResult
from soc_audit.core.interfaces import Finding
from soc_audit.core.risk import aggregate_risk_scores, get_severity_mapping_from_config


class ReportRenderer:
    """Build text and JSON reports from module outputs."""

    def __init__(self, config: Mapping[str, Any] | None = None):
        """Initialize report renderer with optional configuration."""
        self.config = config

    def render_text(self, result: EngineResult) -> str:
        lines = ["SOC Audit Report", "=" * 60]

        # Collect all findings for aggregate risk calculation
        all_findings: list[Finding] = []
        for module_result in result.module_results:
            all_findings.extend(module_result.findings)

        # Calculate aggregate risk if findings exist
        if all_findings:
            severity_mapping = get_severity_mapping_from_config(self.config)
            aggregate = aggregate_risk_scores(all_findings, severity_mapping)
            risk_level = self._calculate_overall_risk_level(aggregate["average_risk_score"])
            lines.append(f"\nOverall Risk Level: {risk_level}")
            lines.append(f"Aggregate Risk Score: {aggregate['average_risk_score']:.1f}/100")
            lines.append(f"Total Findings: {aggregate['total_findings']}")
            lines.append(f"Highest Risk Score: {aggregate['max_risk_score']}/100")

        # Render module results
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

    @staticmethod
    def _calculate_overall_risk_level(average_score: float) -> str:
        """Calculate overall risk level from average risk score."""
        if average_score < 25:
            return "LOW"
        elif average_score < 75:
            return "MEDIUM"
        elif average_score < 90:
            return "HIGH"
        else:
            return "CRITICAL"

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
