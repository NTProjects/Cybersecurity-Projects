"""Risk calculation utilities for security findings."""
from __future__ import annotations

from typing import Iterable

from soc_audit.core.interfaces import Finding


# Default severity-to-risk-score mapping
# Lower scores indicate lower risk, higher scores indicate higher risk
# Scale: 0-100 (common convention for risk scores)
SEVERITY_TO_RISK_SCORE: dict[str, int] = {
    "info": 10,
    "low": 25,
    "medium": 50,
    "high": 75,
    "critical": 95,
}


def calculate_risk_score(finding: Finding, severity_mapping: dict[str, int] | None = None) -> int:
    """
    Calculate a risk score for a Finding.

    If the finding already has a risk_score set, returns that value.
    Otherwise, maps the finding's severity string to a risk score using the provided mapping
    or the default severity-to-risk mapping.

    Args:
        finding: The Finding to calculate a risk score for.
        severity_mapping: Optional custom severity-to-risk-score mapping.
                         If None, uses the default SEVERITY_TO_RISK_SCORE mapping.
                         Keys should be severity strings (case-insensitive), values are risk scores.

    Returns:
        The risk score as an integer (0-100 scale by default).
        Returns 0 if severity cannot be mapped and no risk_score is set.
    """
    # If finding already has a risk score, use it
    if finding.risk_score is not None:
        return finding.risk_score

    # Use provided mapping or default
    mapping = severity_mapping if severity_mapping is not None else SEVERITY_TO_RISK_SCORE

    # Map severity string (case-insensitive) to risk score
    severity_lower = finding.severity.lower()
    return mapping.get(severity_lower, 0)


def aggregate_risk_scores(findings: Iterable[Finding], severity_mapping: dict[str, int] | None = None) -> dict[str, int | float]:
    """
    Aggregate risk scores across multiple findings.

    Calculates several aggregate statistics:
    - total_findings: Total number of findings
    - total_risk_score: Sum of all risk scores
    - average_risk_score: Mean risk score
    - max_risk_score: Highest risk score
    - min_risk_score: Lowest risk score

    Args:
        findings: Iterable of Finding objects to aggregate.
        severity_mapping: Optional custom severity-to-risk-score mapping.
                         If None, uses the default SEVERITY_TO_RISK_SCORE mapping.

    Returns:
        Dictionary containing aggregate statistics with keys:
        - total_findings: int
        - total_risk_score: int
        - average_risk_score: float
        - max_risk_score: int
        - min_risk_score: int
    """
    findings_list = list(findings)
    if not findings_list:
        return {
            "total_findings": 0,
            "total_risk_score": 0,
            "average_risk_score": 0.0,
            "max_risk_score": 0,
            "min_risk_score": 0,
        }

    risk_scores = [calculate_risk_score(finding, severity_mapping) for finding in findings_list]
    total_risk_score = sum(risk_scores)
    total_findings = len(findings_list)

    return {
        "total_findings": total_findings,
        "total_risk_score": total_risk_score,
        "average_risk_score": total_risk_score / total_findings if total_findings > 0 else 0.0,
        "max_risk_score": max(risk_scores),
        "min_risk_score": min(risk_scores),
    }
