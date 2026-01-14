"""Risk-Based Alert (RBA) scoring for security findings.

This module provides functionality to compute risk-based alert scores
that combine severity, base risk scores, MITRE ATT&CK context, and other factors.
"""
from __future__ import annotations

from typing import Any


def compute_rba_score(
    severity: str,
    base_risk_score: float | int | None = None,
    mitre_ids: list[str] | None = None,
    context: dict[str, Any] | None = None,
    severity_weights: dict[str, int] | None = None,
) -> tuple[int, dict[str, Any]]:
    """
    Compute a Risk-Based Alert (RBA) score for a finding.

    Scoring rules:
    - Start with severity weight from config (default mapping)
    - +10 if any MITRE ID present, +5 per additional technique (cap +25)
    - + (base_risk_score * 10) if provided (cap +30)
    - Clamp final score to 0..100

    Args:
        severity: Severity level (critical, high, medium, low, info)
        base_risk_score: Optional base risk score (0-100 range expected)
        mitre_ids: Optional list of MITRE ATT&CK technique IDs
        context: Optional additional context dictionary (reserved for future use)
        severity_weights: Optional custom severity weight mapping.
            Default: {"critical": 100, "high": 70, "medium": 40, "low": 15, "info": 5}

    Returns:
        Tuple of (rba_score: int, breakdown: dict)
        breakdown contains:
        - base_severity: int (severity weight)
        - mitre_bonus: int (MITRE bonus points)
        - risk_bonus: int (base risk score bonus)
        - final_score: int (clamped 0-100)
    """
    # Default severity weights
    default_weights = {
        "critical": 100,
        "high": 70,
        "medium": 40,
        "low": 15,
        "info": 5,
    }
    weights = severity_weights or default_weights

    breakdown: dict[str, Any] = {}

    # Base score from severity
    base_severity = weights.get(severity.lower(), 0)
    breakdown["base_severity"] = base_severity
    score = base_severity

    # MITRE bonus: +10 if any MITRE ID, +5 per additional (cap +25)
    mitre_bonus = 0
    if mitre_ids:
        count = len(mitre_ids)
        if count >= 1:
            mitre_bonus = 10
        if count >= 2:
            mitre_bonus = min(10 + (count - 1) * 5, 25)
    breakdown["mitre_bonus"] = mitre_bonus
    score += mitre_bonus

    # Risk score bonus: + (base_risk_score * 10), cap +30
    risk_bonus = 0
    if base_risk_score is not None:
        # Normalize risk_score to 0-100 range, then scale by 0.3 (max +30)
        normalized_risk = min(max(base_risk_score, 0), 100)
        risk_bonus = min(int(normalized_risk * 0.3), 30)
    breakdown["risk_bonus"] = risk_bonus
    score += risk_bonus

    # Clamp to 0-100
    final_score = max(0, min(100, int(score)))
    breakdown["final_score"] = final_score

    return (final_score, breakdown)
