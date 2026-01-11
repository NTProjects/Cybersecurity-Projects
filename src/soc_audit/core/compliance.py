"""Compliance engine for evaluating findings against compliance rules."""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from soc_audit.core.interfaces import Finding


def _load_yaml(raw_text: str) -> dict[str, Any]:
    """Load YAML content into a dictionary."""
    try:
        import yaml  # type: ignore
    except ImportError as exc:
        raise RuntimeError("YAML support requires PyYAML.") from exc
    return yaml.safe_load(raw_text) or {}


@dataclass
class ComplianceRule:
    """Represents a single compliance rule that can evaluate findings."""

    control_id: str
    title: str
    description: str
    severity: str | None = None

    def evaluate(self, findings: list[Finding]) -> str:
        """
        Evaluate findings against this compliance rule.

        The rule evaluates findings that are associated with this control_id.
        If any findings with this control_id exist, the rule fails.
        If no findings with this control_id exist, the rule passes.

        Args:
            findings: List of Finding objects to evaluate.

        Returns:
            One of: "Pass", "Fail", or "Not Applicable"
        """
        # Find all findings that reference this control_id
        matching_findings = [
            finding
            for finding in findings
            if finding.control_ids and self.control_id in finding.control_ids
        ]

        if not matching_findings:
            return "Pass"

        # If there are matching findings, the rule fails
        return "Fail"


class ComplianceEngine:
    """Engine for evaluating findings against compliance rules loaded from YAML."""

    def __init__(self, rules: list[ComplianceRule] | None = None):
        """
        Initialize the compliance engine with optional rules.

        Args:
            rules: Optional list of ComplianceRule objects to initialize with.
        """
        self._rules: list[ComplianceRule] = rules or []

    def load_from_file(self, file_path: str | Path) -> None:
        """
        Load compliance rules from a YAML file.

        Expected YAML format:
        ```yaml
        rules:
          - control_id: "CIS-1.1"
            title: "Ensure security updates are installed"
            description: "Security updates should be installed promptly"
            severity: "high"
          - control_id: "NIST-AC-3"
            title: "Access control enforcement"
            description: "Access control policies must be enforced"
        ```

        Args:
            file_path: Path to the YAML file containing compliance rules.

        Raises:
            FileNotFoundError: If the file does not exist.
            ValueError: If the YAML structure is invalid or missing required fields.
            RuntimeError: If PyYAML is not installed or YAML parsing fails.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Compliance rule file not found: {path}")

        try:
            raw_text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise RuntimeError(f"Failed to read compliance rule file: {path}") from exc

        try:
            yaml_data = _load_yaml(raw_text)
        except Exception as exc:
            raise RuntimeError(f"Failed to parse YAML file: {path}") from exc

        rules_data = yaml_data.get("rules", [])
        if not isinstance(rules_data, list):
            raise ValueError(f"Invalid YAML structure: 'rules' must be a list in {path}")

        self._rules = []
        for idx, rule_data in enumerate(rules_data):
            if not isinstance(rule_data, dict):
                raise ValueError(
                    f"Invalid rule at index {idx}: rule must be a dictionary in {path}"
                )

            control_id = rule_data.get("control_id")
            if not control_id:
                raise ValueError(
                    f"Invalid rule at index {idx}: 'control_id' is required in {path}"
                )

            title = rule_data.get("title")
            if not title:
                raise ValueError(
                    f"Invalid rule at index {idx}: 'title' is required in {path}"
                )

            description = rule_data.get("description", "")
            severity = rule_data.get("severity")

            rule = ComplianceRule(
                control_id=str(control_id),
                title=str(title),
                description=str(description),
                severity=severity,
            )
            self._rules.append(rule)

    def evaluate(self, findings: list[Finding]) -> dict[str, str]:
        """
        Evaluate findings against all loaded compliance rules.

        Args:
            findings: List of Finding objects to evaluate.

        Returns:
            Dictionary mapping control_id to compliance_status ("Pass", "Fail", or "Not Applicable").
        """
        results: dict[str, str] = {}
        for rule in self._rules:
            status = rule.evaluate(findings)
            results[rule.control_id] = status
        return results

    def get_rules(self) -> list[ComplianceRule]:
        """
        Get all loaded compliance rules.

        Returns:
            List of ComplianceRule objects.
        """
        return list(self._rules)
