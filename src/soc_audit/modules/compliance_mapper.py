"""Compliance mapping module that enriches findings with compliance control IDs and status."""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Mapping

from soc_audit.core.compliance import ComplianceEngine
from soc_audit.core.interfaces import BaseModule, Finding, ModuleContext, ModuleResult


class ComplianceMapper(BaseModule):
    """
    Module that maps findings to compliance controls and evaluates compliance status.

    This module enriches findings with:
    - control_ids: List of compliance control IDs (e.g., "CIS-1.1", "NIST-AC-3")
    - compliance_status: "Pass", "Fail", or "Not Applicable"

    The module accepts findings from previous modules and uses ComplianceEngine
    to evaluate them against compliance rules loaded from a YAML file.
    """

    name = "compliance_mapper"
    description = "Map findings to compliance controls and evaluate compliance status."
    module_type = "compliance"

    @classmethod
    def default_config(cls) -> Mapping[str, object]:
        return {
            "rule_file": None,  # Path to compliance rules YAML file
            "findings": [],  # List of findings to map (when passed via config)
        }

    def run(self, context: ModuleContext) -> ModuleResult:
        """
        Execute the compliance mapping module.

        Args:
            context: Module context containing configuration.

        Returns:
            ModuleResult with enriched findings containing control_ids and compliance_status.
        """
        started_at = datetime.utcnow()
        findings: list[Finding] = []

        # Load findings from config (when passed from previous modules via engine)
        input_findings = self._load_findings_from_config()

        # If no findings provided, return empty result
        if not input_findings:
            completed_at = datetime.utcnow()
            return ModuleResult(
                module_name=self.name,
                started_at=started_at,
                completed_at=completed_at,
                findings=findings,
                metadata={"findings_processed": 0, "rules_loaded": False},
            )

        # Load compliance engine and rules
        compliance_engine = self._load_compliance_engine()

        # Map findings to compliance controls
        findings = self._map_findings_to_controls(input_findings, compliance_engine)

        completed_at = datetime.utcnow()
        return ModuleResult(
            module_name=self.name,
            started_at=started_at,
            completed_at=completed_at,
            findings=findings,
            metadata={
                "findings_processed": len(findings),
                "rules_loaded": len(compliance_engine.get_rules()) > 0,
            },
        )

    def _load_findings_from_config(self) -> list[Finding]:
        """
        Load findings from module configuration.

        Findings can be passed as a list of finding dictionaries or Finding objects.
        This is a placeholder for when the engine is updated to pass findings directly.

        Returns:
            List of Finding objects to process.
        """
        findings_data = self.config.get("findings", [])
        if not isinstance(findings_data, list):
            return []

        findings: list[Finding] = []
        for finding_data in findings_data:
            if isinstance(finding_data, Finding):
                findings.append(finding_data)
            elif isinstance(finding_data, dict):
                # Convert dict to Finding (for when findings are passed via config)
                finding = Finding(
                    title=str(finding_data.get("title", "")),
                    description=str(finding_data.get("description", "")),
                    severity=str(finding_data.get("severity", "medium")),
                    evidence=finding_data.get("evidence", {}),
                    recommendation=finding_data.get("recommendation"),
                    risk_score=finding_data.get("risk_score"),
                    control_ids=finding_data.get("control_ids"),
                    compliance_status=finding_data.get("compliance_status"),
                )
                findings.append(finding)

        return findings

    def _load_compliance_engine(self) -> ComplianceEngine:
        """
        Load compliance engine with rules from configuration.

        Returns:
            ComplianceEngine instance with rules loaded (or empty if no rule file specified).
        """
        engine = ComplianceEngine()
        rule_file = self.config.get("rule_file")
        if rule_file:
            try:
                engine.load_from_file(rule_file)
            except (FileNotFoundError, ValueError, RuntimeError) as exc:
                # Gracefully handle errors - log but don't fail
                # In production, this might be logged
                pass
        return engine

    def _map_findings_to_controls(
        self, findings: list[Finding], compliance_engine: ComplianceEngine
    ) -> list[Finding]:
        """
        Map findings to compliance controls and evaluate compliance status.

        For each finding:
        - If control_ids already exist, preserve them
        - Otherwise, evaluate against compliance rules to determine control_ids
        - Set compliance_status based on evaluation

        Args:
            findings: List of Finding objects to map.
            compliance_engine: ComplianceEngine instance with loaded rules.

        Returns:
            List of new Finding objects with control_ids and compliance_status populated.
        """
        if not findings:
            return []

        # Get all compliance rules
        rules = compliance_engine.get_rules()
        if not rules:
            # No rules loaded - return findings as-is (no mapping possible)
            return [
                Finding(
                    title=finding.title,
                    description=finding.description,
                    severity=finding.severity,
                    evidence=finding.evidence,
                    recommendation=finding.recommendation,
                    risk_score=finding.risk_score,
                    control_ids=finding.control_ids,
                    compliance_status=finding.compliance_status,
                )
                for finding in findings
            ]

        # Evaluate all findings against compliance rules
        compliance_results = compliance_engine.evaluate(findings)

        # Create new findings with compliance mapping
        enriched_findings: list[Finding] = []
        for finding in findings:
            # Preserve existing control_ids if present
            control_ids = finding.control_ids or []

            # If no control_ids, try to find matching rules based on finding characteristics
            if not control_ids:
                # Simple matching: find rules that might apply to this finding
                # This is a basic implementation - can be enhanced with more sophisticated matching
                for rule in rules:
                    # Match based on severity if rule has severity
                    if rule.severity and rule.severity.lower() == finding.severity.lower():
                        if rule.control_id not in control_ids:
                            control_ids.append(rule.control_id)

            # Determine compliance status
            compliance_status: str | None = None
            if control_ids:
                # Check if any of the control_ids have compliance results
                for control_id in control_ids:
                    if control_id in compliance_results:
                        status = compliance_results[control_id]
                        # Use the first non-Pass status, or Pass if all are Pass
                        if compliance_status is None or status != "Pass":
                            compliance_status = status
                        break
                # If no status found, default based on whether finding exists
                if compliance_status is None:
                    compliance_status = "Fail"  # Finding exists, so control fails
            else:
                # No control_ids mapped - status is Not Applicable
                compliance_status = "Not Applicable"

            # Create new finding with compliance information
            enriched_finding = Finding(
                title=finding.title,
                description=finding.description,
                severity=finding.severity,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
                risk_score=finding.risk_score,
                control_ids=control_ids if control_ids else None,
                compliance_status=compliance_status,
            )
            enriched_findings.append(enriched_finding)

        return enriched_findings
