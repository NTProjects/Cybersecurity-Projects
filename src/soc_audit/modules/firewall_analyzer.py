"""Firewall analyzer module for detecting overly permissive iptables rules."""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Mapping

from soc_audit.core.interfaces import BaseModule, Finding, ModuleContext, ModuleResult


class FirewallAnalyzer(BaseModule):
    """
    Module that analyzes iptables firewall rules for security issues.

    This module parses iptables-save format rules and detects overly permissive
    rules that may pose security risks, such as rules allowing traffic from
    any source (0.0.0.0/0 or ::/0).
    """

    name = "firewall_analyzer"
    description = "Analyze iptables firewall rules for overly permissive configurations."
    module_type = "policy"

    @classmethod
    def default_config(cls) -> Mapping[str, object]:
        return {
            "iptables_rules_file": None,  # Path to iptables-save output file
        }

    def run(self, context: ModuleContext) -> ModuleResult:
        """
        Execute the firewall analyzer module.

        Args:
            context: Module context containing configuration.

        Returns:
            ModuleResult with findings for overly permissive firewall rules.

        Raises:
            FileNotFoundError: If the rules file is not found.
            RuntimeError: If the rules file cannot be read.
        """
        started_at = datetime.utcnow()
        findings: list[Finding] = []

        rules_file = self.config.get("iptables_rules_file")
        if not rules_file:
            # No rules file specified - return empty result
            completed_at = datetime.utcnow()
            return ModuleResult(
                module_name=self.name,
                started_at=started_at,
                completed_at=completed_at,
                findings=findings,
                metadata={},
            )

        # Parse rules from file
        try:
            rules = self._load_rules_from_file(rules_file)
            findings = self._analyze_rules(rules)
        except FileNotFoundError:
            raise FileNotFoundError(f"iptables rules file not found: {rules_file}")
        except (OSError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"Failed to read iptables rules file: {rules_file}") from exc

        completed_at = datetime.utcnow()
        return ModuleResult(
            module_name=self.name,
            started_at=started_at,
            completed_at=completed_at,
            findings=findings,
            metadata={},
        )

    def _load_rules_from_file(self, file_path: str | Path) -> list[str]:
        """
        Load iptables rules from a file.

        Args:
            file_path: Path to the iptables-save output file.

        Returns:
            List of rule lines (excluding comments and empty lines).

        Raises:
            FileNotFoundError: If the file does not exist.
            OSError: If the file cannot be read.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"iptables rules file not found: {path}")

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise OSError(f"Failed to read file: {path}") from exc

        # Filter out comments, empty lines, and table/chain declarations
        lines = []
        for line in content.splitlines():
            stripped = line.strip()
            # Skip comments, empty lines, table declarations (*), chain declarations (:), and COMMIT
            if stripped and not stripped.startswith("#") and not stripped.startswith("*") and not stripped.startswith(":") and stripped != "COMMIT":
                lines.append(stripped)

        return lines

    def _analyze_rules(self, rules: list[str]) -> list[Finding]:
        """
        Analyze firewall rules for overly permissive configurations.

        Args:
            rules: List of iptables rule strings.

        Returns:
            List of Finding objects for insecure rules.
        """
        findings: list[Finding] = []

        for rule in rules:
            if self._is_overly_permissive(rule):
                findings.append(self._create_finding(rule))

        return findings

    @staticmethod
    def _is_overly_permissive(rule: str) -> bool:
        """
        Check if a firewall rule is overly permissive.

        A rule is considered overly permissive if:
        - It's an ACCEPT rule
        - It has source 0.0.0.0/0 or ::/0 (any IPv4 or IPv6 source)
        - It has no source restriction (defaults to any source)

        Args:
            rule: iptables rule string (e.g., "-A INPUT -s 0.0.0.0/0 -j ACCEPT").

        Returns:
            True if the rule is overly permissive, False otherwise.
        """
        # Must be an ACCEPT rule
        if "-j ACCEPT" not in rule:
            return False

        # Check for explicit source 0.0.0.0/0 (IPv4 any) or ::/0 (IPv6 any)
        # iptables uses -s for source address
        if " -s 0.0.0.0/0" in rule or " -s ::/0" in rule:
            return True

        # Check if source is not specified at all (defaults to any source)
        # Skip OUTPUT chain rules as source restrictions are less relevant there
        if "-A OUTPUT" not in rule and " -s " not in rule:
            return True

        return False

    @staticmethod
    def _create_finding(rule: str) -> Finding:
        """
        Create a Finding for an overly permissive firewall rule.

        Args:
            rule: The iptables rule string.

        Returns:
            Finding object describing the security issue.
        """
        return Finding(
            title="Overly permissive firewall rule detected",
            description=(
                "An iptables firewall rule allows traffic from any source (0.0.0.0/0 or ::/0) "
                "or has no source restriction. This configuration may allow unauthorized access "
                "from any network location."
            ),
            severity="high",
            evidence={"rule": rule},
            recommendation=(
                "Restrict the source IP address or CIDR range to specific trusted networks. "
                "Only allow traffic from known, authorized sources. Use CIDR notation to specify "
                "allowed source networks (e.g., -s 192.168.1.0/24)."
            ),
            risk_score=None,
            control_ids=None,
            compliance_status=None,
        )
