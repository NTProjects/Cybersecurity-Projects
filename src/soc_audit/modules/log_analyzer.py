"""Log analyzer module for detecting repeated authentication failures in Linux auth logs."""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Mapping

from soc_audit.core.interfaces import BaseModule, Finding, ModuleContext, ModuleResult


class LogAnalyzer(BaseModule):
    """
    Module that analyzes Linux authentication logs for repeated failure patterns.

    This module parses auth.log format files and detects potential brute-force
    attacks by identifying repeated authentication failures from the same source.
    """

    name = "log_analyzer"
    description = "Analyze Linux authentication logs for repeated authentication failures."
    module_type = "policy"

    @classmethod
    def default_config(cls) -> Mapping[str, object]:
        return {
            "log_file": None,  # Path to auth.log file
            "failure_threshold": 5,  # Minimum number of failures to trigger a finding
        }

    def run(self, context: ModuleContext) -> ModuleResult:
        """
        Execute the log analyzer module.

        Args:
            context: Module context containing configuration.

        Returns:
            ModuleResult with findings for repeated authentication failures.

        Raises:
            FileNotFoundError: If the log file is not found.
            RuntimeError: If the log file cannot be read.
        """
        started_at = datetime.utcnow()
        findings: list[Finding] = []

        # Get config from log_analyzer section
        log_analyzer_config = self.config.get("log_analyzer", {})
        log_file = log_analyzer_config.get("log_file")
        failure_threshold = log_analyzer_config.get("failure_threshold", 5)

        if not log_file:
            # No log file specified - return empty result
            completed_at = datetime.utcnow()
            return ModuleResult(
                module_name=self.name,
                started_at=started_at,
                completed_at=completed_at,
                findings=findings,
                metadata={},
            )

        # Parse log file
        try:
            failure_counts = self._parse_auth_log(log_file)
            findings = self._detect_repeated_failures(failure_counts, failure_threshold)
        except FileNotFoundError:
            # Re-raise FileNotFoundError as-is
            raise
        except (OSError, UnicodeDecodeError) as exc:
            raise RuntimeError(f"Failed to read log file: {log_file}") from exc

        completed_at = datetime.utcnow()
        return ModuleResult(
            module_name=self.name,
            started_at=started_at,
            completed_at=completed_at,
            findings=findings,
            metadata={},
        )

    def _parse_auth_log(self, file_path: str | Path) -> dict[tuple[str | None, str | None], int]:
        """
        Parse Linux auth.log file and count authentication failures.

        Args:
            file_path: Path to the auth.log file.

        Returns:
            Dictionary mapping (username, source_ip) tuples to failure counts.

        Raises:
            FileNotFoundError: If the file does not exist.
            OSError: If the file cannot be read.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Log file not found: {path}")

        try:
            content = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise OSError(f"Failed to read file: {path}") from exc

        failure_counts: dict[tuple[str | None, str | None], int] = defaultdict(int)

        # Patterns to match authentication failure lines
        # Examples:
        # - "Failed password for user from 192.168.1.1"
        # - "authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost=192.168.1.1"
        # - "Invalid user admin from 192.168.1.1"

        failed_password_pattern = re.compile(
            r"Failed password for (?P<username>\S+) from (?P<ip>\S+)"
        )
        auth_failure_pattern = re.compile(
            r"authentication failure.*?rhost=(?P<ip>\S+)"
        )
        invalid_user_pattern = re.compile(
            r"Invalid user (?P<username>\S+) from (?P<ip>\S+)"
        )

        for line in content.splitlines():
            # Try to match failed password pattern
            match = failed_password_pattern.search(line)
            if match:
                username = match.group("username")
                source_ip = match.group("ip")
                failure_counts[(username, source_ip)] += 1
                continue

            # Try to match authentication failure pattern
            match = auth_failure_pattern.search(line)
            if match:
                source_ip = match.group("ip")
                failure_counts[(None, source_ip)] += 1
                continue

            # Try to match invalid user pattern
            match = invalid_user_pattern.search(line)
            if match:
                username = match.group("username")
                source_ip = match.group("ip")
                failure_counts[(username, source_ip)] += 1
                continue

        return dict(failure_counts)

    def _detect_repeated_failures(
        self, failure_counts: dict[tuple[str | None, str | None], int], threshold: int
    ) -> list[Finding]:
        """
        Detect repeated authentication failures exceeding the threshold.

        Args:
            failure_counts: Dictionary mapping (username, source_ip) to failure counts.
            threshold: Minimum number of failures to trigger a finding.

        Returns:
            List of Finding objects for failures exceeding the threshold.
        """
        findings: list[Finding] = []

        for (username, source_ip), count in failure_counts.items():
            if count >= threshold:
                findings.append(self._create_finding(username, source_ip, count))

        return findings

    @staticmethod
    def _create_finding(username: str | None, source_ip: str | None, failure_count: int) -> Finding:
        """
        Create a Finding for repeated authentication failures.

        Args:
            username: The username that failed authentication (may be None).
            source_ip: The source IP address (may be None).
            failure_count: The number of failed attempts.

        Returns:
            Finding object describing the security issue.
        """
        # Build description
        parts = []
        if username:
            parts.append(f"User '{username}'")
        else:
            parts.append("Unknown user")
        if source_ip:
            parts.append(f"from IP {source_ip}")
        parts.append(f"has {failure_count} authentication failure(s)")

        description = f"{' '.join(parts)}. This pattern may indicate a brute-force attack attempt."

        # Build evidence
        evidence: dict[str, str | int] = {"failure_count": failure_count}
        if username:
            evidence["username"] = username
        if source_ip:
            evidence["source_ip"] = source_ip

        return Finding(
            title="Repeated authentication failures detected",
            description=description,
            severity="high",
            evidence=evidence,
            recommendation=(
                "Investigate potential brute-force attack and consider blocking the source IP. "
                "Review authentication logs for additional context and implement rate limiting "
                "or account lockout policies if not already in place."
            ),
            risk_score=None,
            control_ids=None,
            compliance_status=None,
        )
