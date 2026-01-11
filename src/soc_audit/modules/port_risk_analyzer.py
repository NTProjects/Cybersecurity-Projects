"""Port risk analysis module for categorizing ports and detecting protocol vulnerabilities."""
from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Mapping

from soc_audit.core.interfaces import BaseModule, Finding, ModuleContext, ModuleResult
from soc_audit.core.risk import calculate_risk_score


@dataclass(frozen=True)
class PortTarget:
    host: str
    port: int


# Known-risk port categorization
# High-risk ports: Commonly exploited services, unencrypted protocols, database services
HIGH_RISK_PORTS: set[int] = {
    21,  # FTP (if anonymous access enabled)
    23,  # Telnet (clear text)
    135,  # MSRPC
    139,  # NetBIOS
    445,  # SMB
    1433,  # MSSQL
    3306,  # MySQL
    5432,  # PostgreSQL
    3389,  # RDP
    5900,  # VNC
    5985,  # WinRM HTTP
    5986,  # WinRM HTTPS (if misconfigured)
}

# Medium-risk ports: Common services that may be misconfigured
MEDIUM_RISK_PORTS: set[int] = {
    22,  # SSH (if weak config)
    80,  # HTTP (if not redirecting to HTTPS)
    161,  # SNMP (if public community strings)
    443,  # HTTPS (if weak ciphers)
    2049,  # NFS
    6379,  # Redis (if exposed without auth)
    27017,  # MongoDB (if exposed without auth)
    8080,  # HTTP Proxy
    8443,  # HTTPS Alternative
}


class PortRiskAnalyzer(BaseModule):
    name = "port_risk_analyzer"
    description = "Analyze open ports for known-risk categorization and protocol-aware security checks."
    module_type = "network"

    @classmethod
    def default_config(cls) -> Mapping[str, object]:
        return {
            "targets": [
                {
                    "host": "127.0.0.1",
                    "port": 22,
                }
            ],
            "timeout_seconds": 2.0,
            "check_ftp_anonymous": True,
            "check_telnet": True,
        }

    def run(self, context: ModuleContext) -> ModuleResult:
        started_at = datetime.utcnow()
        findings: list[Finding] = []
        targets = list(self._load_targets())
        for target in targets:
            findings.extend(self._analyze_port(target))
        completed_at = datetime.utcnow()
        return ModuleResult(
            module_name=self.name,
            started_at=started_at,
            completed_at=completed_at,
            findings=findings,
            metadata={"ports_analyzed": len(targets)},
        )

    def _load_targets(self) -> Iterable[PortTarget]:
        targets = []
        for entry in self.config.get("targets", []):
            targets.append(PortTarget(host=entry["host"], port=entry["port"]))
        return targets

    def _analyze_port(self, target: PortTarget) -> Iterable[Finding]:
        findings: list[Finding] = []
        timeout = float(self.config.get("timeout_seconds", 2.0))

        # Categorize port by known risk level
        risk_level, severity = self._categorize_port_risk(target.port)
        if risk_level:
            findings.append(self._create_port_risk_finding(target, risk_level, severity))

        # Protocol-aware checks
        if target.port == 21 and self.config.get("check_ftp_anonymous", True):
            ftp_finding = self._check_ftp_anonymous(target, timeout)
            if ftp_finding:
                findings.append(ftp_finding)

        if target.port == 23 and self.config.get("check_telnet", True):
            findings.append(self._create_telnet_warning(target))

        return findings

    @staticmethod
    def _categorize_port_risk(port: int) -> tuple[str | None, str]:
        """
        Categorize a port by known risk level.

        Returns:
            Tuple of (risk_level, severity) or (None, "low") if port is not in known risk lists.
        """
        if port in HIGH_RISK_PORTS:
            return "high", "high"
        if port in MEDIUM_RISK_PORTS:
            return "medium", "medium"
        return None, "low"

    def _create_port_risk_finding(self, target: PortTarget, risk_level: str, severity: str) -> Finding:
        """Create a finding for a known-risk port."""
        risk_level_display = risk_level.upper()
        temp_finding = Finding(
            title="",
            description="",
            severity=severity,
        )
        risk_score = calculate_risk_score(temp_finding)

        service_name = self._get_service_name(target.port)
        return Finding(
            title=f"Known-risk port detected: {target.port} ({service_name})",
            description=(
                f"Port {target.port} ({service_name}) on host {target.host} is categorized as "
                f"{risk_level_display}-risk. This port is commonly associated with services that "
                f"may be vulnerable if misconfigured or exposed."
            ),
            severity=severity,
            evidence={
                "host": target.host,
                "port": target.port,
                "service": service_name,
                "risk_level": risk_level,
            },
            recommendation=(
                f"Review the configuration of {service_name} on port {target.port}. "
                f"Ensure the service is properly secured, authenticated, and up-to-date."
            ),
            risk_score=risk_score,
        )

    def _check_ftp_anonymous(self, target: PortTarget, timeout: float) -> Finding | None:
        """Check if FTP server allows anonymous access."""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((target.host, target.port))
                # Read FTP banner
                banner = sock.recv(1024).decode("utf-8", errors="ignore")

                # Try anonymous login
                sock.sendall(b"USER anonymous\r\n")
                response = sock.recv(1024).decode("utf-8", errors="ignore").upper()

                # Check if anonymous login is accepted (typically "230" response code)
                if "230" in response or "331" in response:
                    # 230 = logged in, 331 = password required but user accepted
                    temp_finding = Finding(
                        title="",
                        description="",
                        severity="high",
                    )
                    risk_score = calculate_risk_score(temp_finding)

                    return Finding(
                        title="FTP anonymous access enabled",
                        description=(
                            f"FTP server on {target.host}:{target.port} appears to allow "
                            "anonymous access. This is a significant security risk as it "
                            "allows unauthorized users to access the FTP server."
                        ),
                        severity="high",
                        evidence={
                            "host": target.host,
                            "port": target.port,
                            "banner": banner.strip(),
                            "anonymous_response": response.strip(),
                        },
                        recommendation=(
                            "Disable anonymous FTP access unless absolutely necessary. "
                            "If anonymous access is required, restrict it to read-only "
                            "operations and monitor access logs."
                        ),
                        risk_score=risk_score,
                    )
        except (OSError, socket.timeout, UnicodeDecodeError):
            # Connection failed or error reading response - cannot determine anonymous access
            pass

        return None

    def _create_telnet_warning(self, target: PortTarget) -> Finding:
        """Create a warning finding for Telnet service (clear text protocol)."""
        temp_finding = Finding(
            title="",
            description="",
            severity="high",
        )
        risk_score = calculate_risk_score(temp_finding)

        return Finding(
            title="Telnet service detected (clear text protocol)",
            description=(
                f"Telnet service is running on {target.host}:{target.port}. "
                "Telnet transmits credentials and data in clear text, making it vulnerable "
                "to eavesdropping and credential theft."
            ),
            severity="high",
            evidence={
                "host": target.host,
                "port": target.port,
                "protocol": "telnet",
            },
            recommendation=(
                "Replace Telnet with SSH (port 22) or another encrypted remote access protocol. "
                "Telnet should never be used in production environments due to its lack of encryption."
            ),
            risk_score=risk_score,
        )

    @staticmethod
    def _get_service_name(port: int) -> str:
        """Get common service name for a port."""
        service_names: dict[int, str] = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            80: "HTTP",
            135: "MSRPC",
            139: "NetBIOS",
            443: "HTTPS",
            445: "SMB",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5432: "PostgreSQL",
            5900: "VNC",
            5985: "WinRM HTTP",
            5986: "WinRM HTTPS",
            6379: "Redis",
            8080: "HTTP Proxy",
            8443: "HTTPS Alternative",
            2049: "NFS",
            27017: "MongoDB",
            161: "SNMP",
        }
        return service_names.get(port, "Unknown")
