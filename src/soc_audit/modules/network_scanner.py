"""Network scanning module providing basic port discovery."""
from __future__ import annotations

import socket
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable, Mapping

from soc_audit.core.interfaces import BaseModule, Finding, ModuleContext, ModuleResult


@dataclass(frozen=True)
class PortScanTarget:
    host: str
    ports: Iterable[int]


class NetworkScanner(BaseModule):
    name = "network_scanner"
    description = "Scan hosts for open TCP ports and basic service detection."
    module_type = "network"

    @classmethod
    def default_config(cls) -> Mapping[str, object]:
        return {
            "targets": [
                {
                    "host": "127.0.0.1",
                    "ports": [22, 80, 443],
                }
            ],
            "timeout_seconds": 1.0,
        }

    def run(self, context: ModuleContext) -> ModuleResult:
        started_at = datetime.utcnow()
        findings: list[Finding] = []
        targets = list(self._load_targets())
        for target in targets:
            findings.extend(self._scan_target(target))
        completed_at = datetime.utcnow()
        return ModuleResult(
            module_name=self.name,
            started_at=started_at,
            completed_at=completed_at,
            findings=findings,
            metadata={"targets_scanned": len(targets)},
        )

    def _load_targets(self) -> Iterable[PortScanTarget]:
        targets = []
        for entry in self.config.get("targets", []):
            targets.append(PortScanTarget(host=entry["host"], ports=entry["ports"]))
        return targets

    def _scan_target(self, target: PortScanTarget) -> Iterable[Finding]:
        timeout = float(self.config.get("timeout_seconds", 1.0))
        findings: list[Finding] = []
        for port in target.ports:
            if self._is_port_open(target.host, port, timeout):
                service = self._detect_service(target.host, port, timeout)
                findings.append(
                    Finding(
                        title=f"Open port detected: {port}",
                        description=(
                            f"Port {port} is accepting TCP connections on host {target.host}."
                        ),
                        severity="medium",
                        evidence={"host": target.host, "port": port, "service": service},
                        recommendation="Validate if the service is authorized and hardened.",
                    )
                )
        return findings

    @staticmethod
    def _is_port_open(host: str, port: int, timeout: float) -> bool:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((host, port)) == 0

    @staticmethod
    def _detect_service(host: str, port: int, timeout: float) -> str:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(timeout)
                sock.connect((host, port))
                try:
                    sock.sendall(b"\r\n")
                    banner = sock.recv(64)
                except OSError:
                    banner = b""
            if banner:
                return banner.decode("utf-8", errors="ignore").strip()
        except OSError:
            return "unknown"
        return "unknown"
