"""Firewall State Ingestion Module.

Phase 13.1: Firewall & Network Security
- Windows Defender Firewall
- iptables / nftables
- Cloud SGs (future)
"""
from __future__ import annotations

import platform
import subprocess
from pathlib import Path
from typing import Any

from soc_audit.core.interfaces import Finding, ModuleResult
from soc_audit.core.models import BaseModule


class FirewallStateIngestion(BaseModule):
    """
    Ingests firewall state from various sources.
    
    Phase 13.1: Collects firewall rules and state for analysis.
    """
    
    @classmethod
    def default_config(cls) -> dict[str, Any]:
        """Return default configuration."""
        return {
            "enabled": True,
            "sources": ["windows", "iptables", "nftables"],  # Which firewalls to check
            "windows_profile": "all",  # domain, private, public, all
        }
    
    def run(self, context: Any) -> ModuleResult:
        """
        Run firewall state ingestion.
        
        Phase 13.1: Collects firewall rules from available sources.
        """
        findings: list[Finding] = []
        system = platform.system().lower()
        
        config = self.config
        sources = config.get("sources", [])
        
        # Windows Defender Firewall
        if "windows" in sources and system == "windows":
            windows_findings = self._ingest_windows_firewall()
            findings.extend(windows_findings)
        
        # iptables (Linux)
        if "iptables" in sources and system == "linux":
            iptables_findings = self._ingest_iptables()
            findings.extend(iptables_findings)
        
        # nftables (Linux)
        if "nftables" in sources and system == "linux":
            nftables_findings = self._ingest_nftables()
            findings.extend(nftables_findings)
        
        return ModuleResult(
            module_name="firewall_state_ingestion",
            findings=findings,
            metadata={
                "system": system,
                "sources_checked": sources,
                "rules_ingested": len(findings),
            },
        )
    
    def _ingest_windows_firewall(self) -> list[Finding]:
        """
        Ingest Windows Defender Firewall rules.
        
        Phase 13.1: Uses netsh to query firewall rules.
        """
        findings: list[Finding] = []
        
        try:
            # Get firewall rules
            profile = self.config.get("windows_profile", "all")
            cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all", "type=all"]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Parse rules (simplified - full parser would be more complex)
                rules = self._parse_windows_rules(result.stdout)
                
                for rule in rules:
                    findings.append(
                        Finding(
                            title=f"Firewall Rule: {rule.get('name', 'Unknown')}",
                            description=f"Windows Firewall Rule - Direction: {rule.get('direction', 'Unknown')}, Action: {rule.get('action', 'Unknown')}",
                            severity="info",
                            evidence={
                                "rule_name": rule.get("name"),
                                "direction": rule.get("direction"),
                                "action": rule.get("action"),
                                "protocol": rule.get("protocol"),
                                "local_port": rule.get("local_port"),
                                "remote_port": rule.get("remote_port"),
                                "profile": rule.get("profile"),
                                "source": "windows_firewall",
                            },
                            mitre_ids=["T1562.004"],  # Impair Defenses: Disable or Modify System Firewall
                        )
                    )
        except Exception as e:
            findings.append(
                Finding(
                    title="Windows Firewall Ingestion Error",
                    description=f"Failed to ingest Windows Firewall rules: {str(e)}",
                    severity="warning",
                    evidence={"error": str(e), "source": "windows_firewall"},
                )
            )
        
        return findings
    
    def _parse_windows_rules(self, output: str) -> list[dict[str, Any]]:
        """
        Parse Windows netsh firewall rule output.
        
        Phase 13.1: Extracts rule information from netsh output.
        """
        rules = []
        current_rule: dict[str, Any] = {}
        
        for line in output.split("\n"):
            line = line.strip()
            if not line:
                if current_rule:
                    rules.append(current_rule)
                    current_rule = {}
                continue
            
            # Parse key-value pairs
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == "rule name":
                    if current_rule:
                        rules.append(current_rule)
                    current_rule = {"name": value}
                elif key == "enabled":
                    current_rule["enabled"] = value.lower() == "yes"
                elif key == "direction":
                    current_rule["direction"] = value.lower()
                elif key == "action":
                    current_rule["action"] = value.lower()
                elif key == "protocol":
                    current_rule["protocol"] = value.upper()
                elif key == "localport":
                    current_rule["local_port"] = value
                elif key == "remoteport":
                    current_rule["remote_port"] = value
                elif key == "profile":
                    current_rule["profile"] = value
        
        if current_rule:
            rules.append(current_rule)
        
        return rules
    
    def _ingest_iptables(self) -> list[Finding]:
        """
        Ingest iptables rules.
        
        Phase 13.1: Uses iptables-save or iptables -L to query rules.
        """
        findings: list[Finding] = []
        
        try:
            # Try iptables-save first (more complete)
            cmd = ["iptables-save"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode != 0:
                # Fallback to iptables -L
                cmd = ["iptables", "-L", "-n", "-v"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                rules = self._parse_iptables_rules(result.stdout)
                
                for rule in rules:
                    findings.append(
                        Finding(
                            title=f"iptables Rule: {rule.get('chain', 'Unknown')}",
                            description=f"iptables Rule - Target: {rule.get('target', 'Unknown')}, Protocol: {rule.get('protocol', 'Unknown')}",
                            severity="info",
                            evidence={
                                "chain": rule.get("chain"),
                                "target": rule.get("target"),
                                "protocol": rule.get("protocol"),
                                "source": rule.get("source"),
                                "destination": rule.get("destination"),
                                "sport": rule.get("sport"),
                                "dport": rule.get("dport"),
                                "source": "iptables",
                            },
                            mitre_ids=["T1562.004"],
                        )
                    )
        except FileNotFoundError:
            # iptables not available
            pass
        except Exception as e:
            findings.append(
                Finding(
                    title="iptables Ingestion Error",
                    description=f"Failed to ingest iptables rules: {str(e)}",
                    severity="warning",
                    evidence={"error": str(e), "source": "iptables"},
                )
            )
        
        return findings
    
    def _parse_iptables_rules(self, output: str) -> list[dict[str, Any]]:
        """
        Parse iptables rule output.
        
        Phase 13.1: Extracts rule information from iptables output.
        """
        rules = []
        current_chain = None
        
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Chain declaration
            if line.startswith(":"):
                # Format: :CHAIN_NAME POLICY [packets:bytes]
                parts = line.split()
                if parts:
                    current_chain = parts[0].lstrip(":")
            elif line.startswith("-A") or (current_chain and not line.startswith("*") and not line.startswith("COMMIT")):
                # Rule line
                rule: dict[str, Any] = {"chain": current_chain or "unknown"}
                
                # Parse rule components (simplified)
                parts = line.split()
                for i, part in enumerate(parts):
                    if part == "-p" and i + 1 < len(parts):
                        rule["protocol"] = parts[i + 1]
                    elif part == "-s" and i + 1 < len(parts):
                        rule["source"] = parts[i + 1]
                    elif part == "-d" and i + 1 < len(parts):
                        rule["destination"] = parts[i + 1]
                    elif part == "--sport" and i + 1 < len(parts):
                        rule["sport"] = parts[i + 1]
                    elif part == "--dport" and i + 1 < len(parts):
                        rule["dport"] = parts[i + 1]
                    elif part == "-j" and i + 1 < len(parts):
                        rule["target"] = parts[i + 1]
                
                if rule.get("target"):
                    rules.append(rule)
        
        return rules
    
    def _ingest_nftables(self) -> list[Finding]:
        """
        Ingest nftables rules.
        
        Phase 13.1: Uses nft list ruleset to query rules.
        """
        findings: list[Finding] = []
        
        try:
            cmd = ["nft", "list", "ruleset"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                rules = self._parse_nftables_rules(result.stdout)
                
                for rule in rules:
                    findings.append(
                        Finding(
                            title=f"nftables Rule: {rule.get('chain', 'Unknown')}",
                            description=f"nftables Rule - Action: {rule.get('action', 'Unknown')}, Protocol: {rule.get('protocol', 'Unknown')}",
                            severity="info",
                            evidence={
                                "table": rule.get("table"),
                                "chain": rule.get("chain"),
                                "action": rule.get("action"),
                                "protocol": rule.get("protocol"),
                                "source": rule.get("source"),
                                "destination": rule.get("destination"),
                                "sport": rule.get("sport"),
                                "dport": rule.get("dport"),
                                "source": "nftables",
                            },
                            mitre_ids=["T1562.004"],
                        )
                    )
        except FileNotFoundError:
            # nftables not available
            pass
        except Exception as e:
            findings.append(
                Finding(
                    title="nftables Ingestion Error",
                    description=f"Failed to ingest nftables rules: {str(e)}",
                    severity="warning",
                    evidence={"error": str(e), "source": "nftables"},
                )
            )
        
        return findings
    
    def _parse_nftables_rules(self, output: str) -> list[dict[str, Any]]:
        """
        Parse nftables rule output.
        
        Phase 13.1: Extracts rule information from nftables output.
        """
        rules = []
        current_table = None
        current_chain = None
        
        for line in output.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            
            # Table declaration
            if line.startswith("table"):
                parts = line.split()
                if len(parts) >= 2:
                    current_table = parts[1]
            
            # Chain declaration
            elif line.startswith("chain"):
                parts = line.split()
                if len(parts) >= 2:
                    current_chain = parts[1]
            
            # Rule line
            elif line and current_chain:
                rule: dict[str, Any] = {
                    "table": current_table,
                    "chain": current_chain,
                }
                
                # Parse rule (simplified - nftables syntax is complex)
                if "accept" in line.lower():
                    rule["action"] = "accept"
                elif "drop" in line.lower():
                    rule["action"] = "drop"
                elif "reject" in line.lower():
                    rule["action"] = "reject"
                
                # Extract protocol, ports, etc. (simplified)
                if "tcp" in line.lower():
                    rule["protocol"] = "tcp"
                elif "udp" in line.lower():
                    rule["protocol"] = "udp"
                
                if rule.get("action"):
                    rules.append(rule)
        
        return rules
