"""Firewall Misconfiguration Detection Module.

Phase 13.3: Firewall & Network Security
- Open ports vs exposure
- Shadow rules
- Insecure allow-alls
"""
from __future__ import annotations

from typing import Any

from soc_audit.core.interfaces import BaseModule, Finding, ModuleResult


class FirewallMisconfigDetector(BaseModule):
    """
    Detects firewall misconfigurations.
    
    Phase 13.3: Analyzes firewall rules for security issues.
    """
    
    @classmethod
    def default_config(cls) -> dict[str, Any]:
        """Return default configuration."""
        return {
            "enabled": True,
            "check_allow_all": True,
            "check_shadow_rules": True,
            "check_open_ports": True,
            "allowed_ports": [22, 80, 443, 3389],  # Common allowed ports
        }
    
    def run(self, context: Any) -> ModuleResult:
        """
        Run firewall misconfiguration detection.
        
        Phase 13.3: Analyzes firewall rules for security issues.
        """
        findings: list[Finding] = []
        
        # Get firewall rules from context (would be populated by firewall_state_ingestion)
        firewall_rules = context.get("firewall_rules", [])
        
        if not firewall_rules:
            return ModuleResult(
                module_name="firewall_misconfig_detector",
                findings=findings,
                metadata={"message": "No firewall rules available for analysis"},
            )
        
        config = self.config
        
        # Check for insecure allow-all rules
        if config.get("check_allow_all", True):
            allow_all_findings = self._check_allow_all_rules(firewall_rules)
            findings.extend(allow_all_findings)
        
        # Check for shadow rules (conflicting rules)
        if config.get("check_shadow_rules", True):
            shadow_findings = self._check_shadow_rules(firewall_rules)
            findings.extend(shadow_findings)
        
        # Check for exposed ports
        if config.get("check_open_ports", True):
            exposed_findings = self._check_exposed_ports(firewall_rules)
            findings.extend(exposed_findings)
        
        return ModuleResult(
            module_name="firewall_misconfig_detector",
            findings=findings,
            metadata={
                "rules_analyzed": len(firewall_rules),
                "misconfigurations_found": len(findings),
            },
        )
    
    def _check_allow_all_rules(self, rules: list[dict[str, Any]]) -> list[Finding]:
        """
        Check for insecure allow-all rules.
        
        Phase 13.3: Detects rules that allow all traffic.
        """
        findings: list[Finding] = []
        
        for rule in rules:
            source = rule.get("source", "")
            destination = rule.get("destination", "")
            action = rule.get("action", "").lower()
            
            # Check for allow-all source (0.0.0.0/0 or ::/0)
            if action in ("allow", "accept") and source in ("0.0.0.0/0", "::/0", "any", "*"):
                findings.append(
                    Finding(
                        title="Insecure Allow-All Source Rule",
                        description=f"Firewall rule allows traffic from any source: {rule.get('name', 'Unknown rule')}",
                        severity="high",
                        evidence={
                            "rule_name": rule.get("name"),
                            "source": source,
                            "destination": destination,
                            "action": action,
                            "protocol": rule.get("protocol"),
                            "port": rule.get("port"),
                        },
                        recommendation="Restrict source IP addresses to specific networks or hosts",
                        mitre_ids=["T1562.004"],  # Impair Defenses: Disable or Modify System Firewall
                    )
                )
            
            # Check for allow-all destination
            if action in ("allow", "accept") and destination in ("0.0.0.0/0", "::/0", "any", "*"):
                findings.append(
                    Finding(
                        title="Insecure Allow-All Destination Rule",
                        description=f"Firewall rule allows traffic to any destination: {rule.get('name', 'Unknown rule')}",
                        severity="medium",
                        evidence={
                            "rule_name": rule.get("name"),
                            "source": source,
                            "destination": destination,
                            "action": action,
                        },
                        recommendation="Restrict destination IP addresses to specific networks or hosts",
                        mitre_ids=["T1562.004"],
                    )
                )
        
        return findings
    
    def _check_shadow_rules(self, rules: list[dict[str, Any]]) -> list[Finding]:
        """
        Check for shadow rules (conflicting rules).
        
        Phase 13.3: Detects rules that are shadowed by more permissive rules.
        """
        findings: list[Finding] = []
        
        # Group rules by protocol and port
        rule_groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
        
        for rule in rules:
            protocol = rule.get("protocol", "any")
            port = rule.get("port") or rule.get("dport") or "any"
            key = (protocol, str(port))
            
            if key not in rule_groups:
                rule_groups[key] = []
            rule_groups[key].append(rule)
        
        # Check for conflicting rules in same group
        for (protocol, port), group_rules in rule_groups.items():
            if len(group_rules) < 2:
                continue
            
            # Check if there are both allow and deny rules
            has_allow = any(r.get("action", "").lower() in ("allow", "accept") for r in group_rules)
            has_deny = any(r.get("action", "").lower() in ("deny", "drop", "reject") for r in group_rules)
            
            if has_allow and has_deny:
                # Potential shadow rule - deny might be shadowed by allow
                findings.append(
                    Finding(
                        title="Potential Shadow Rule Conflict",
                        description=f"Conflicting firewall rules for {protocol} port {port}: both allow and deny rules present",
                        severity="medium",
                        evidence={
                            "protocol": protocol,
                            "port": port,
                            "rule_count": len(group_rules),
                            "rules": [r.get("name", "Unknown") for r in group_rules],
                        },
                        recommendation="Review rule order and ensure deny rules are evaluated before allow rules",
                        mitre_ids=["T1562.004"],
                    )
                )
        
        return findings
    
    def _check_exposed_ports(self, rules: list[dict[str, Any]]) -> list[Finding]:
        """
        Check for exposed ports (open to internet).
        
        Phase 13.3: Detects ports that are open to external networks.
        """
        findings: list[Finding] = []
        config = self.config
        allowed_ports = set(config.get("allowed_ports", [22, 80, 443, 3389]))
        
        for rule in rules:
            action = rule.get("action", "").lower()
            source = rule.get("source", "")
            port_str = rule.get("port") or rule.get("dport") or ""
            
            # Check if rule allows external access
            if action in ("allow", "accept") and source in ("0.0.0.0/0", "::/0", "any", "*"):
                # Try to parse port
                try:
                    port = int(port_str)
                    if port not in allowed_ports:
                        findings.append(
                            Finding(
                                title=f"Exposed Port: {port}",
                                description=f"Firewall rule allows external access to port {port}: {rule.get('name', 'Unknown rule')}",
                                severity="high" if port < 1024 else "medium",
                                evidence={
                                    "rule_name": rule.get("name"),
                                    "port": port,
                                    "protocol": rule.get("protocol"),
                                    "source": source,
                                    "action": action,
                                },
                                recommendation=f"Restrict port {port} to specific source IPs or close if not needed",
                                mitre_ids=["T1562.004", "T1046"],  # Network Service Scanning
                            )
                        )
                except (ValueError, TypeError):
                    # Port range or unknown format
                    if port_str and port_str not in ("any", "*", "all"):
                        findings.append(
                            Finding(
                                title="Exposed Port Range",
                                description=f"Firewall rule allows external access to port range {port_str}: {rule.get('name', 'Unknown rule')}",
                                severity="medium",
                                evidence={
                                    "rule_name": rule.get("name"),
                                    "port_range": port_str,
                                    "protocol": rule.get("protocol"),
                                    "source": source,
                                },
                                recommendation="Restrict port range to specific source IPs",
                                mitre_ids=["T1562.004", "T1046"],
                            )
                        )
        
        return findings
