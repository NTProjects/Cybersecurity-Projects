"""Local Security Scanner Module.

Checks local system security settings:
- Firewall status and configuration
- Authentication settings
- Logging configuration
- System hardening
- Endpoint protection status
"""
from __future__ import annotations

import platform
import subprocess
from datetime import datetime
from typing import Any, Iterable, Mapping

from soc_audit.core.interfaces import BaseModule, Finding, ModuleContext, ModuleResult


class LocalSecurityScanner(BaseModule):
    """
    Scans local system for security configuration issues.
    
    Uses local_security_scans configuration from config file.
    """
    
    name = "local_security_scanner"
    description = "Scans local system for security misconfigurations (firewall, authentication, logging, hardening, endpoint protection)"
    module_type = "security"
    
    @classmethod
    def default_config(cls) -> Mapping[str, Any]:
        """Return default configuration."""
        return {
            "enabled": True,
            "firewall": {
                "enabled": True,
                "check_firewall_enabled": True,
                "check_default_inbound_policy": True,
                "check_allow_all_rules": True,
                "check_open_inbound_rules": True,
                "check_logging_enabled": True,
                "platforms": {
                    "windows_defender_firewall": True,
                    "iptables": True,
                    "nftables": True,
                },
            },
            "authentication": {
                "enabled": True,
                "check_local_admin_accounts": True,
                "check_guest_account_status": True,
                "check_password_policy": {
                    "min_length": 12,
                    "require_complexity": True,
                },
                "check_account_lockout_policy": True,
            },
            "logging": {
                "enabled": True,
                "check_audit_logging_enabled": True,
                "check_auth_log_sources": True,
                "check_log_retention_days": {
                    "minimum": 30,
                },
                "check_log_file_permissions": True,
            },
            "system_hardening": {
                "enabled": True,
                "check_secure_boot": True,
                "check_disk_encryption": True,
                "check_automatic_updates_enabled": True,
                "check_time_sync_enabled": True,
            },
            "endpoint_protection": {
                "enabled": True,
                "check_antivirus_present": True,
                "check_real_time_protection": True,
                "check_tamper_protection": True,
            },
        }
    
    def run(self, context: ModuleContext) -> ModuleResult:
        """Run local security scan based on configuration."""
        started_at = datetime.utcnow()
        findings: list[Finding] = []
        
        # Get local_security_scans config from context (top-level config)
        config = context.config.get("local_security_scans", {})
        
        # Merge with module's own config (allows per-module override)
        scan_config = {**self.default_config(), **config, **self.config}
        
        if not scan_config.get("enabled", True):
            return ModuleResult(
                module_name=self.name,
                started_at=started_at,
                completed_at=datetime.utcnow(),
                findings=[],
                metadata={"enabled": False},
            )
        
        system = platform.system().lower()
        
        # Firewall checks
        firewall_config = scan_config.get("firewall", {})
        if firewall_config.get("enabled", True):
            firewall_findings = self._check_firewall(system, firewall_config)
            findings.extend(firewall_findings)
        
        # Authentication checks (Windows only for now)
        if system == "windows":
            auth_config = scan_config.get("authentication", {})
            if auth_config.get("enabled", True):
                auth_findings = self._check_authentication(auth_config)
                findings.extend(auth_findings)
        
        # Logging checks
        logging_config = scan_config.get("logging", {})
        if logging_config.get("enabled", True):
            logging_findings = self._check_logging(system, logging_config)
            findings.extend(logging_findings)
        
        # System hardening checks
        hardening_config = scan_config.get("system_hardening", {})
        if hardening_config.get("enabled", True):
            hardening_findings = self._check_system_hardening(system, hardening_config)
            findings.extend(hardening_findings)
        
        # Endpoint protection checks (Windows only for now)
        if system == "windows":
            endpoint_config = scan_config.get("endpoint_protection", {})
            if endpoint_config.get("enabled", True):
                endpoint_findings = self._check_endpoint_protection(endpoint_config)
                findings.extend(endpoint_findings)
        
        completed_at = datetime.utcnow()
        return ModuleResult(
            module_name=self.name,
            started_at=started_at,
            completed_at=completed_at,
            findings=findings,
            metadata={
                "system": system,
                "checks_performed": len(findings),
            },
        )
    
    def _check_firewall(self, system: str, config: dict[str, Any]) -> list[Finding]:
        """Check firewall status and configuration."""
        findings: list[Finding] = []
        
        if system == "windows":
            platforms = config.get("platforms", {})
            if platforms.get("windows_defender_firewall", True):
                # Check if firewall is enabled
                if config.get("check_firewall_enabled", True):
                    firewall_status = self._check_windows_firewall_enabled()
                    if firewall_status.get("enabled") is False:
                        findings.append(
                            Finding(
                                title="Windows Firewall is Disabled",
                                description=f"Windows Defender Firewall is currently disabled. This leaves the system vulnerable to network attacks. Profiles affected: {', '.join(firewall_status.get('disabled_profiles', []))}",
                                severity="critical",
                                evidence={
                                    "system": "windows",
                                    "firewall_type": "windows_defender_firewall",
                                    "profiles": firewall_status.get("profiles", {}),
                                    "source": "local_security_scanner",
                                },
                                recommendation="Enable Windows Defender Firewall for all profiles (Domain, Private, Public) to protect against unauthorized network access.",
                                mitre_ids=["T1562.004"],  # Impair Defenses: Disable or Modify System Firewall
                            )
                        )
                    elif firewall_status.get("enabled") is True:
                        # Firewall is enabled - check additional settings if configured
                        if config.get("check_default_inbound_policy", True):
                            default_policy = firewall_status.get("default_inbound_policy")
                            if default_policy == "allow":
                                findings.append(
                                    Finding(
                                        title="Windows Firewall Default Inbound Policy is Allow",
                                        description="Windows Firewall default inbound policy is set to 'Allow', which allows all inbound connections by default. This is insecure.",
                                        severity="high",
                                        evidence={
                                            "default_inbound_policy": default_policy,
                                            "source": "local_security_scanner",
                                        },
                                        recommendation="Change default inbound policy to 'Block' and create explicit allow rules for required services.",
                                        mitre_ids=["T1562.004"],
                                    )
                                )
                        
                        if config.get("check_logging_enabled", True):
                            logging_enabled = firewall_status.get("logging_enabled")
                            if not logging_enabled:
                                findings.append(
                                    Finding(
                                        title="Windows Firewall Logging is Disabled",
                                        description="Windows Firewall logging is not enabled. This prevents monitoring of blocked/allowed connections.",
                                        severity="medium",
                                        evidence={"source": "local_security_scanner"},
                                        recommendation="Enable Windows Firewall logging for security monitoring.",
                                    )
                                )
        
        elif system == "linux":
            # Check iptables/nftables if configured
            platforms = config.get("platforms", {})
            if platforms.get("iptables", True):
                # TODO: Implement iptables check
                pass
            if platforms.get("nftables", True):
                # TODO: Implement nftables check
                pass
        
        return findings
    
    def _check_windows_firewall_enabled(self) -> dict[str, Any]:
        """Check if Windows Defender Firewall is enabled."""
        try:
            # Check all profiles (Domain, Private, Public)
            cmd = ["netsh", "advfirewall", "show", "allprofiles", "state"]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                return {"enabled": None, "error": result.stderr}
            
            output = result.stdout
            profiles = {}
            disabled_profiles = []
            
            # Parse output for each profile
            for profile in ["Domain", "Private", "Public"]:
                profile_state = None
                default_inbound_policy = None
                logging_enabled = None
                
                # Get profile state
                profile_cmd = ["netsh", "advfirewall", "show", f"{profile.lower()}profile", "state"]
                profile_result = subprocess.run(profile_cmd, capture_output=True, text=True, timeout=10)
                
                if profile_result.returncode == 0:
                    if "ON" in profile_result.stdout.upper():
                        profile_state = True
                    elif "OFF" in profile_result.stdout.upper():
                        profile_state = False
                        disabled_profiles.append(profile)
                
                # Get default inbound policy
                policy_cmd = ["netsh", "advfirewall", "show", f"{profile.lower()}profile", "firewallpolicy"]
                policy_result = subprocess.run(policy_cmd, capture_output=True, text=True, timeout=10)
                
                if policy_result.returncode == 0:
                    if "Inbound:Allow" in policy_result.stdout or "Inbound:AllowInboundAlwaysBlock" in policy_result.stdout:
                        default_inbound_policy = "allow"
                    elif "Inbound:Block" in policy_result.stdout:
                        default_inbound_policy = "block"
                
                # Get logging status
                logging_cmd = ["netsh", "advfirewall", "show", f"{profile.lower()}profile", "logging"]
                logging_result = subprocess.run(logging_cmd, capture_output=True, text=True, timeout=10)
                
                if logging_result.returncode == 0:
                    logging_enabled = "Enabled" in logging_result.stdout
                
                profiles[profile] = {
                    "enabled": profile_state,
                    "default_inbound_policy": default_inbound_policy,
                    "logging_enabled": logging_enabled,
                }
            
            # Overall firewall is enabled if at least one profile is enabled
            overall_enabled = any(p.get("enabled") for p in profiles.values())
            
            return {
                "enabled": overall_enabled,
                "profiles": profiles,
                "disabled_profiles": disabled_profiles,
                "default_inbound_policy": profiles.get("Domain", {}).get("default_inbound_policy") or profiles.get("Private", {}).get("default_inbound_policy"),
                "logging_enabled": any(p.get("logging_enabled") for p in profiles.values()),
            }
        except Exception as e:
            return {"enabled": None, "error": str(e)}
    
    def _check_authentication(self, config: dict[str, Any]) -> list[Finding]:
        """Check authentication settings."""
        findings: list[Finding] = []
        # TODO: Implement authentication checks
        # - Check local admin accounts
        # - Check guest account status
        # - Check password policy
        # - Check account lockout policy
        return findings
    
    def _check_logging(self, system: str, config: dict[str, Any]) -> list[Finding]:
        """Check logging configuration."""
        findings: list[Finding] = []
        # TODO: Implement logging checks
        # - Check audit logging enabled
        # - Check auth log sources
        # - Check log retention
        # - Check log file permissions
        return findings
    
    def _check_system_hardening(self, system: str, config: dict[str, Any]) -> list[Finding]:
        """Check system hardening settings."""
        findings: list[Finding] = []
        # TODO: Implement system hardening checks
        # - Check secure boot
        # - Check disk encryption
        # - Check automatic updates
        # - Check time sync
        return findings
    
    def _check_endpoint_protection(self, config: dict[str, Any]) -> list[Finding]:
        """Check endpoint protection status."""
        findings: list[Finding] = []
        # TODO: Implement endpoint protection checks
        # - Check antivirus present
        # - Check real-time protection
        # - Check tamper protection
        return findings
