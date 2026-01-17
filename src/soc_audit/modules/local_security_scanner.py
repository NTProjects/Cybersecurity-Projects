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
            },
            "windows_defender": {
                "enabled": True,
                "check_real_time_protection": True,
                "check_tamper_protection": True,
                "check_cloud_protection": True,
                "check_automatic_sample_submission": True,
                "check_signature_updates": True,
                "check_dev_drive_protection": True,
                "check_controlled_folder_access": True,
                "check_exclusions": True,
            },
            "device_security": {
                "enabled": True,
                "check_memory_integrity": True,
                "check_secure_boot": True,
                "check_tpm": True,
                "check_lsa_protection": True,
                "check_vulnerable_driver_blocklist": True,
                "check_kernel_stack_protection": True,
            },
            "exploit_protection": {
                "enabled": True,
                "check_cfg": True,
                "check_dep": True,
                "check_mandatory_aslr": True,
                "check_bottom_up_aslr": True,
                "check_high_entropy_aslr": True,
                "check_sehop": True,
                "check_heap_integrity": True,
            },
            "app_browser_control": {
                "enabled": True,
                "check_smartscreen_apps": True,
                "check_smartscreen_edge": True,
                "check_smartscreen_store": True,
                "check_phishing_protection": True,
                "check_pua_blocking": True,
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
            
            # Windows Defender checks
            defender_config = scan_config.get("windows_defender", {})
            if defender_config.get("enabled", True):
                defender_findings = self._check_windows_defender(defender_config)
                findings.extend(defender_findings)
            
            # Device security checks
            device_security_config = scan_config.get("device_security", {})
            if device_security_config.get("enabled", True):
                device_security_findings = self._check_device_security(device_security_config)
                findings.extend(device_security_findings)
            
            # Exploit protection checks
            exploit_config = scan_config.get("exploit_protection", {})
            if exploit_config.get("enabled", True):
                exploit_findings = self._check_exploit_protection(exploit_config)
                findings.extend(exploit_findings)
            
            # App & browser control checks
            app_browser_config = scan_config.get("app_browser_control", {})
            if app_browser_config.get("enabled", True):
                app_browser_findings = self._check_app_browser_control(app_browser_config)
                findings.extend(app_browser_findings)
        
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
        
        if config.get("check_antivirus_present", True):
            # Check if Windows Defender is present and running
            try:
                cmd = ["powershell", "-Command", "Get-MpComputerStatus | Select-Object -ExpandProperty AntivirusEnabled"]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                if result.returncode == 0:
                    av_enabled = result.stdout.strip().lower() == "true"
                    if not av_enabled:
                        findings.append(
                            Finding(
                                title="Windows Defender Antivirus is Disabled",
                                description="Windows Defender Antivirus is not enabled. This leaves the system vulnerable to malware and viruses.",
                                severity="critical",
                                evidence={"source": "local_security_scanner"},
                                recommendation="Enable Windows Defender Antivirus to protect against malware threats.",
                                mitre_ids=["T1562.001"],  # Impair Defenses: Disable or Modify Tools
                            )
                        )
            except Exception:
                pass  # PowerShell might not be available
        
        return findings
    
    def _check_windows_defender(self, config: dict[str, Any]) -> list[Finding]:
        """Check Windows Defender Antivirus settings."""
        findings: list[Finding] = []
        
        try:
            # Get Windows Defender status using PowerShell
            ps_cmd = """
            $status = Get-MpComputerStatus
            $prefs = Get-MpPreference
            
            @{
                RealTimeProtectionEnabled = $status.RealTimeProtectionEnabled
                TamperProtectionEnabled = $status.IsTamperProtected
                CloudProtectionEnabled = $prefs.MAPSReporting -eq 2
                AutomaticSampleSubmission = $prefs.SubmitSamplesConsent -eq 1
                AntivirusEnabled = $status.AntivirusEnabled
                AntispywareEnabled = $status.AntispywareEnabled
                QuickScanAge = $status.QuickScanAge
                FullScanAge = $status.FullScanAge
                SignatureAge = $status.AntivirusSignatureAge
            } | ConvertTo-Json
            """
            
            cmd = ["powershell", "-Command", ps_cmd]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                import json
                defender_status = json.loads(result.stdout)
                
                # Check real-time protection
                if config.get("check_real_time_protection", True):
                    if not defender_status.get("RealTimeProtectionEnabled", False):
                        findings.append(
                            Finding(
                                title="Windows Defender Real-Time Protection is Disabled",
                                description="Windows Defender Real-Time Protection is disabled. This prevents real-time scanning of files and processes.",
                                severity="critical",
                                evidence={"source": "local_security_scanner", "setting": "RealTimeProtectionEnabled"},
                                recommendation="Enable Windows Defender Real-Time Protection to detect and block threats in real-time.",
                                mitre_ids=["T1562.001"],
                            )
                        )
                
                # Check tamper protection
                if config.get("check_tamper_protection", True):
                    if not defender_status.get("TamperProtectionEnabled", False):
                        findings.append(
                            Finding(
                                title="Windows Defender Tamper Protection is Disabled",
                                description="Windows Defender Tamper Protection is disabled. This allows unauthorized changes to antivirus settings.",
                                severity="high",
                                evidence={"source": "local_security_scanner", "setting": "TamperProtectionEnabled"},
                                recommendation="Enable Windows Defender Tamper Protection to prevent malicious software from disabling security features.",
                                mitre_ids=["T1562.001"],
                            )
                        )
                
                # Check cloud protection
                if config.get("check_cloud_protection", True):
                    if not defender_status.get("CloudProtectionEnabled", False):
                        findings.append(
                            Finding(
                                title="Windows Defender Cloud Protection is Disabled",
                                description="Windows Defender Cloud Protection (MAPS) is disabled. This reduces the ability to detect new and emerging threats.",
                                severity="medium",
                                evidence={"source": "local_security_scanner", "setting": "CloudProtectionEnabled"},
                                recommendation="Enable Windows Defender Cloud Protection for enhanced threat detection capabilities.",
                            )
                        )
                
                # Check automatic sample submission
                if config.get("check_automatic_sample_submission", True):
                    if not defender_status.get("AutomaticSampleSubmission", False):
                        findings.append(
                            Finding(
                                title="Windows Defender Automatic Sample Submission is Disabled",
                                description="Automatic sample submission is disabled. This prevents Microsoft from analyzing suspicious files for threat intelligence.",
                                severity="low",
                                evidence={"source": "local_security_scanner", "setting": "AutomaticSampleSubmission"},
                                recommendation="Enable automatic sample submission to help improve threat detection for all users.",
                            )
                        )
                
                # Check signature updates
                if config.get("check_signature_updates", True):
                    signature_age = defender_status.get("SignatureAge", 999)
                    if signature_age > 7:  # Older than 7 days
                        findings.append(
                            Finding(
                                title="Windows Defender Signatures are Outdated",
                                description=f"Windows Defender antivirus signatures are {signature_age} days old. Outdated signatures reduce protection against new threats.",
                                severity="high",
                                evidence={"source": "local_security_scanner", "signature_age_days": signature_age},
                                recommendation="Update Windows Defender signatures immediately to ensure protection against the latest threats.",
                            )
                        )
                
                # Check Dev Drive protection
                if config.get("check_dev_drive_protection", True):
                    ps_cmd_dev = """
                    try {
                        $prefs = Get-MpPreference -ErrorAction SilentlyContinue
                        $devDriveEnabled = ($prefs.EnableDevDriveScanning -eq $true)
                        @{DevDriveProtection = $devDriveEnabled} | ConvertTo-Json
                    } catch {
                        @{DevDriveProtection = $false, Error = $_.Exception.Message} | ConvertTo-Json
                    }
                    """
                    
                    cmd_dev = ["powershell", "-Command", ps_cmd_dev]
                    result_dev = subprocess.run(cmd_dev, capture_output=True, text=True, timeout=10)
                    
                    if result_dev.returncode == 0:
                        status_dev = json.loads(result_dev.stdout)
                        if not status_dev.get("DevDriveProtection", False):
                            findings.append(
                                Finding(
                                    title="Windows Defender Dev Drive Protection is Disabled",
                                    description="Dev Drive protection is disabled. This reduces protection against threats on Dev Drive volumes.",
                                    severity="low",
                                    evidence={"source": "local_security_scanner", "setting": "DevDriveProtection"},
                                    recommendation="Enable Dev Drive protection in Windows Security > Virus & threat protection settings to scan Dev Drive volumes for threats.",
                                )
                            )
                
                # Check Controlled Folder Access (Ransomware protection)
                if config.get("check_controlled_folder_access", True):
                    ps_cmd_cfa = """
                    try {
                        $regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows Defender\\Windows Defender Exploit Guard\\Controlled Folder Access"
                        $enabled = (Get-ItemProperty -Path $regPath -Name "EnableControlledFolderAccess" -ErrorAction SilentlyContinue).EnableControlledFolderAccess
                        if ($enabled -eq $null) { $enabled = 0 }
                        @{ControlledFolderAccess = ($enabled -eq 1)} | ConvertTo-Json
                    } catch {
                        @{ControlledFolderAccess = $false, Error = $_.Exception.Message} | ConvertTo-Json
                    }
                    """
                    
                    cmd_cfa = ["powershell", "-Command", ps_cmd_cfa]
                    result_cfa = subprocess.run(cmd_cfa, capture_output=True, text=True, timeout=10)
                    
                    if result_cfa.returncode == 0:
                        status_cfa = json.loads(result_cfa.stdout)
                        if not status_cfa.get("ControlledFolderAccess", False):
                            findings.append(
                                Finding(
                                    title="Controlled Folder Access (Ransomware Protection) is Disabled",
                                    description="Controlled Folder Access is disabled. This leaves files, folders, and memory areas vulnerable to unauthorized changes by malicious applications, including ransomware attacks.",
                                    severity="high",
                                    evidence={"source": "local_security_scanner", "setting": "ControlledFolderAccess"},
                                    recommendation="Enable Controlled Folder Access in Windows Security > Virus & threat protection > Ransomware protection to protect against unauthorized file changes.",
                                    mitre_ids=["T1486"],  # Data Encrypted for Impact
                                )
                            )
                
                # Check for exclusions (warn if any exist)
                if config.get("check_exclusions", True):
                    ps_cmd_excl = """
                    try {
                        $prefs = Get-MpPreference -ErrorAction SilentlyContinue
                        $exclusions = @()
                        
                        if ($prefs.ExclusionPath) { $exclusions += $prefs.ExclusionPath }
                        if ($prefs.ExclusionExtension) { $exclusions += $prefs.ExclusionExtension }
                        if ($prefs.ExclusionProcess) { $exclusions += $prefs.ExclusionProcess }
                        
                        @{ExclusionCount = $exclusions.Count, Exclusions = $exclusions} | ConvertTo-Json
                    } catch {
                        @{ExclusionCount = 0, Error = $_.Exception.Message} | ConvertTo-Json
                    }
                    """
                    
                    cmd_excl = ["powershell", "-Command", ps_cmd_excl]
                    result_excl = subprocess.run(cmd_excl, capture_output=True, text=True, timeout=10)
                    
                    if result_excl.returncode == 0:
                        status_excl = json.loads(result_excl.stdout)
                        exclusion_count = status_excl.get("ExclusionCount", 0)
                        if exclusion_count > 0:
                            exclusions = status_excl.get("Exclusions", [])
                            # Limit to first 10 for display
                            exclusion_preview = exclusions[:10] if len(exclusions) > 10 else exclusions
                            findings.append(
                                Finding(
                                    title=f"Windows Defender Has {exclusion_count} Exclusion(s) Configured",
                                    description=f"Windows Defender has {exclusion_count} exclusion(s) configured. Excluded items are not scanned and could contain threats. Review exclusions regularly to ensure they are necessary. Exclusions: {', '.join(str(e) for e in exclusion_preview)}{'...' if exclusion_count > 10 else ''}",
                                    severity="medium",
                                    evidence={
                                        "source": "local_security_scanner",
                                        "setting": "Exclusions",
                                        "exclusion_count": exclusion_count,
                                        "exclusions": exclusion_preview,
                                    },
                                    recommendation="Review Windows Defender exclusions regularly in Windows Security > Virus & threat protection > Exclusions. Remove any unnecessary exclusions to ensure full protection coverage.",
                                    mitre_ids=["T1562.001"],
                                )
                            )
                    
        except Exception as e:
            # PowerShell might not be available or Defender module not loaded
            findings.append(
                Finding(
                    title="Windows Defender Status Check Failed",
                    description=f"Could not query Windows Defender status: {str(e)}",
                    severity="warning",
                    evidence={"error": str(e), "source": "local_security_scanner"},
                )
            )
    
        return findings
    
    def _check_device_security(self, config: dict[str, Any]) -> list[Finding]:
        """Check device security settings (Memory integrity, Secure Boot, TPM, etc.)."""
        findings: list[Finding] = []
        
        try:
            import json
            
            # Check Memory integrity (Core isolation)
            if config.get("check_memory_integrity", True):
                ps_cmd = """
                try {
                    $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
                    $enabled = (Get-ItemProperty -Path $regPath -Name "Enabled" -ErrorAction SilentlyContinue).Enabled
                    if ($enabled -eq $null) { $enabled = 0 }
                    @{MemoryIntegrityEnabled = ($enabled -eq 1)} | ConvertTo-Json
                } catch {
                    @{MemoryIntegrityEnabled = $false, Error = $_.Exception.Message} | ConvertTo-Json
                }
                """
                
                cmd = ["powershell", "-Command", ps_cmd]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    if not status.get("MemoryIntegrityEnabled", False):
                        findings.append(
                            Finding(
                                title="Memory Integrity (Core Isolation) is Disabled",
                                description="Memory integrity is disabled. This leaves the system vulnerable to kernel-level attacks that insert malicious code into high-security processes.",
                                severity="high",
                                evidence={"source": "local_security_scanner", "setting": "MemoryIntegrity"},
                                recommendation="Enable Memory integrity in Windows Security > Device security > Core isolation to protect against kernel-level attacks.",
                                mitre_ids=["T1562.001"],
                            )
                        )
            
            # Check Secure Boot
            if config.get("check_secure_boot", True):
                ps_cmd = """
                try {
                    $secureBoot = Confirm-SecureBootUEFI -ErrorAction SilentlyContinue
                    @{SecureBootEnabled = $secureBoot} | ConvertTo-Json
                } catch {
                    @{SecureBootEnabled = $false, Error = $_.Exception.Message} | ConvertTo-Json
                }
                """
                
                cmd = ["powershell", "-Command", ps_cmd]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    if not status.get("SecureBootEnabled", False):
                        findings.append(
                            Finding(
                                title="Secure Boot is Disabled",
                                description="Secure Boot is disabled. This allows malicious software to load during system startup.",
                                severity="high",
                                evidence={"source": "local_security_scanner", "setting": "SecureBoot"},
                                recommendation="Enable Secure Boot in BIOS/UEFI settings to prevent unauthorized software from loading at boot time.",
                            )
                        )
            
            # Check TPM
            if config.get("check_tpm", True):
                ps_cmd = """
                try {
                    $tpm = Get-Tpm -ErrorAction SilentlyContinue
                    @{TPMEnabled = ($tpm -ne $null -and $tpm.TpmPresent -and $tpm.TpmReady)} | ConvertTo-Json
                } catch {
                    @{TPMEnabled = $false, Error = $_.Exception.Message} | ConvertTo-Json
                }
                """
                
                cmd = ["powershell", "-Command", ps_cmd]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    if not status.get("TPMEnabled", False):
                        findings.append(
                            Finding(
                                title="TPM (Trusted Platform Module) is Not Available or Not Ready",
                                description="TPM is not available or not ready. This prevents use of hardware-based encryption and secure boot features.",
                                severity="medium",
                                evidence={"source": "local_security_scanner", "setting": "TPM"},
                                recommendation="Ensure TPM is enabled in BIOS/UEFI settings and that it is initialized and ready.",
                            )
                        )
            
            # Check LSA Protection
            if config.get("check_lsa_protection", True):
                ps_cmd = """
                try {
                    $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa"
                    $lsaCfgFlags = (Get-ItemProperty -Path $regPath -Name "LsaCfgFlags" -ErrorAction SilentlyContinue).LsaCfgFlags
                    if ($lsaCfgFlags -eq $null) { $lsaCfgFlags = 0 }
                    @{LSAProtectionEnabled = ($lsaCfgFlags -eq 1 -or $lsaCfgFlags -eq 2)} | ConvertTo-Json
                } catch {
                    @{LSAProtectionEnabled = $false, Error = $_.Exception.Message} | ConvertTo-Json
                }
                """
                
                cmd = ["powershell", "-Command", ps_cmd]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    if not status.get("LSAProtectionEnabled", False):
                        findings.append(
                            Finding(
                                title="Local Security Authority (LSA) Protection is Disabled",
                                description="LSA Protection is disabled. This allows unsigned drivers and plugins to load into LSA, potentially compromising credential security.",
                                severity="high",
                                evidence={"source": "local_security_scanner", "setting": "LSAProtection"},
                                recommendation="Enable LSA Protection in Windows Security > Device security > Core isolation to protect user credentials.",
                            )
                        )
            
            # Check Vulnerable Driver Blocklist
            if config.get("check_vulnerable_driver_blocklist", True):
                ps_cmd = """
                try {
                    $regPath = "HKLM:\\SYSTEM\\CurrentControlSet\\Control\\CI\\Config"
                    $enabled = (Get-ItemProperty -Path $regPath -Name "VulnerableDriverBlocklistEnable" -ErrorAction SilentlyContinue).VulnerableDriverBlocklistEnable
                    if ($enabled -eq $null) { $enabled = 1 }  # Default is enabled
                    @{VulnerableDriverBlocklistEnabled = ($enabled -eq 1)} | ConvertTo-Json
                } catch {
                    @{VulnerableDriverBlocklistEnabled = $true} | ConvertTo-Json  # Assume enabled if can't check
                }
                """
                
                cmd = ["powershell", "-Command", ps_cmd]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    if not status.get("VulnerableDriverBlocklistEnabled", True):
                        findings.append(
                            Finding(
                                title="Microsoft Vulnerable Driver Blocklist is Disabled",
                                description="The Microsoft Vulnerable Driver Blocklist is disabled. This allows drivers with known security vulnerabilities to run on the system.",
                                severity="high",
                                evidence={"source": "local_security_scanner", "setting": "VulnerableDriverBlocklist"},
                                recommendation="Enable Microsoft Vulnerable Driver Blocklist to prevent vulnerable drivers from loading.",
                            )
                        )
                    
        except Exception as e:
            findings.append(
                Finding(
                    title="Device Security Status Check Failed",
                    description=f"Could not query device security status: {str(e)}",
                    severity="warning",
                    evidence={"error": str(e), "source": "local_security_scanner"},
                )
            )
        
        return findings
    
    def _check_exploit_protection(self, config: dict[str, Any]) -> list[Finding]:
        """Check Exploit Protection settings."""
        findings: list[Finding] = []
        
        try:
            import json
            # Use Get-ProcessMitigation to check system-level exploit protection settings
            ps_cmd = """
            try {
                $mitigation = Get-ProcessMitigation -System
                @{
                    CFG = ($mitigation.CFG -ne 'Off' -and $mitigation.CFG -ne $null)
                    DEP = ($mitigation.DEP -ne 'Off' -and $mitigation.DEP -ne $null)
                    MandatoryASLR = ($mitigation.ForceRelocateImages -ne 'Off' -and $mitigation.ForceRelocateImages -ne $null)
                    BottomUpASLR = ($mitigation.BottomUp -ne 'Off' -and $mitigation.BottomUp -ne $null)
                    HighEntropyASLR = ($mitigation.HighEntropy -ne 'Off' -and $mitigation.HighEntropy -ne $null)
                    SEHOP = ($mitigation.SEHOP -ne 'Off' -and $mitigation.SEHOP -ne $null)
                    HeapTerminate = ($mitigation.HeapTerminate -ne 'Off' -and $mitigation.HeapTerminate -ne $null)
                } | ConvertTo-Json
            } catch {
                @{Error = $_.Exception.Message} | ConvertTo-Json
            }
            """
            
            cmd = ["powershell", "-Command", ps_cmd]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            
            if result.returncode == 0:
                mitigation_status = json.loads(result.stdout)
                
                checks = {
                    "CFG": ("Control Flow Guard (CFG)", config.get("check_cfg", True)),
                    "DEP": ("Data Execution Prevention (DEP)", config.get("check_dep", True)),
                    "MandatoryASLR": ("Force randomization for images (Mandatory ASLR)", config.get("check_mandatory_aslr", True)),
                    "BottomUpASLR": ("Randomize memory allocations (Bottom-up ASLR)", config.get("check_bottom_up_aslr", True)),
                    "HighEntropyASLR": ("High-entropy ASLR", config.get("check_high_entropy_aslr", True)),
                    "SEHOP": ("Validate exception chains (SEHOP)", config.get("check_sehop", True)),
                    "HeapTerminate": ("Validate heap integrity", config.get("check_heap_integrity", True)),
                }
                
                for setting_key, (setting_name, should_check) in checks.items():
                    if should_check and not mitigation_status.get(setting_key, False):
                        findings.append(
                            Finding(
                                title=f"Exploit Protection: {setting_name} is Disabled",
                                description=f"{setting_name} is disabled or set to 'Off'. This reduces protection against exploit attacks.",
                                severity="medium",
                                evidence={"source": "local_security_scanner", "setting": setting_key},
                                recommendation=f"Enable {setting_name} in Windows Security > App & browser control > Exploit protection settings.",
                            )
                        )
                    
        except Exception as e:
            findings.append(
                Finding(
                    title="Exploit Protection Status Check Failed",
                    description=f"Could not query exploit protection status: {str(e)}",
                    severity="warning",
                    evidence={"error": str(e), "source": "local_security_scanner"},
                )
            )
        
        return findings
    
    def _check_app_browser_control(self, config: dict[str, Any]) -> list[Finding]:
        """Check App & Browser Control settings (SmartScreen, PUA blocking, etc.)."""
        findings: list[Finding] = []
        
        try:
            import json
            # Check SmartScreen for apps and files
            if config.get("check_smartscreen_apps", True):
                ps_cmd = """
                try {
                    $regPath = "HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer"
                    $smartscreen = (Get-ItemProperty -Path $regPath -Name "SmartScreenEnabled" -ErrorAction SilentlyContinue).SmartScreenEnabled
                    if ($smartscreen -eq $null) { $smartscreen = "Warn" }  # Default is Warn
                    @{SmartScreenApps = ($smartscreen -ne "Off")} | ConvertTo-Json
                } catch {
                    @{SmartScreenApps = $true} | ConvertTo-Json
                }
                """
                
                cmd = ["powershell", "-Command", ps_cmd]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    if not status.get("SmartScreenApps", True):
                        findings.append(
                            Finding(
                                title="SmartScreen for Apps and Files is Disabled",
                                description="SmartScreen for apps and files is disabled. This reduces protection against unrecognized or malicious apps downloaded from the web.",
                                severity="high",
                                evidence={"source": "local_security_scanner", "setting": "SmartScreenApps"},
                                recommendation="Enable SmartScreen for apps and files in Windows Security > App & browser control > Reputation-based protection.",
                            )
                        )
            
            # Check SmartScreen for Microsoft Edge
            if config.get("check_smartscreen_edge", True):
                ps_cmd = """
                try {
                    $regPath = "HKLM:\\SOFTWARE\\Policies\\Microsoft\\MicrosoftEdge\\PhishingFilter"
                    $enabled = (Get-ItemProperty -Path $regPath -Name "EnabledV9" -ErrorAction SilentlyContinue).EnabledV9
                    if ($enabled -eq $null) {
                        $regPath2 = "HKCU:\\Software\\Microsoft\\Edge\\PhishingFilter"
                        $enabled = (Get-ItemProperty -Path $regPath2 -Name "EnabledV9" -ErrorAction SilentlyContinue).EnabledV9
                    }
                    if ($enabled -eq $null) { $enabled = 1 }  # Default is enabled
                    @{SmartScreenEdge = ($enabled -eq 1)} | ConvertTo-Json
                } catch {
                    @{SmartScreenEdge = $true} | ConvertTo-Json
                }
                """
                
                cmd = ["powershell", "-Command", ps_cmd]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    if not status.get("SmartScreenEdge", True):
                        findings.append(
                            Finding(
                                title="SmartScreen for Microsoft Edge is Disabled",
                                description="SmartScreen for Microsoft Edge is disabled. This reduces protection against malicious sites and downloads.",
                                severity="medium",
                                evidence={"source": "local_security_scanner", "setting": "SmartScreenEdge"},
                                recommendation="Enable SmartScreen for Microsoft Edge in Windows Security > App & browser control > Reputation-based protection.",
                            )
                        )
            
            # Check PUA (Potentially Unwanted App) blocking
            if config.get("check_pua_blocking", True):
                ps_cmd = """
                try {
                    $prefs = Get-MpPreference -ErrorAction SilentlyContinue
                    @{PUABlocking = $prefs.PUAProtection -eq 1} | ConvertTo-Json
                } catch {
                    @{PUABlocking = $false, Error = $_.Exception.Message} | ConvertTo-Json
                }
                """
                
                cmd = ["powershell", "-Command", ps_cmd]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
                
                if result.returncode == 0:
                    status = json.loads(result.stdout)
                    if not status.get("PUABlocking", False):
                        findings.append(
                            Finding(
                                title="Potentially Unwanted App (PUA) Blocking is Disabled",
                                description="PUA blocking is disabled. This allows low-reputation apps that might cause unexpected behaviors to run.",
                                severity="medium",
                                evidence={"source": "local_security_scanner", "setting": "PUABlocking"},
                                recommendation="Enable PUA blocking in Windows Security > App & browser control > Reputation-based protection.",
                            )
                        )
                    
        except Exception as e:
            findings.append(
                Finding(
                    title="App & Browser Control Status Check Failed",
                    description=f"Could not query app & browser control status: {str(e)}",
                    severity="warning",
                    evidence={"error": str(e), "source": "local_security_scanner"},
                )
            )
        
        return findings
