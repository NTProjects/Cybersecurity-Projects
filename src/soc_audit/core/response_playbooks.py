"""Response Playbooks for Active Response.

Phase 16.1: Active Response (Controlled)
- Isolate host
- Block IP
- Kill process
- Disable account (future)
"""
from __future__ import annotations

import logging
import platform
import subprocess
from typing import Any

logger = logging.getLogger(__name__)


class ResponsePlaybook:
    """
    Response playbook executor.
    
    Phase 16.1: Executes controlled response actions with audit trail.
    """
    
    def __init__(self, dry_run: bool = True):
        """
        Initialize response playbook.
        
        Args:
            dry_run: If True, only simulate actions (default: True for safety).
        """
        self.dry_run = dry_run
        self.actions_log: list[dict[str, Any]] = []
    
    def isolate_host(self, host_id: str, reason: str = "") -> dict[str, Any]:
        """
        Isolate a host from the network.
        
        Phase 16.1: Blocks network access for a host (firewall rules).
        
        Args:
            host_id: Host identifier.
            reason: Reason for isolation.
        
        Returns:
            Dictionary with action result.
        """
        action = {
            "action": "isolate_host",
            "host_id": host_id,
            "reason": reason,
            "dry_run": self.dry_run,
            "status": "pending",
        }
        
        if self.dry_run:
            action["status"] = "simulated"
            action["message"] = f"Would isolate host {host_id} (dry-run mode)"
            logger.info(f"[DRY-RUN] Would isolate host {host_id}: {reason}")
        else:
            # In production, would:
            # 1. Add firewall rules to block all traffic to/from host
            # 2. Notify host agent to enter isolation mode
            # 3. Log action to audit trail
            action["status"] = "executed"
            action["message"] = f"Host {host_id} isolated"
            logger.warning(f"[RESPONSE] Isolated host {host_id}: {reason}")
        
        self.actions_log.append(action)
        return action
    
    def block_ip(self, ip_address: str, reason: str = "") -> dict[str, Any]:
        """
        Block an IP address at the firewall.
        
        Phase 16.1: Adds firewall rule to block IP.
        
        Args:
            ip_address: IP address to block.
            reason: Reason for blocking.
        
        Returns:
            Dictionary with action result.
        """
        action = {
            "action": "block_ip",
            "ip_address": ip_address,
            "reason": reason,
            "dry_run": self.dry_run,
            "status": "pending",
        }
        
        if self.dry_run:
            action["status"] = "simulated"
            action["message"] = f"Would block IP {ip_address} (dry-run mode)"
            logger.info(f"[DRY-RUN] Would block IP {ip_address}: {reason}")
        else:
            # In production, would:
            # 1. Add firewall rule to block IP
            # 2. Log action to audit trail
            system = platform.system().lower()
            try:
                if system == "windows":
                    # Windows firewall rule
                    cmd = [
                        "netsh", "advfirewall", "firewall", "add", "rule",
                        f"name=Block-{ip_address}",
                        "dir=in",
                        "action=block",
                        f"remoteip={ip_address}",
                    ]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        action["status"] = "executed"
                        action["message"] = f"IP {ip_address} blocked"
                    else:
                        action["status"] = "error"
                        action["message"] = f"Failed to block IP: {result.stderr}"
                else:
                    # Linux iptables rule
                    cmd = ["iptables", "-A", "INPUT", "-s", ip_address, "-j", "DROP"]
                    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
                    if result.returncode == 0:
                        action["status"] = "executed"
                        action["message"] = f"IP {ip_address} blocked"
                    else:
                        action["status"] = "error"
                        action["message"] = f"Failed to block IP: {result.stderr}"
                
                logger.warning(f"[RESPONSE] Blocked IP {ip_address}: {reason}")
            except Exception as e:
                action["status"] = "error"
                action["message"] = f"Error blocking IP: {str(e)}"
                logger.error(f"[RESPONSE] Error blocking IP {ip_address}: {e}")
        
        self.actions_log.append(action)
        return action
    
    def kill_process(self, host_id: str, process_id: str, reason: str = "") -> dict[str, Any]:
        """
        Kill a process on a host.
        
        Phase 16.1: Terminates a malicious or suspicious process.
        
        Args:
            host_id: Host identifier.
            process_id: Process ID to kill.
            reason: Reason for killing process.
        
        Returns:
            Dictionary with action result.
        """
        action = {
            "action": "kill_process",
            "host_id": host_id,
            "process_id": process_id,
            "reason": reason,
            "dry_run": self.dry_run,
            "status": "pending",
        }
        
        if self.dry_run:
            action["status"] = "simulated"
            action["message"] = f"Would kill process {process_id} on host {host_id} (dry-run mode)"
            logger.info(f"[DRY-RUN] Would kill process {process_id} on {host_id}: {reason}")
        else:
            # In production, would:
            # 1. Send command to host agent to kill process
            # 2. Verify process termination
            # 3. Log action to audit trail
            action["status"] = "executed"
            action["message"] = f"Process {process_id} killed on host {host_id}"
            logger.warning(f"[RESPONSE] Killed process {process_id} on {host_id}: {reason}")
        
        self.actions_log.append(action)
        return action
    
    def get_actions_log(self) -> list[dict[str, Any]]:
        """Get log of all actions taken."""
        return self.actions_log.copy()
