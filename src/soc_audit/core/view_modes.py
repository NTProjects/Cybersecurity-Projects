"""Analyst & Auditor View Modes.

Phase 18.2: SOC Command Platform
- SOC view
- Audit-only read mode
- Evidence export mode
"""
from __future__ import annotations

from typing import Any


class ViewMode:
    """View mode configuration."""
    
    SOC_VIEW = "soc_view"  # Full SOC analyst view
    AUDIT_READ_ONLY = "audit_read_only"  # Audit-only read mode
    EVIDENCE_EXPORT = "evidence_export"  # Evidence export mode


class ViewModeManager:
    """
    Manages view modes for different user roles.
    
    Phase 18.2: Provides role-appropriate views and capabilities.
    """
    
    def __init__(self):
        """Initialize view mode manager."""
        self.mode_capabilities = {
            ViewMode.SOC_VIEW: {
                "read_alerts": True,
                "read_incidents": True,
                "ack_alerts": True,
                "suppress_alerts": False,  # Admin only
                "close_incidents": False,  # Admin only
                "execute_response": False,  # Admin only
                "export_evidence": True,
            },
            ViewMode.AUDIT_READ_ONLY: {
                "read_alerts": True,
                "read_incidents": True,
                "read_hosts": True,
                "read_reports": True,
                "ack_alerts": False,
                "suppress_alerts": False,
                "close_incidents": False,
                "execute_response": False,
                "export_evidence": True,
            },
            ViewMode.EVIDENCE_EXPORT: {
                "read_alerts": True,
                "read_incidents": True,
                "read_incidents": True,
                "read_hosts": True,
                "read_reports": True,
                "export_evidence": True,
                "ack_alerts": False,
                "suppress_alerts": False,
                "close_incidents": False,
                "execute_response": False,
            },
        }
    
    def get_mode_for_role(self, role: str) -> str:
        """
        Get appropriate view mode for role.
        
        Phase 18.2: Maps roles to view modes.
        
        Args:
            role: User role (agent, analyst, admin, auditor).
        
        Returns:
            View mode identifier.
        """
        if role == "auditor":
            return ViewMode.AUDIT_READ_ONLY
        elif role == "analyst":
            return ViewMode.SOC_VIEW
        elif role == "admin":
            return ViewMode.SOC_VIEW  # Admin has full SOC view + additional capabilities
        else:
            return ViewMode.SOC_VIEW  # Default
    
    def can_perform_operation(self, mode: str, operation: str) -> bool:
        """
        Check if operation is allowed in view mode.
        
        Phase 18.2: Validates operation permissions for view mode.
        
        Args:
            mode: View mode identifier.
            operation: Operation to check.
        
        Returns:
            True if allowed, False otherwise.
        """
        capabilities = self.mode_capabilities.get(mode, {})
        return capabilities.get(operation, False)
