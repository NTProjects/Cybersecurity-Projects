"""RBAC (Role-Based Access Control) enforcement for SOC Audit Server.

Phase 10.1: Enterprise RBAC Hardening
- Enforce role checks per endpoint
- Explicit deny rules
- Role matrix documentation
- Remove "role awareness without enforcement"
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import Depends, HTTPException, Request

from soc_audit.server.auth import get_role_from_request


# Role hierarchy: higher number = more permissions
ROLE_HIERARCHY: dict[str, int] = {
    "agent": 0,      # Can only send heartbeats and ingest alerts
    "analyst": 1,    # Can read alerts/incidents, acknowledge alerts, add notes
    "admin": 2,      # Full access including suppression, incident closure, reports
}

# Explicit deny rules: operations that require explicit permission
DENY_RULES: dict[str, list[str]] = {
    "agent": ["read_alerts", "read_incidents", "read_hosts", "ack_alerts", "suppress_alerts", "close_incidents", "view_reports"],
    "analyst": ["suppress_alerts", "close_incidents"],  # Analysts cannot suppress or close
}


def require_role(
    min_role: Literal["agent", "analyst", "admin"],
    operation: str | None = None,
):
    """
    FastAPI dependency factory to enforce RBAC with explicit deny rules.
    
    Phase 10.1: Hardened RBAC enforcement with explicit deny rules.
    
    Args:
        min_role: Minimum required role ("agent", "analyst", or "admin").
        operation: Optional operation name for explicit deny rule checking.
    
    Returns:
        FastAPI dependency that checks role and returns role string.
    
    Raises:
        HTTPException 401: If authentication fails.
        HTTPException 403: If role is insufficient or operation is denied.
    """
    async def role_checker(request: Request) -> str:
        # Get role from request
        role = get_role_from_request(request)
        
        # Check role hierarchy
        user_level = ROLE_HIERARCHY.get(role, -1)
        required_level = ROLE_HIERARCHY.get(min_role, 999)
        
        if user_level < required_level:
            raise HTTPException(
                status_code=403,
                detail=f"Requires {min_role} role or higher (current: {role})"
            )
        
        # Phase 10.1: Explicit deny rules - check if operation is explicitly denied for this role
        if operation and role in DENY_RULES:
            if operation in DENY_RULES[role]:
                raise HTTPException(
                    status_code=403,
                    detail=f"Operation '{operation}' is explicitly denied for role '{role}'"
                )
        
        return role
    
    return Depends(role_checker)


def require_analyst_or_admin(operation: str | None = None) -> Any:
    """Convenience dependency: requires analyst or admin role."""
    return require_role("analyst", operation)


def require_admin(operation: str | None = None) -> Any:
    """Convenience dependency: requires admin role."""
    return require_role("admin", operation)


def require_agent_or_admin(operation: str | None = None) -> Any:
    """Convenience dependency: requires agent or admin role."""
    return require_role("agent", operation)


# Phase 10.1: Role Matrix Documentation
ROLE_MATRIX = {
    "agent": {
        "allowed_operations": [
            "send_heartbeat",
            "ingest_alerts",
            "ingest_batch_alerts",
        ],
        "denied_operations": [
            "read_alerts",
            "read_incidents",
            "read_hosts",
            "ack_alerts",
            "suppress_alerts",
            "close_incidents",
            "view_reports",
            "add_incident_notes",
        ],
    },
    "analyst": {
        "allowed_operations": [
            "read_alerts",
            "read_incidents",
            "read_hosts",
            "ack_alerts",
            "add_incident_notes",
            "view_reports",
            "view_metrics",
        ],
        "denied_operations": [
            "suppress_alerts",
            "close_incidents",
        ],
    },
    "admin": {
        "allowed_operations": [
            "read_alerts",
            "read_incidents",
            "read_hosts",
            "ack_alerts",
            "suppress_alerts",
            "close_incidents",
            "add_incident_notes",
            "view_reports",
            "view_metrics",
            "ingest_alerts",
            "send_heartbeat",
        ],
        "denied_operations": [],
    },
}
