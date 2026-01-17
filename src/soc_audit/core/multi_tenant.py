"""Multi-Tenant Support.

Phase 17.1: Enterprise & Scale
- Org / environment isolation
- Tenant-specific RBAC
"""
from __future__ import annotations

from typing import Any


class TenantContext:
    """
    Tenant context for multi-tenant isolation.
    
    Phase 17.1: Represents a tenant (organization/environment).
    """
    
    def __init__(self, tenant_id: str, tenant_name: str, metadata: dict[str, Any] | None = None):
        """
        Initialize tenant context.
        
        Args:
            tenant_id: Unique tenant identifier.
            tenant_name: Human-readable tenant name.
            metadata: Optional tenant metadata.
        """
        self.tenant_id = tenant_id
        self.tenant_name = tenant_name
        self.metadata = metadata or {}


class MultiTenantManager:
    """
    Multi-tenant manager for org/environment isolation.
    
    Phase 17.1: Manages tenant isolation and tenant-specific configurations.
    """
    
    def __init__(self):
        """Initialize multi-tenant manager."""
        self.tenants: dict[str, TenantContext] = {}
        self.tenant_rbac: dict[str, dict[str, list[str]]] = {}  # tenant_id -> role -> operations
    
    def register_tenant(
        self,
        tenant_id: str,
        tenant_name: str,
        metadata: dict[str, Any] | None = None,
    ) -> TenantContext:
        """
        Register a new tenant.
        
        Phase 17.1: Creates tenant context with isolation.
        
        Args:
            tenant_id: Unique tenant identifier.
            tenant_name: Human-readable tenant name.
            metadata: Optional tenant metadata.
        
        Returns:
            TenantContext instance.
        """
        tenant = TenantContext(tenant_id, tenant_name, metadata)
        self.tenants[tenant_id] = tenant
        return tenant
    
    def get_tenant(self, tenant_id: str) -> TenantContext | None:
        """Get tenant by ID."""
        return self.tenants.get(tenant_id)
    
    def set_tenant_rbac(
        self,
        tenant_id: str,
        role: str,
        allowed_operations: list[str],
    ) -> None:
        """
        Set tenant-specific RBAC rules.
        
        Phase 17.1: Allows per-tenant role customization.
        
        Args:
            tenant_id: Tenant identifier.
            role: Role name (agent, analyst, admin).
            allowed_operations: List of allowed operations for this role.
        """
        if tenant_id not in self.tenant_rbac:
            self.tenant_rbac[tenant_id] = {}
        self.tenant_rbac[tenant_id][role] = allowed_operations
    
    def check_tenant_access(
        self,
        tenant_id: str,
        role: str,
        operation: str,
    ) -> bool:
        """
        Check if role has access to operation in tenant.
        
        Phase 17.1: Validates tenant-specific permissions.
        
        Args:
            tenant_id: Tenant identifier.
            role: User role.
            operation: Operation to check.
        
        Returns:
            True if allowed, False otherwise.
        """
        if tenant_id not in self.tenant_rbac:
            return True  # Default: allow if no tenant-specific rules
        
        tenant_roles = self.tenant_rbac[tenant_id]
        if role not in tenant_roles:
            return True  # Default: allow if role not restricted
        
        return operation in tenant_roles[role]
