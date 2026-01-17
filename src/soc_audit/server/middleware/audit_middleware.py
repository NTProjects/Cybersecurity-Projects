"""Audit logging middleware for automatic request logging.

Phase 10.2: Automatic audit logging for all API requests.
"""
from __future__ import annotations

import hashlib
from typing import Callable

from fastapi import Request, Response
from starlette.middleware.base import BaseHTTPMiddleware

from soc_audit.server.auth import get_role_from_request


def hash_api_key(api_key: str | None) -> str | None:
    """Hash API key for privacy (store hash, not plaintext)."""
    if not api_key:
        return None
    return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]  # First 16 chars


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """
    Middleware to automatically log all API requests to audit log.
    
    Phase 10.2: Logs who, what, when, where for all requests.
    """
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Process request and log to audit trail."""
        # Skip health check and root endpoints
        if request.url.path in ["/", "/health", "/docs", "/openapi.json", "/redoc"]:
            return await call_next(request)
        
        # Get user info (if authenticated)
        user_id = None
        role = None
        try:
            role = get_role_from_request(request)
            # Get API key from header for user_id hash
            api_key = request.headers.get("X-API-Key")
            user_id = hash_api_key(api_key) if api_key else None
        except Exception:
            # Auth failed or not required - log as unauthenticated
            pass
        
        # Determine operation and action from path and method
        operation = self._extract_operation(request)
        action = self._extract_action(request.method)
        object_type, object_id = self._extract_object_info(request)
        
        # Process request
        try:
            response = await call_next(request)
            result = "success" if response.status_code < 400 else "error"
            
            # Log to audit trail
            if hasattr(request.app.state, "audit_logger"):
                try:
                    request.app.state.audit_logger.log(
                        user_id=user_id,
                        role=role or "unknown",
                        operation=operation,
                        action=action,
                        result=result,
                        endpoint=request.url.path,
                        object_type=object_type,
                        object_id=object_id,
                        details={
                            "method": request.method,
                            "status_code": response.status_code,
                            "query_params": dict(request.query_params) if request.query_params else None,
                        },
                    )
                except Exception as e:
                    # Don't fail request if audit logging fails
                    print(f"[AUDIT] Failed to log request: {e}")
            
            return response
        except Exception as e:
            # Log error
            if hasattr(request.app.state, "audit_logger"):
                try:
                    request.app.state.audit_logger.log(
                        user_id=user_id,
                        role=role or "unknown",
                        operation=operation,
                        action=action,
                        result="error",
                        endpoint=request.url.path,
                        object_type=object_type,
                        object_id=object_id,
                        details={
                            "method": request.method,
                            "error": str(e),
                        },
                    )
                except Exception:
                    pass
            raise
    
    def _extract_operation(self, request: Request) -> str:
        """Extract operation name from request path."""
        path = request.url.path
        
        # Map common patterns
        if "/alerts" in path:
            if "/ack" in path:
                return "ack_alert"
            elif "/suppress" in path:
                return "suppress_alert"
            elif request.method == "GET":
                return "read_alerts"
            elif request.method == "POST":
                return "ingest_alerts"
        elif "/incidents" in path:
            if "/close" in path:
                return "close_incident"
            elif "/note" in path:
                return "add_incident_note"
            elif "/metrics" in path:
                return "view_metrics"
            elif request.method == "GET":
                return "read_incidents"
        elif "/hosts" in path:
            return "read_hosts"
        elif "/heartbeat" in path:
            return "send_heartbeat"
        elif "/reports" in path:
            return "view_reports"
        elif "/ingest" in path:
            if "/batch" in path:
                return "ingest_batch_alerts"
            else:
                return "ingest_alerts"
        
        # Fallback
        return f"{request.method.lower()}_{path.replace('/', '_').replace('-', '_')}"
    
    def _extract_action(self, method: str) -> str:
        """Extract action from HTTP method."""
        method_map = {
            "GET": "read",
            "POST": "create",
            "PUT": "update",
            "PATCH": "update",
            "DELETE": "delete",
        }
        return method_map.get(method, method.lower())
    
    def _extract_object_info(self, request: Request) -> tuple[str | None, str | None]:
        """Extract object type and ID from path."""
        path = request.url.path
        
        # Extract object type
        if "/alerts/" in path:
            object_type = "alert"
            # Try to extract alert_id from path
            parts = path.split("/alerts/")
            if len(parts) > 1:
                object_id = parts[1].split("/")[0]
                return object_type, object_id
        elif "/incidents/" in path:
            object_type = "incident"
            parts = path.split("/incidents/")
            if len(parts) > 1:
                object_id = parts[1].split("/")[0]
                return object_type, object_id
        elif "/hosts/" in path:
            object_type = "host"
            parts = path.split("/hosts/")
            if len(parts) > 1:
                object_id = parts[1].split("/")[0]
                return object_type, object_id
        
        return None, None
