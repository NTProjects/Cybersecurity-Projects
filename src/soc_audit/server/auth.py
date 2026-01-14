"""Authentication and RBAC for SOC Audit Server."""
from __future__ import annotations

from typing import Any, Literal

from fastapi import HTTPException, Request, Security
from fastapi.security import APIKeyHeader

from soc_audit.core.config import load_config

# API key header
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


def get_auth_config(config_path: str | None = None) -> dict[str, Any]:
    """Load auth configuration from config file."""
    if config_path:
        try:
            config = load_config(config_path)
            backend_config = config.get("backend", {})
            return backend_config.get("auth", {})
        except Exception:
            pass
    return {"enabled": False, "keys": []}


def get_role_from_request(
    request: Request,
    auth_config: dict[str, Any] | None = None,
    config_path: str | None = None,
) -> str:
    """
    Extract role from API key in request header.

    Args:
        request: FastAPI request object.
        auth_config: Optional auth config dict.
        config_path: Optional path to config file.

    Returns:
        Role string ("analyst" or "admin").

    Raises:
        HTTPException: If authentication fails.
    """
    if auth_config is None:
        auth_config = get_auth_config(config_path)

    if not auth_config.get("enabled", False):
        # Auth disabled - default to admin for development
        return "admin"

    # Get API key from header
    api_key = request.headers.get("X-API-Key")
    if not api_key:
        raise HTTPException(status_code=401, detail="Missing API key")

    # Check keys
    keys = auth_config.get("keys", [])
    for key_config in keys:
        if key_config.get("key") == api_key:
            return key_config.get("role", "analyst")

    raise HTTPException(status_code=401, detail="Invalid API key")


def require_role(
    min_role: Literal["analyst", "admin"],
    auth_config: dict[str, Any] | None = None,
    config_path: str | None = None,
):
    """
    FastAPI dependency to enforce RBAC.

    Args:
        min_role: Minimum required role ("analyst" or "admin").
        auth_config: Optional auth config dict.
        config_path: Optional path to config file.

    Returns:
        Dependency function that checks role.
    """
    role_hierarchy = {"analyst": 0, "admin": 1}

    async def role_checker(request: Request) -> str:
        role = get_role_from_request(request, auth_config, config_path)
        if role_hierarchy.get(role, 0) < role_hierarchy.get(min_role, 0):
            raise HTTPException(
                status_code=403, detail=f"Requires {min_role} role or higher"
            )
        return role

    return role_checker


def get_role_from_websocket(websocket, auth_config: dict[str, Any] | None = None) -> str:
    """
    Extract role from API key in WebSocket connection.

    Reads API key from query parameter (?api_key=...) or header (X-API-Key).
    Validates against backend.auth.keys from config.

    Args:
        websocket: FastAPI WebSocket connection object.
        auth_config: Optional auth config dict.

    Returns:
        Role string ("analyst" or "admin").

    Raises:
        WebSocketDisconnect: If authentication fails (code 4401).
    """
    from fastapi import WebSocketDisconnect

    if auth_config is None:
        # Try to get from app state if available
        try:
            if hasattr(websocket, "app") and hasattr(websocket.app, "state"):
                if hasattr(websocket.app.state, "config"):
                    auth_config = websocket.app.state.config.get("auth", {})
        except Exception:
            pass

        if auth_config is None:
            auth_config = get_auth_config()

    if not auth_config.get("enabled", False):
        # Auth disabled - default to admin for development
        return "admin"

    # Try to get API key from query parameters first (accessible before accept)
    api_key = None
    try:
        # websocket.url.query is available before accept()
        query_string = websocket.url.query
        if query_string:
            params = dict(param.split("=", 1) for param in query_string.split("&") if "=" in param)
            api_key = params.get("api_key")
    except Exception:
        pass

    # Fallback to header if not in query (headers may require accept first)
    if not api_key:
        try:
            # Try to access headers (may not work before accept in some FastAPI versions)
            headers = getattr(websocket, "headers", None)
            if headers:
                # Headers might be dict or list of tuples
                if isinstance(headers, dict):
                    api_key = headers.get("x-api-key") or headers.get("X-API-Key")
                elif isinstance(headers, (list, tuple)):
                    headers_dict = dict(headers)
                    api_key = headers_dict.get("x-api-key") or headers_dict.get("X-API-Key")
        except Exception:
            pass

    if not api_key:
        # No API key provided - disconnect
        raise WebSocketDisconnect(code=4401)

    # Check keys
    keys = auth_config.get("keys", [])
    for key_config in keys:
        if key_config.get("key") == api_key:
            return key_config.get("role", "analyst")

    # Invalid API key - disconnect
    raise WebSocketDisconnect(code=4401)


def get_role_from_api_key(
    api_key: str | None, auth_config: dict[str, Any] | None = None
) -> str | None:
    """
    Get role from API key (helper function).

    Args:
        api_key: API key string.
        auth_config: Optional auth config dict.

    Returns:
        Role string or None if invalid.
    """
    if not auth_config:
        auth_config = get_auth_config()

    if not auth_config.get("enabled", False):
        return "admin"  # Default for development

    if not api_key:
        return None

    keys = auth_config.get("keys", [])
    for key_config in keys:
        if key_config.get("key") == api_key:
            return key_config.get("role", "analyst")

    return None
