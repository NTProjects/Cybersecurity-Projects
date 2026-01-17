"""Dependency injection functions for FastAPI routes."""
from __future__ import annotations

from fastapi import Request

from soc_audit.server.audit_log import AuditLogger
from soc_audit.server.incident_engine import ServerIncidentEngine
from soc_audit.server.storage import BackendStorage
from soc_audit.server.ws_manager import WebSocketManager


def get_storage(request: Request) -> BackendStorage:
    """Get storage instance from app state."""
    return request.app.state.storage


def get_incident_engine(request: Request) -> ServerIncidentEngine:
    """Get incident engine instance from app state."""
    return request.app.state.incident_engine


def get_ws_manager(request: Request) -> WebSocketManager:
    """Get WebSocket manager instance from app state."""
    return request.app.state.ws_manager


def get_audit_logger(request: Request) -> AuditLogger:
    """Get audit logger instance from app state (Phase 10.2)."""
    return request.app.state.audit_logger
