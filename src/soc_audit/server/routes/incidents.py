"""Incidents API endpoints."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from soc_audit.server.auth import get_role_from_request
from soc_audit.server.deps import get_storage, get_ws_manager
from soc_audit.server.rbac import require_analyst_or_admin, require_admin
from soc_audit.server.schemas import IncidentSchema, NoteRequest
from soc_audit.server.schemas.incident_metrics import IncidentMetricsResponse
from soc_audit.server.storage import BackendStorage
from soc_audit.server.ws_manager import WebSocketManager

router = APIRouter(prefix="/api/v1/incidents", tags=["incidents"])


@router.get("/", response_model=list[IncidentSchema])
async def list_incidents(
    request: Request,
    role: str = require_analyst_or_admin("read_incidents"),  # Phase 10.1: Enforce RBAC
    host_id: str | None = Query(None),
    status: str | None = Query(None),
    storage: BackendStorage = Depends(get_storage),
):
    """
    List incidents with optional filters.
    
    Phase 10.1: Requires analyst or admin role.
    """
    filters: dict[str, Any] = {}
    if host_id:
        filters["host_id"] = host_id
    if status:
        filters["status"] = status

    incidents = storage.list_incidents(filters)
    return incidents


@router.get("/{incident_id}", response_model=IncidentSchema)
async def get_incident(
    incident_id: str,
    request: Request,
    role: str = require_analyst_or_admin("read_incidents"),  # Phase 10.1: Enforce RBAC
    storage: BackendStorage = Depends(get_storage),
):
    """
    Get a specific incident by ID.
    
    Phase 10.1: Requires analyst or admin role.
    """
    incident = storage.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return incident


@router.post("/{incident_id}/close", response_model=IncidentSchema)
async def close_incident(
    incident_id: str,
    request: Request,
    role: str = require_admin("close_incidents"),  # Phase 10.1: Enforce RBAC - admin only
    storage: BackendStorage = Depends(get_storage),
    ws_manager: WebSocketManager = Depends(get_ws_manager),
):
    """
    Close an incident.

    Phase 10.1: Requires admin role (explicitly denied for analyst).
    """

    incident = storage.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Update status
    storage.update_incident_status(incident_id, status="closed")

    # Append timeline
    storage.append_timeline(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "message": f"Incident closed: {incident.get('title', incident_id)}",
            "level": "info",
            "source": "api",
            "module": incident.get("entity_summary", {}).get("module", "unknown"),
            "incident_id": incident_id,
            "host_id": incident.get("host_id"),
        }
    )

    # Phase 11.1: Broadcast update with event type for subscription filtering
    updated_incident = storage.get_incident(incident_id)
    if ws_manager and updated_incident:
        await ws_manager.broadcast_json({"type": "incident", "data": updated_incident}, event_type="incident")

    return updated_incident


@router.get("/metrics", response_model=IncidentMetricsResponse)
async def get_incident_metrics(
    request: Request,
    role: str = require_analyst_or_admin("view_metrics"),  # Phase 10.1: Enforce RBAC
    storage: BackendStorage = Depends(get_storage),
):
    """
    Phase 9.2: Get incident lifecycle metrics (MTTR, aging buckets).
    
    Phase 10.1: Requires analyst or admin role.
    """
    metrics = storage.get_incident_metrics()
    return IncidentMetricsResponse(**metrics)


@router.post("/{incident_id}/note", response_model=IncidentSchema)
async def add_incident_note(
    incident_id: str,
    request: Request,
    note_request: NoteRequest,
    role: str = require_analyst_or_admin("add_incident_notes"),  # Phase 10.1: Enforce RBAC
    storage: BackendStorage = Depends(get_storage),
    ws_manager: WebSocketManager = Depends(get_ws_manager),
):
    """
    Add a note to an incident.

    Phase 10.1: Requires analyst or admin role.
    """
    incident = storage.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")

    # Add note
    storage.add_incident_note(incident_id, note_request.note)

    # Append timeline
    storage.append_timeline(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "message": f"Note added to incident: {incident.get('title', incident_id)}",
            "level": "info",
            "source": "api",
            "module": incident.get("entity_summary", {}).get("module", "unknown"),
            "incident_id": incident_id,
            "host_id": incident.get("host_id"),
        }
    )

    # Phase 11.1: Broadcast update with event type for subscription filtering
    updated_incident = storage.get_incident(incident_id)
    if ws_manager and updated_incident:
        await ws_manager.broadcast_json({"type": "incident", "data": updated_incident}, event_type="incident")

    return updated_incident
