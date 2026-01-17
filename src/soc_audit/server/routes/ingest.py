"""Ingest endpoint for alert events."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from soc_audit.server.auth import get_role_from_request
from soc_audit.server.deps import get_incident_engine, get_storage, get_ws_manager
from soc_audit.server.rbac import require_analyst_or_admin
from soc_audit.server.incident_engine import ServerIncidentEngine
from soc_audit.server.schemas import AlertEventSchema, IngestResponse
from soc_audit.server.storage import BackendStorage
from soc_audit.server.ws_manager import WebSocketManager

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


@router.post("/event", response_model=IngestResponse)
async def ingest_event(
    event: AlertEventSchema,
    request: Request,
    role: str = require_analyst_or_admin("ingest_alerts"),  # Phase 10.1: Enforce RBAC
    storage: BackendStorage = Depends(get_storage),
    incident_engine: ServerIncidentEngine = Depends(get_incident_engine),
    ws_manager: WebSocketManager = Depends(get_ws_manager),
):
    """
    Ingest an alert event.

    Phase 10.1: Requires analyst or admin role.
    """

    # Ensure host_id exists
    if not event.host_id:
        raise HTTPException(status_code=400, detail="host_id is required")

    # Add received timestamp
    event_dict = event.model_dump()
    event_dict["received_ts"] = datetime.utcnow().isoformat()

    try:
        # Process through incident engine
        updated_event, incident = incident_engine.ingest_event(event_dict)

        # Save alert
        storage.save_alert(updated_event)

        # Save incident if created/updated
        if incident:
            storage.save_incident(incident)

        # Append timeline entry
        storage.append_timeline(
            {
                "timestamp": datetime.utcnow().isoformat(),
                "message": f"Alert ingested: {updated_event['title']}",
                "level": updated_event.get("severity", "info"),
                "source": updated_event.get("source", "ingest"),
                "module": updated_event.get("module", "unknown"),
                "alert_id": updated_event["id"],
                "incident_id": incident["id"] if incident else None,
                "host_id": updated_event["host_id"],
            }
        )

        # Broadcast WebSocket updates
        if ws_manager:
            await ws_manager.broadcast_json({"type": "alert", "data": updated_event})
            if incident:
                await ws_manager.broadcast_json({"type": "incident", "data": incident})

        return IngestResponse(
            ok=True, alert_id=updated_event["id"], incident_id=incident["id"] if incident else None
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error ingesting event: {str(e)}")
