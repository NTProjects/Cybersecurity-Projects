"""Batch ingest endpoint for agent event ingestion."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request

from soc_audit.server.auth import get_role_from_request
from soc_audit.server.deps import get_incident_engine, get_storage, get_ws_manager
from soc_audit.server.rbac import require_agent_or_admin
from soc_audit.server.incident_engine import ServerIncidentEngine
from soc_audit.server.schemas.host import BatchIngestRequest, BatchIngestResponse
from soc_audit.server.storage import BackendStorage
from soc_audit.server.ws_manager import WebSocketManager

router = APIRouter(prefix="/api/v1/ingest", tags=["ingest"])


@router.post("/batch", response_model=BatchIngestResponse)
async def ingest_batch(
    batch_request: BatchIngestRequest,
    request: Request,
    role: str = require_agent_or_admin("ingest_batch_alerts"),  # Phase 10.1: Enforce RBAC
    storage: BackendStorage = Depends(get_storage),
    incident_engine: ServerIncidentEngine = Depends(get_incident_engine),
    ws_manager: WebSocketManager = Depends(get_ws_manager),
):
    """
    Ingest multiple alert events in a single batch.

    Phase 10.1: Requires agent or admin role.
    Each event must include required AlertEvent fields.
    Host will be auto-registered if not exists.
    """

    host_id = batch_request.host_id
    if not host_id:
        raise HTTPException(status_code=400, detail="host_id is required in batch request")

    # Ensure host exists (auto-register with minimal record if not)
    existing_host = storage.get_host(host_id)
    if not existing_host:
        storage.upsert_host(
            {
                "host_id": host_id,
                "host_name": None,  # Will be updated on heartbeat
                "meta": {},
            }
        )

    accepted = 0
    incident_ids: list[str] = []
    errors: list[str] = []

    received_ts = datetime.utcnow().isoformat()

    for event_dict in batch_request.events:
        try:
            # Normalize event: ensure host_id, timestamp, required fields
            if not isinstance(event_dict, dict):
                errors.append(f"Event is not a dict: {type(event_dict)}")
                continue

            # Ensure host_id matches batch request
            event_dict["host_id"] = host_id

            # Ensure timestamp is ISO format string
            if "timestamp" not in event_dict:
                event_dict["timestamp"] = received_ts
            elif isinstance(event_dict["timestamp"], datetime):
                event_dict["timestamp"] = event_dict["timestamp"].isoformat()

            # Ensure required fields with defaults
            if "source" not in event_dict:
                event_dict["source"] = "agent"
            if "evidence" not in event_dict:
                event_dict["evidence"] = {}
            if "mitre_ids" not in event_dict:
                event_dict["mitre_ids"] = []
            if "entity_keys" not in event_dict:
                event_dict["entity_keys"] = {}

            # Ensure received_ts
            event_dict["received_ts"] = received_ts

            # Process through incident engine
            updated_event, incident = incident_engine.ingest_event(event_dict)

            # Save alert
            storage.save_alert(updated_event)

            # Save incident if created/updated
            if incident:
                storage.save_incident(incident)
                if incident["id"] not in incident_ids:
                    incident_ids.append(incident["id"])

            # Append timeline entry
            storage.append_timeline(
                {
                    "timestamp": received_ts,
                    "message": f"Alert ingested: {updated_event.get('title', 'Unknown')}",
                    "level": updated_event.get("severity", "info"),
                    "source": event_dict.get("source", "agent"),
                    "module": updated_event.get("module", "unknown"),
                    "alert_id": updated_event["id"],
                    "incident_id": incident["id"] if incident else None,
                    "host_id": host_id,
                }
            )

            # Phase 11.1: Broadcast WebSocket updates with event types for subscription filtering
            if ws_manager:
                await ws_manager.broadcast_json({"type": "alert", "data": updated_event}, event_type="alert")
                if incident:
                    await ws_manager.broadcast_json({"type": "incident", "data": incident}, event_type="incident")

            accepted += 1

        except Exception as e:
            error_msg = f"Error processing event: {str(e)}"
            if len(errors) < 10:  # Bound error list
                errors.append(error_msg)

    return BatchIngestResponse(
        ok=True,
        accepted=accepted,
        incident_ids=incident_ids,
        errors=errors if errors else None,
    )
