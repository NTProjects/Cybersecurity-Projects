"""Heartbeat API endpoint for agent registration."""
from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Request

from soc_audit.server.auth import get_role_from_request
from soc_audit.server.deps import get_storage
from soc_audit.server.schemas.host import HeartbeatRequest, HeartbeatResponse
from soc_audit.server.storage import BackendStorage

router = APIRouter(prefix="/api/v1", tags=["heartbeat"])


@router.post("/heartbeat", response_model=HeartbeatResponse)
async def heartbeat(
    heartbeat_request: HeartbeatRequest,
    request: Request,
    storage: BackendStorage = Depends(get_storage),
):
    """
    Update heartbeat for an agent host.

    Requires agent role (or admin for backward compatibility).
    Creates minimal host record if not exists.
    """
    # Check auth (agent or admin allowed for heartbeat)
    try:
        role = get_role_from_request(request)
        if role not in ["agent", "admin"]:
            raise HTTPException(status_code=403, detail="Requires agent or admin role")
    except HTTPException:
        raise
    except Exception:
        # Auth disabled - allow
        pass

    # Upsert host record (preserves first_seen_ts, updates last_seen_ts)
    host_info = {
        "host_id": heartbeat_request.host_id,
        "host_name": heartbeat_request.host_name,
        "meta": heartbeat_request.meta or {},
    }

    try:
        storage.upsert_host(host_info)
        storage.update_heartbeat(heartbeat_request.host_id)
        return HeartbeatResponse(ok=True)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error updating heartbeat: {str(e)}")
