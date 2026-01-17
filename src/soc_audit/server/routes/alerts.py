"""Alerts API endpoints."""
from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from soc_audit.server.auth import get_role_from_request
from soc_audit.server.deps import get_storage, get_ws_manager
from soc_audit.server.logging_config import log_performance, get_correlation_id
from soc_audit.server.rbac import require_analyst_or_admin, require_admin
from soc_audit.server.schemas import AckRequest, AlertEventSchema, SuppressRequest
from soc_audit.server.storage import BackendStorage
from soc_audit.server.ws_manager import WebSocketManager

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/alerts", tags=["alerts"])


@router.get("/", response_model=list[AlertEventSchema])
async def list_alerts(
    request: Request,
    role: str = require_analyst_or_admin("read_alerts"),  # Phase 10.1: Enforce RBAC (dependency)
    host_id: str | None = Query(None),
    severity: str | None = Query(None),
    rba_min: int | None = Query(None),
    rba_max: int | None = Query(None),
    incident_id: str | None = Query(None),
    acked: bool | None = Query(None),
    suppressed: bool | None = Query(None),
    limit: int = Query(500, ge=1, le=10000),
    storage: BackendStorage = Depends(get_storage),
):
    """
    List alerts with optional filters.
    
    Phase 10.1: Requires analyst or admin role.
    """
    filters: dict[str, Any] = {}
    if host_id:
        filters["host_id"] = host_id
    if severity:
        filters["severity"] = severity
    if rba_min is not None:
        filters["rba_min"] = rba_min
    if rba_max is not None:
        filters["rba_max"] = rba_max
    if incident_id:
        filters["incident_id"] = incident_id
    if acked is not None:
        filters["acked"] = acked
    if suppressed is not None:
        filters["suppressed"] = suppressed
    filters["limit"] = limit

    alerts = storage.list_alerts(filters)
    return alerts


@router.get("/{alert_id}", response_model=AlertEventSchema)
async def get_alert(
    alert_id: str,
    request: Request,
    role: str = require_analyst_or_admin("read_alerts"),  # Phase 10.1: Enforce RBAC (dependency)
    storage: BackendStorage = Depends(get_storage),
):
    """
    Get a specific alert by ID.
    
    Phase 10.1: Requires analyst or admin role.
    """
    alert = storage.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert


@router.post("/{alert_id}/ack", response_model=AlertEventSchema)
async def ack_alert(
    alert_id: str,
    request: Request,
    ack_request: AckRequest,
    role: str = require_analyst_or_admin("ack_alerts"),  # Phase 10.1: Enforce RBAC (dependency)
    storage: BackendStorage = Depends(get_storage),
    ws_manager: WebSocketManager = Depends(get_ws_manager),
):
    """
    Acknowledge or unacknowledge an alert.

    Phase 10.1: Requires analyst or admin role.
    """

            alert = storage.get_alert(alert_id)
            if not alert:
                raise HTTPException(status_code=404, detail="Alert not found")

            # Update ack status
            storage.update_alert_ack(alert_id, ack_request.acked, datetime.utcnow().isoformat())

            # Append timeline
            storage.append_timeline(
                {
                    "timestamp": datetime.utcnow().isoformat(),
                    "message": f"Alert {'acknowledged' if ack_request.acked else 'unacknowledged'}",
                    "level": "info",
                    "source": "api",
                    "module": alert.get("module", "unknown"),
                    "alert_id": alert_id,
                    "host_id": alert.get("host_id"),
                }
            )

            # Broadcast update
            updated_alert = storage.get_alert(alert_id)
            if ws_manager and updated_alert:
                await ws_manager.broadcast_json({"type": "alert", "data": updated_alert})

            logger.info(
                f"Alert {alert_id} {'acknowledged' if ack_request.acked else 'unacknowledged'}",
                extra={
                    "extra_fields": {
                        "alert_id": alert_id,
                        "action": "ack" if ack_request.acked else "unack",
                        "role": role,
                    }
                },
            )
            
            return updated_alert
        except HTTPException:
            raise
        except Exception as e:
            logger.error(
                f"Error acknowledging alert {alert_id}: {e}",
                exc_info=True,
                extra={
                    "extra_fields": {
                        "alert_id": alert_id,
                        "correlation_id": get_correlation_id(),
                    }
                },
            )
            raise HTTPException(status_code=500, detail=f"Error acknowledging alert: {str(e)}")


@router.post("/{alert_id}/suppress", response_model=AlertEventSchema)
async def suppress_alert(
    alert_id: str,
    request: Request,
    suppress_request: SuppressRequest,
    role: str = require_admin("suppress_alerts"),  # Phase 10.1: Enforce RBAC - admin only (dependency)
    storage: BackendStorage = Depends(get_storage),
    ws_manager: WebSocketManager = Depends(get_ws_manager),
):
    """
    Suppress or unsuppress an alert.

    Phase 10.1: Requires admin role (explicitly denied for analyst).
    """

    alert = storage.get_alert(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")

    # Update suppress status
    storage.update_alert_suppressed(
        alert_id, suppress_request.suppressed, suppress_request.suppressed_until
    )

    # Append timeline
    storage.append_timeline(
        {
            "timestamp": datetime.utcnow().isoformat(),
            "message": f"Alert {'suppressed' if suppress_request.suppressed else 'unsuppressed'}",
            "level": "info",
            "source": "api",
            "module": alert.get("module", "unknown"),
            "alert_id": alert_id,
            "host_id": alert.get("host_id"),
        }
    )

    # Broadcast update
    updated_alert = storage.get_alert(alert_id)
    if ws_manager and updated_alert:
        await ws_manager.broadcast_json({"type": "alert", "data": updated_alert})

    return updated_alert
