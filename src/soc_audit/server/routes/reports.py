"""Reporting API endpoints (Phase 9.3)."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from soc_audit.server.auth import get_role_from_request
from soc_audit.server.deps import get_storage
from soc_audit.server.storage import BackendStorage

router = APIRouter(prefix="/api/v1/reports", tags=["reports"])


class IncidentSummaryItem(BaseModel):
    """Incident summary item for report."""

    incident_id: str
    status: str
    severity_max: str
    rba_max: int | None = None
    alert_count: int = 0
    host_id: str | None = None
    created_ts: str  # ISO8601
    updated_ts: str  # ISO8601


class IncidentReportResponse(BaseModel):
    """Response schema for incident report endpoint."""

    generated_at: str = Field(description="ISO8601 timestamp")
    total_incidents: int
    open_incidents: int
    closed_incidents: int
    mttr_seconds: float | None = None
    aging_buckets: dict[str, int] = Field(
        default_factory=lambda: {"<1h": 0, "1-4h": 0, "4-24h": 0, ">24h": 0}
    )
    incidents: list[IncidentSummaryItem] = Field(default_factory=list)


class HostSummaryItem(BaseModel):
    """Host summary item for report."""

    host_id: str
    host_name: str | None = None
    status: str  # ONLINE, OFFLINE, UNKNOWN
    first_seen_ts: str  # ISO8601
    last_seen_ts: str  # ISO8601
    incident_count: int = 0
    open_incidents: int = 0


class HostReportResponse(BaseModel):
    """Response schema for host report endpoint."""

    generated_at: str = Field(description="ISO8601 timestamp")
    total_hosts: int
    online_hosts: int
    offline_hosts: int
    hosts: list[HostSummaryItem] = Field(default_factory=list)


@router.get("/incidents", response_model=IncidentReportResponse)
async def get_incident_report(
    request: Request,
    storage: BackendStorage = Depends(get_storage),
):
    """
    Phase 9.3: Get incident report for export.
    
    Requires analyst or admin role.
    """
    # Check auth (analyst or admin allowed)
    try:
        role = get_role_from_request(request)
        if role not in ["analyst", "admin"]:
            raise HTTPException(status_code=403, detail="Requires analyst or admin role")
    except HTTPException:
        raise
    except Exception:
        pass  # Auth disabled - allow

    report_data = storage.get_incident_report_data()
    
    # Add generated_at timestamp
    report_data["generated_at"] = datetime.utcnow().isoformat()
    
    return IncidentReportResponse(**report_data)


@router.get("/hosts", response_model=HostReportResponse)
async def get_host_report(
    request: Request,
    storage: BackendStorage = Depends(get_storage),
):
    """
    Phase 9.3: Get host report for export.
    
    Requires analyst or admin role.
    """
    # Check auth (analyst or admin allowed)
    try:
        role = get_role_from_request(request)
        if role not in ["analyst", "admin"]:
            raise HTTPException(status_code=403, detail="Requires analyst or admin role")
    except HTTPException:
        raise
    except Exception:
        pass  # Auth disabled - allow

    report_data = storage.get_host_report_data()
    
    # Add generated_at timestamp
    report_data["generated_at"] = datetime.utcnow().isoformat()
    
    return HostReportResponse(**report_data)
