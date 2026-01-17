"""Host registry API endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request

from soc_audit.server.auth import get_role_from_request
from soc_audit.server.deps import get_storage
from soc_audit.server.rbac import require_analyst_or_admin
from soc_audit.server.schemas.host import HostInfo, HostListResponse
from soc_audit.server.storage import BackendStorage

router = APIRouter(prefix="/api/v1/hosts", tags=["hosts"])


@router.get("/", response_model=HostListResponse)
async def list_hosts(
    request: Request,
    role: str = require_analyst_or_admin("read_hosts"),  # Phase 10.1: Enforce RBAC
    storage: BackendStorage = Depends(get_storage),
):
    """
    List all registered hosts.

    Phase 10.1: Requires analyst or admin role.
    """

    hosts_data = storage.list_hosts()
    hosts = [
        HostInfo(
            host_id=h["host_id"],
            host_name=h.get("host_name"),
            first_seen_ts=h.get("first_seen_ts", ""),
            last_seen_ts=h.get("last_seen_ts", ""),
            meta=h.get("meta", {}),
        )
        for h in hosts_data
    ]

    return HostListResponse(hosts=hosts)


@router.get("/{host_id}", response_model=HostInfo)
async def get_host(
    host_id: str,
    request: Request,
    role: str = require_analyst_or_admin("read_hosts"),  # Phase 10.1: Enforce RBAC
    storage: BackendStorage = Depends(get_storage),
):
    """
    Get details for a specific host.

    Phase 10.1: Requires analyst or admin role.
    """

    host_data = storage.get_host(host_id)
    if not host_data:
        raise HTTPException(status_code=404, detail="Host not found")

    return HostInfo(
        host_id=host_data["host_id"],
        host_name=host_data.get("host_name"),
        first_seen_ts=host_data.get("first_seen_ts", ""),
        last_seen_ts=host_data.get("last_seen_ts", ""),
        meta=host_data.get("meta", {}),
    )
