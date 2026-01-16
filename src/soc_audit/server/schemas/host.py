"""Pydantic schemas for host registry and heartbeat."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class HostInfo(BaseModel):
    """Schema for host information."""

    host_id: str
    host_name: str | None
    first_seen_ts: str  # ISO format datetime string
    last_seen_ts: str  # ISO format datetime string
    meta: dict[str, Any] = Field(default_factory=dict)

    class Config:
        extra = "allow"


class HostListResponse(BaseModel):
    """Response schema for listing hosts."""

    hosts: list[HostInfo]


class HeartbeatRequest(BaseModel):
    """Request schema for heartbeat endpoint."""

    host_id: str
    host_name: str | None = None
    meta: dict[str, Any] | None = Field(default_factory=dict)


class BatchIngestRequest(BaseModel):
    """Request schema for batch ingest endpoint."""

    host_id: str
    events: list[dict[str, Any]]  # Normalized AlertEvent-like payloads


class BatchIngestResponse(BaseModel):
    """Response schema for batch ingest endpoint."""

    ok: bool
    accepted: int
    incident_ids: list[str] = Field(default_factory=list)
    errors: list[str] | None = Field(default=None, max_length=10)  # Bounded error list


class HeartbeatResponse(BaseModel):
    """Response schema for heartbeat endpoint."""

    ok: bool
    host_id: str
    server_time: str  # ISO format datetime string
    last_seen_ts: str  # ISO format datetime string
