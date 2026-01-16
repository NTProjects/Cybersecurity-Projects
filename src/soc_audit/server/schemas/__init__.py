"""Server-side Pydantic schemas for API request/response validation."""
from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field, field_validator


class AlertEventSchema(BaseModel):
    """Schema for AlertEvent ingestion and responses."""

    id: str
    timestamp: str  # ISO format datetime string
    severity: str
    module: str
    title: str
    source: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    mitre_ids: list[str] = Field(default_factory=list)
    rba_score: int | None = None
    entity_keys: dict[str, Any] = Field(default_factory=dict)
    acked: bool = False
    suppressed: bool = False
    incident_id: str | None = None
    host_id: str  # Required for backend
    host_name: str | None = None
    received_ts: str | None = None  # ISO format datetime string

    class Config:
        extra = "allow"  # Allow extra fields for future compatibility


class IncidentSchema(BaseModel):
    """Schema for Incident responses."""

    id: str
    title: str
    status: str
    created_ts: str  # ISO format datetime string
    updated_ts: str  # ISO format datetime string
    severity_max: str
    rba_max: int | None = None
    entity_summary: dict[str, Any] = Field(default_factory=dict)
    alert_count: int = 0
    notes: str | None = None
    host_id: str  # Required for backend

    class Config:
        extra = "allow"


class TimelineEntrySchema(BaseModel):
    """Schema for timeline entries."""

    id: int | None = None
    timestamp: str  # ISO format datetime string
    message: str
    level: str
    source: str
    module: str
    alert_id: str | None = None
    incident_id: str | None = None
    host_id: str | None = None

    class Config:
        extra = "allow"


class AckRequest(BaseModel):
    """Request to acknowledge/unacknowledge an alert."""

    acked: bool


class SuppressRequest(BaseModel):
    """Request to suppress/unsuppress an alert."""

    suppressed: bool
    suppressed_until: str | None = None  # ISO format datetime string
    rule: dict[str, Any] | None = None


class NoteRequest(BaseModel):
    """Request to add a note to an incident."""

    note: str


class IngestResponse(BaseModel):
    """Response from event ingestion."""

    ok: bool
    alert_id: str
    incident_id: str | None = None


class ErrorResponse(BaseModel):
    """Error response schema."""

    error: str
    detail: str | None = None
