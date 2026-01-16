"""Pydantic schemas for incident metrics (Phase 9.2)."""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field


class IncidentMetricsResponse(BaseModel):
    """Response schema for incident metrics endpoint."""

    mttr_seconds: float | None = Field(None, description="Mean Time To Resolve in seconds (None if no closed incidents)")
    resolved_count: int = Field(0, description="Number of resolved/closed incidents")
    open_count: int = Field(0, description="Number of open incidents")
    aging_buckets: dict[str, int] = Field(
        default_factory=lambda: {"<1h": 0, "1-4h": 0, "4-24h": 0, ">24h": 0},
        description="Count of open incidents by age bucket",
    )
