"""Data models for SOC workflow: AlertEvent and Incident.

This module defines the core data structures used for alert management,
incident grouping, and persistence in the SOC Audit Framework.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

from soc_audit.core.collectors import TelemetryEvent
from soc_audit.core.interfaces import Finding


@dataclass
class AlertEvent:
    """
    A normalized alert event that can come from engine findings or collectors.

    This is the unified model used for persistence, incident grouping,
    and suppression matching.
    """

    id: str
    timestamp: datetime
    severity: str
    module: str
    title: str
    source: str  # "engine", "metrics", "logs", etc.
    evidence: dict[str, Any] = field(default_factory=dict)
    mitre_ids: list[str] = field(default_factory=list)
    rba_score: int | None = None
    entity_keys: dict[str, str] = field(default_factory=dict)  # e.g., {"ip": "192.168.1.1", "user": "admin"}
    acked: bool = False
    suppressed: bool = False
    incident_id: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "severity": self.severity,
            "module": self.module,
            "title": self.title,
            "source": self.source,
            "evidence": self.evidence,
            "mitre_ids": self.mitre_ids,
            "rba_score": self.rba_score,
            "entity_keys": self.entity_keys,
            "acked": self.acked,
            "suppressed": self.suppressed,
            "incident_id": self.incident_id,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AlertEvent:
        """Create from dictionary (for JSON deserialization)."""
        return cls(
            id=data["id"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            severity=data["severity"],
            module=data["module"],
            title=data["title"],
            source=data["source"],
            evidence=data.get("evidence", {}),
            mitre_ids=data.get("mitre_ids", []),
            rba_score=data.get("rba_score"),
            entity_keys=data.get("entity_keys", {}),
            acked=data.get("acked", False),
            suppressed=data.get("suppressed", False),
            incident_id=data.get("incident_id"),
        )


@dataclass
class Incident:
    """
    An incident that groups related alerts.

    Incidents are created automatically through grouping heuristics
    or manually by users.
    """

    id: str
    title: str
    status: str  # "open" or "closed"
    created_ts: datetime
    updated_ts: datetime
    severity_max: str  # Highest severity among alerts
    rba_max: int | None = None  # Highest RBA score among alerts
    entity_summary: dict[str, Any] = field(default_factory=dict)  # Aggregated entities
    alert_count: int = 0
    notes: str | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "id": self.id,
            "title": self.title,
            "status": self.status,
            "created_ts": self.created_ts.isoformat(),
            "updated_ts": self.updated_ts.isoformat(),
            "severity_max": self.severity_max,
            "rba_max": self.rba_max,
            "entity_summary": self.entity_summary,
            "alert_count": self.alert_count,
            "notes": self.notes,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Incident:
        """Create from dictionary (for JSON deserialization)."""
        return cls(
            id=data["id"],
            title=data["title"],
            status=data["status"],
            created_ts=datetime.fromisoformat(data["created_ts"]),
            updated_ts=datetime.fromisoformat(data["updated_ts"]),
            severity_max=data["severity_max"],
            rba_max=data.get("rba_max"),
            entity_summary=data.get("entity_summary", {}),
            alert_count=data.get("alert_count", 0),
            notes=data.get("notes"),
        )


def normalize_event_from_finding(
    finding: Finding, module_name: str, source: str = "engine"
) -> AlertEvent:
    """
    Convert a Finding to an AlertEvent.

    Args:
        finding: The Finding object to normalize.
        module_name: Name of the module that produced the finding.
        source: Source identifier (default: "engine").

    Returns:
        AlertEvent with normalized data.
    """
    # Extract entity keys from evidence
    entity_keys: dict[str, str] = {}
    evidence = finding.evidence or {}
    
    # Common entity field mappings
    if "source_ip" in evidence or "ip" in evidence:
        entity_keys["ip"] = str(evidence.get("source_ip") or evidence.get("ip", ""))
    if "username" in evidence or "user" in evidence:
        entity_keys["user"] = str(evidence.get("username") or evidence.get("user", ""))
    if "port" in evidence:
        entity_keys["port"] = str(evidence["port"])
    if "host" in evidence:
        entity_keys["host"] = str(evidence["host"])

    # Extract MITRE IDs
    mitre_ids = getattr(finding, "mitre_ids", None) or []
    
    # Extract RBA score
    rba_score = getattr(finding, "rba_score", None)

    return AlertEvent(
        id=str(uuid.uuid4()),
        timestamp=datetime.utcnow(),
        severity=finding.severity,
        module=module_name,
        title=finding.title,
        source=source,
        evidence=dict(evidence),
        mitre_ids=list(mitre_ids),
        rba_score=rba_score,
        entity_keys=entity_keys,
    )


def normalize_event_from_telemetry(event: TelemetryEvent) -> AlertEvent:
    """
    Convert a TelemetryEvent to an AlertEvent.

    Args:
        event: The TelemetryEvent from collectors.

    Returns:
        AlertEvent with normalized data.
    """
    # Extract entity keys from evidence
    entity_keys: dict[str, str] = {}
    evidence = event.evidence or {}
    
    if "source_ip" in evidence:
        entity_keys["ip"] = str(evidence["source_ip"])
    if "username" in evidence:
        entity_keys["user"] = str(evidence["username"])

    return AlertEvent(
        id=str(uuid.uuid4()),
        timestamp=event.timestamp,
        severity=event.severity,
        module=event.module,
        title=event.title,
        source=event.source,
        evidence=dict(evidence),
        mitre_ids=list(event.mitre_ids or []),
        rba_score=event.rba_score,
        entity_keys=entity_keys,
    )
