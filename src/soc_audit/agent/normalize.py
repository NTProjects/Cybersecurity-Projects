"""Event normalization for agent telemetry."""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from random import randint
from typing import Any


def normalize_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """
    Normalize a Finding object into an AlertEvent-like payload.

    Args:
        finding: Finding dict from engine.

    Returns:
        Normalized event dict ready for batch ingest.
    """
    event_id = finding.get("id") or f"agent-{uuid.uuid4().hex[:8]}"
    
    return {
        "id": event_id,
        "timestamp": finding.get("timestamp", datetime.now(timezone.utc).isoformat()),
        "severity": finding.get("severity", "medium"),
        "module": finding.get("module", "unknown"),
        "title": finding.get("title", "Unknown finding"),
        "source": "agent",
        "evidence": finding.get("evidence", {}),
        "mitre_ids": finding.get("mitre_ids", []),
        "rba_score": finding.get("rba_score", None),
        "entity_keys": finding.get("entity_keys", {}),
    }


def normalize_demo_event(host_id: str) -> dict[str, Any]:
    """
    Generate a synthetic demo event for testing.

    Args:
        host_id: Host identifier.

    Returns:
        Normalized event dict ready for batch ingest.
    """
    event_id = f"agent-demo-{uuid.uuid4().hex[:12]}"
    severity_options = ["low", "medium"]
    severity = severity_options[randint(0, len(severity_options) - 1)]
    rba_score = randint(20, 60)
    
    return {
        "id": event_id,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "severity": severity,
        "module": "agent_demo",
        "title": "Demo agent event",
        "source": "agent",
        "evidence": {},
        "mitre_ids": ["T1059"],
        "rba_score": rba_score,
        "entity_keys": {
            "host": host_id,
        },
    }
