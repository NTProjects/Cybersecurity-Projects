"""Threat Hunt Workspace.

Phase 15.1: Threat Hunting & Forensics
- Query historical events
- Timeline reconstruction
- Entity pivoting
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any

from soc_audit.core.models import AlertEvent


class ThreatHuntWorkspace:
    """
    Threat hunt workspace for analyst investigations.
    
    Phase 15.1: Provides query, timeline, and pivoting capabilities.
    """
    
    def __init__(self, storage: Any):
        """
        Initialize threat hunt workspace.
        
        Args:
            storage: Storage backend for querying historical data.
        """
        self.storage = storage
    
    def query_events(
        self,
        host_id: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        mitre_technique: str | None = None,
        severity: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
        limit: int = 1000,
    ) -> list[dict[str, Any]]:
        """
        Query historical events with filters.
        
        Phase 15.1: Flexible query interface for threat hunting.
        
        Args:
            host_id: Filter by host ID.
            entity_type: Filter by entity type (ip, user, port).
            entity_id: Filter by entity ID.
            mitre_technique: Filter by MITRE technique ID.
            severity: Filter by severity.
            start_time: Start of time range.
            end_time: End of time range.
            limit: Maximum number of results.
        
        Returns:
            List of event dictionaries.
        """
        filters: dict[str, Any] = {}
        
        if host_id:
            filters["host_id"] = host_id
        if severity:
            filters["severity"] = severity
        if start_time:
            filters["start_time"] = start_time.isoformat()
        if end_time:
            filters["end_time"] = end_time.isoformat()
        filters["limit"] = limit
        
        # Query alerts
        alerts = self.storage.list_alerts(filters)
        
        # Filter by entity if specified
        if entity_type and entity_id:
            filtered_alerts = []
            for alert in alerts:
                entity_keys = alert.get("entity_keys", {})
                if entity_keys.get(entity_type) == entity_id:
                    filtered_alerts.append(alert)
            alerts = filtered_alerts
        
        # Filter by MITRE technique if specified
        if mitre_technique:
            filtered_alerts = []
            for alert in alerts:
                mitre_ids = alert.get("mitre_ids", [])
                if mitre_technique in mitre_ids:
                    filtered_alerts.append(alert)
            alerts = filtered_alerts
        
        return alerts
    
    def reconstruct_timeline(
        self,
        host_id: str | None = None,
        entity_type: str | None = None,
        entity_id: str | None = None,
        start_time: datetime | None = None,
        end_time: datetime | None = None,
    ) -> list[dict[str, Any]]:
        """
        Reconstruct timeline of events.
        
        Phase 15.1: Creates chronological timeline for investigation.
        
        Args:
            host_id: Filter by host ID.
            entity_type: Filter by entity type.
            entity_id: Filter by entity ID.
            start_time: Start of time range.
            end_time: End of time range.
        
        Returns:
            List of timeline events in chronological order.
        """
        events = self.query_events(
            host_id=host_id,
            entity_type=entity_type,
            entity_id=entity_id,
            start_time=start_time,
            end_time=end_time,
            limit=10000,
        )
        
        # Sort by timestamp
        events.sort(key=lambda e: e.get("timestamp", ""))
        
        # Enrich with timeline metadata
        timeline = []
        for event in events:
            timeline.append({
                "timestamp": event.get("timestamp"),
                "type": "alert",
                "title": event.get("title"),
                "severity": event.get("severity"),
                "module": event.get("module"),
                "host_id": event.get("host_id"),
                "mitre_ids": event.get("mitre_ids", []),
                "rba_score": event.get("rba_score"),
                "alert_id": event.get("id"),
            })
        
        return timeline
    
    def pivot_entity(
        self,
        entity_type: str,
        entity_id: str,
        time_window_hours: int = 24,
    ) -> dict[str, Any]:
        """
        Pivot on an entity to find related events and entities.
        
        Phase 15.1: Entity-centric investigation pivot point.
        
        Args:
            entity_type: Type of entity (ip, user, port, host).
            entity_id: Entity identifier.
            time_window_hours: Time window for related events.
        
        Returns:
            Dictionary with related events and entities.
        """
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_window_hours)
        
        # Query events involving this entity
        events = self.query_events(
            entity_type=entity_type,
            entity_id=entity_id,
            start_time=start_time,
            end_time=end_time,
            limit=1000,
        )
        
        # Extract related entities
        related_entities: dict[str, set[str]] = {
            "hosts": set(),
            "ips": set(),
            "users": set(),
            "ports": set(),
        }
        
        for event in events:
            host_id = event.get("host_id")
            if host_id:
                related_entities["hosts"].add(host_id)
            
            entity_keys = event.get("entity_keys", {})
            for etype, eid in entity_keys.items():
                if etype in related_entities and eid:
                    related_entities[etype].add(eid)
        
        # Get related alerts
        related_alerts = events[:100]  # Limit to 100 most recent
        
        return {
            "entity_type": entity_type,
            "entity_id": entity_id,
            "time_window_hours": time_window_hours,
            "event_count": len(events),
            "related_entities": {
                k: list(v) for k, v in related_entities.items()
            },
            "related_alerts": related_alerts,
            "timeline": self.reconstruct_timeline(
                entity_type=entity_type,
                entity_id=entity_id,
                start_time=start_time,
                end_time=end_time,
            ),
        }
