"""Incident grouping engine for SOC workflow.

This module provides functionality to automatically group related alerts
into incidents based on similarity heuristics.
"""
from __future__ import annotations

import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any

from soc_audit.core.models import AlertEvent, Incident


@dataclass
class IncidentMatch:
    """Result of incident matching."""

    incident: Incident
    score: float  # 0.0 to 1.0, higher = better match


class IncidentEngine:
    """
    Engine for grouping alerts into incidents.

    Uses heuristics to determine if alerts should be grouped together:
    - Same module + same primary entity (IP/user)
    - Same module + title similarity
    - Same MITRE ID within time window
    """

    def __init__(
        self,
        group_window_seconds: int = 300,
        similarity_title: bool = True,
        similarity_entities: bool = True,
    ):
        """
        Initialize the incident engine.

        Args:
            group_window_seconds: Time window for grouping (default: 300 = 5 minutes).
            similarity_title: Enable title similarity matching.
            similarity_entities: Enable entity-based matching.
        """
        self.group_window_seconds = group_window_seconds
        self.similarity_title = similarity_title
        self.similarity_entities = similarity_entities
        self._incidents: dict[str, Incident] = {}  # id -> Incident

    def ingest_event(
        self, event: AlertEvent
    ) -> tuple[AlertEvent, Incident | None]:
        """
        Process an event and assign it to an incident if a match is found.

        Args:
            event: The AlertEvent to process.

        Returns:
            Tuple of (event with incident_id set, matched incident or None).
        """
        # Find best matching incident
        match = self._find_best_match(event)

        if match and match.incident.status == "open":
            # Assign to existing open incident
            incident = match.incident
            event.incident_id = incident.id
            self._update_incident_from_event(incident, event)
            return (event, incident)
        elif match and match.score >= 0.8:
            # Strong match even if closed - reopen or create new
            # For now, create new incident for closed matches
            incident = self._create_incident_from_event(event)
            event.incident_id = incident.id
            return (event, incident)
        else:
            # No match or weak match - create new incident
            incident = self._create_incident_from_event(event)
            event.incident_id = incident.id
            return (event, incident)

    def _find_best_match(self, event: AlertEvent) -> IncidentMatch | None:
        """Find the best matching incident for an event."""
        best_match: IncidentMatch | None = None
        best_score = 0.0

        now = event.timestamp
        window_start = now - timedelta(seconds=self.group_window_seconds)

        for incident in self._incidents.values():
            # Skip if incident is closed and not strongly matching
            if incident.status == "closed":
                continue  # Don't attach to closed incidents by default

            # Check time window (for open incidents, be more lenient)
            if incident.status == "open":
                # Open incidents can accept events beyond window if strong match
                pass
            else:
                if incident.updated_ts < window_start:
                    continue

            # Compute match score
            score = self._compute_match_score(event, incident)

            if score > best_score and score >= 0.5:  # Minimum threshold
                best_score = score
                best_match = IncidentMatch(incident=incident, score=score)

        return best_match

    def _compute_match_score(self, event: AlertEvent, incident: Incident) -> float:
        """
        Compute a similarity score between event and incident (0.0 to 1.0).

        Args:
            event: The AlertEvent.
            incident: The Incident to match against.

        Returns:
            Score between 0.0 and 1.0.
        """
        score = 0.0

        # Module match (required for grouping)
        # We need to check if any alert in the incident has the same module
        # For now, use entity_summary to infer module similarity
        # This is a simplified heuristic - in production, store module in incident
        if "module" in incident.entity_summary:
            if event.module == incident.entity_summary.get("module"):
                score += 0.3
        else:
            # First event in incident - module match is important
            score += 0.3

        # Entity match (IP, user, etc.)
        if self.similarity_entities:
            event_entities = set(event.entity_keys.values())
            incident_entities = set()
            for key, values in incident.entity_summary.items():
                if key != "module" and isinstance(values, list):
                    incident_entities.update(str(v) for v in values)
                elif key != "module":
                    incident_entities.add(str(values))

            if event_entities and incident_entities:
                overlap = len(event_entities & incident_entities)
                if overlap > 0:
                    score += 0.4 * min(overlap / len(event_entities), 1.0)

        # Title similarity
        if self.similarity_title:
            # Simple word overlap heuristic
            event_words = set(event.title.lower().split())
            incident_words = set(incident.title.lower().split())
            if event_words and incident_words:
                overlap = len(event_words & incident_words)
                if overlap > 0:
                    score += 0.2 * min(overlap / len(event_words), 1.0)

        # MITRE ID match
        if event.mitre_ids:
            incident_mitre = incident.entity_summary.get("mitre_ids", [])
            if isinstance(incident_mitre, list):
                if any(mitre_id in incident_mitre for mitre_id in event.mitre_ids):
                    score += 0.1

        return min(score, 1.0)

    def _create_incident_from_event(self, event: AlertEvent) -> Incident:
        """Create a new incident from an event."""
        incident_id = str(uuid.uuid4())
        now = datetime.utcnow()

        # Build entity summary
        entity_summary: dict[str, Any] = {
            "module": event.module,
        }
        for key, value in event.entity_keys.items():
            entity_summary[key] = [value]  # Start as list for aggregation

        if event.mitre_ids:
            entity_summary["mitre_ids"] = list(event.mitre_ids)

        incident = Incident(
            id=incident_id,
            title=event.title,  # Use first event's title
            status="open",
            created_ts=now,
            updated_ts=now,
            severity_max=event.severity,
            rba_max=event.rba_score,
            entity_summary=entity_summary,
            alert_count=1,
        )

        self._incidents[incident_id] = incident
        return incident

    def _update_incident_from_event(self, incident: Incident, event: AlertEvent) -> None:
        """Update an incident with a new event."""
        incident.alert_count += 1
        incident.updated_ts = datetime.utcnow()

        # Update severity_max
        severity_order = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
        current_max = severity_order.get(incident.severity_max.lower(), 0)
        event_severity = severity_order.get(event.severity.lower(), 0)
        if event_severity > current_max:
            incident.severity_max = event.severity

        # Update rba_max
        if event.rba_score is not None:
            if incident.rba_max is None or event.rba_score > incident.rba_max:
                incident.rba_max = event.rba_score

        # Update entity summary (aggregate entities)
        for key, value in event.entity_keys.items():
            if key not in incident.entity_summary:
                incident.entity_summary[key] = []
            elif not isinstance(incident.entity_summary[key], list):
                incident.entity_summary[key] = [incident.entity_summary[key]]

            if str(value) not in [str(v) for v in incident.entity_summary[key]]:
                incident.entity_summary[key].append(value)

        # Update MITRE IDs
        if event.mitre_ids:
            if "mitre_ids" not in incident.entity_summary:
                incident.entity_summary["mitre_ids"] = []
            existing = incident.entity_summary["mitre_ids"]
            for mitre_id in event.mitre_ids:
                if mitre_id not in existing:
                    existing.append(mitre_id)

    def ack_incident(self, incident_id: str) -> None:
        """Acknowledge an incident (no-op for now, can add acked field later)."""
        if incident_id in self._incidents:
            pass  # Placeholder for future ack functionality

    def close_incident(self, incident_id: str) -> None:
        """Close an incident."""
        if incident_id in self._incidents:
            self._incidents[incident_id].status = "closed"
            self._incidents[incident_id].updated_ts = datetime.utcnow()

    def add_note(self, incident_id: str, note: str) -> None:
        """Add a note to an incident."""
        if incident_id in self._incidents:
            existing = self._incidents[incident_id].notes or ""
            if existing:
                self._incidents[incident_id].notes = f"{existing}\n{note}"
            else:
                self._incidents[incident_id].notes = note
            self._incidents[incident_id].updated_ts = datetime.utcnow()

    def get_incident(self, incident_id: str) -> Incident | None:
        """Get an incident by ID."""
        return self._incidents.get(incident_id)

    def get_all_incidents(self) -> list[Incident]:
        """Get all incidents."""
        return list(self._incidents.values())

    def get_open_incidents(self) -> list[Incident]:
        """Get all open incidents."""
        return [inc for inc in self._incidents.values() if inc.status == "open"]

    def load_incidents(self, incidents: list[Incident]) -> None:
        """Load incidents into the engine (for persistence restore)."""
        self._incidents = {inc.id: inc for inc in incidents}
