"""Server-side incident engine with multi-host enforcement."""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timedelta
from typing import Any

from soc_audit.server.storage import BackendStorage


class ServerIncidentEngine:
    """
    Server-side incident engine that enforces per-host grouping.

    Incidents MUST NOT mix different host_id values (Phase 6 requirement).
    """

    def __init__(
        self,
        storage: BackendStorage,
        group_window_seconds: int = 300,
        similarity_title: bool = True,
        similarity_entities: bool = True,
        title_similarity_threshold: float = 0.7,
    ):
        """
        Initialize the server incident engine.

        Args:
            storage: Backend storage instance.
            group_window_seconds: Time window for grouping (default: 300 = 5 minutes).
            similarity_title: Enable title similarity matching.
            similarity_entities: Enable entity-based matching.
            title_similarity_threshold: Jaccard similarity threshold for titles.
        """
        self.storage = storage
        self.group_window_seconds = group_window_seconds
        self.similarity_title = similarity_title
        self.similarity_entities = similarity_entities
        self.title_similarity_threshold = title_similarity_threshold

    def ingest_event(self, alert_dict: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
        """
        Process an alert event and assign it to an incident if a match is found.

        Args:
            alert_dict: Alert event dict (from API schema).

        Returns:
            Tuple of (updated alert_dict with incident_id, matched incident_dict or None).
        """
        host_id = alert_dict.get("host_id")
        if not host_id:
            raise ValueError("host_id is required for alert events")

        # Find best matching incident (only from same host)
        match = self._find_best_match(alert_dict)

        if match:
            # Update existing incident
            incident = match
            alert_dict["incident_id"] = incident["id"]
            updated_incident = self._update_incident_from_alert(incident, alert_dict)
            return alert_dict, updated_incident
        else:
            # Create new incident
            new_incident = self._create_incident_from_alert(alert_dict)
            alert_dict["incident_id"] = new_incident["id"]
            return alert_dict, new_incident

    def _find_best_match(self, alert_dict: dict[str, Any]) -> dict[str, Any] | None:
        """Find the best matching open incident for an alert (same host only)."""
        host_id = alert_dict["host_id"]
        alert_timestamp = datetime.fromisoformat(alert_dict["timestamp"])
        window_start = alert_timestamp - timedelta(seconds=self.group_window_seconds)

        # Load open incidents for this host only
        incidents = self.storage.list_incidents(filters={"host_id": host_id, "status": "open"})

        best_match: dict[str, Any] | None = None
        best_score = 0.0

        for incident in incidents:
            incident_updated = datetime.fromisoformat(incident["updated_ts"])

            # Time window check
            if incident_updated < window_start:
                continue

            # Module match (strong indicator)
            alert_module = alert_dict.get("module", "unknown")
            incident_module = incident.get("entity_summary", {}).get("module")
            if alert_module != "unknown" and incident_module and alert_module != incident_module:
                continue

            score = 0.0

            # Title similarity
            if self.similarity_title:
                title_score = self._calculate_title_similarity(
                    alert_dict.get("title", ""), incident.get("title", "")
                )
                if title_score >= self.title_similarity_threshold:
                    score = max(score, title_score)

            # Entity similarity
            if self.similarity_entities:
                entity_score = self._compare_entities(
                    alert_dict.get("entity_keys", {}), incident.get("entity_summary", {})
                )
                if entity_score:
                    score = max(score, 0.7)

            # MITRE ID overlap
            alert_mitre = set(alert_dict.get("mitre_ids", []))
            incident_mitre = set(incident.get("entity_summary", {}).get("mitre_ids", []))
            if alert_mitre and incident_mitre and alert_mitre.intersection(incident_mitre):
                score = max(score, 0.8)

            if score > best_score and score >= 0.6:  # Minimum threshold
                best_score = score
                best_match = incident

        return best_match

    def _create_incident_from_alert(self, alert_dict: dict[str, Any]) -> dict[str, Any]:
        """Create a new incident from an alert event."""
        now = datetime.utcnow().isoformat()
        entity_summary = {
            "module": alert_dict.get("module", "unknown"),
            "severity": alert_dict.get("severity", "info"),
            "rba_score": alert_dict.get("rba_score"),
            "mitre_ids": alert_dict.get("mitre_ids", []),
            **(alert_dict.get("entity_keys", {})),
        }

        incident = {
            "id": str(uuid.uuid4()),
            "title": alert_dict.get("title", "Untitled Incident"),
            "status": "open",
            "created_ts": alert_dict.get("timestamp", now),
            "updated_ts": alert_dict.get("timestamp", now),
            "severity_max": alert_dict.get("severity", "info"),
            "rba_max": alert_dict.get("rba_score") or 0,
            "entity_summary": entity_summary,
            "alert_count": 1,
            "notes": None,
            "host_id": alert_dict["host_id"],
        }

        self.storage.save_incident(incident)
        return incident

    def _update_incident_from_alert(
        self, incident: dict[str, Any], alert_dict: dict[str, Any]
    ) -> dict[str, Any]:
        """Update an existing incident with a new alert event."""
        incident["alert_count"] = incident.get("alert_count", 0) + 1
        incident["updated_ts"] = alert_dict.get("timestamp", datetime.utcnow().isoformat())

        # Update max severity
        severity_order = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
        alert_severity = alert_dict.get("severity", "info")
        current_severity = incident.get("severity_max", "info")
        if severity_order.get(alert_severity.lower(), 0) > severity_order.get(current_severity.lower(), 0):
            incident["severity_max"] = alert_severity

        # Update max RBA
        alert_rba = alert_dict.get("rba_score") or 0
        if alert_rba > (incident.get("rba_max") or 0):
            incident["rba_max"] = alert_rba

        # Update entity summary
        entity_summary = incident.get("entity_summary", {})
        alert_entities = alert_dict.get("entity_keys", {})
        for key, value in alert_entities.items():
            if key not in entity_summary:
                entity_summary[key] = value
            elif isinstance(entity_summary[key], list):
                if value not in entity_summary[key]:
                    entity_summary[key].append(value)
            elif entity_summary[key] != value:
                entity_summary[key] = [entity_summary[key], value]

        # Merge MITRE IDs
        alert_mitre = set(alert_dict.get("mitre_ids", []))
        incident_mitre = set(entity_summary.get("mitre_ids", []))
        entity_summary["mitre_ids"] = list(incident_mitre.union(alert_mitre))

        incident["entity_summary"] = entity_summary
        self.storage.save_incident(incident)
        return incident

    def _calculate_title_similarity(self, title1: str, title2: str) -> float:
        """Calculate Jaccard similarity between two titles."""
        words1 = set(re.findall(r"\w+", title1.lower()))
        words2 = set(re.findall(r"\w+", title2.lower()))
        if not words1 and not words2:
            return 1.0
        if not words1 or not words2:
            return 0.0
        intersection = len(words1.intersection(words2))
        union = len(words1.union(words2))
        return intersection / union if union > 0 else 0.0

    def _compare_entities(self, alert_entities: dict[str, Any], incident_entities: dict[str, Any]) -> bool:
        """Compare if alert entities overlap with incident entities."""
        for key, alert_value in alert_entities.items():
            if key in incident_entities:
                incident_value = incident_entities[key]
                if isinstance(alert_value, list) and isinstance(incident_value, list):
                    if set(alert_value).intersection(incident_value):
                        return True
                elif isinstance(alert_value, list) and alert_value and alert_value[0] == incident_value:
                    return True
                elif isinstance(incident_value, list) and incident_value and incident_value[0] == alert_value:
                    return True
                elif alert_value == incident_value:
                    return True
        return False
