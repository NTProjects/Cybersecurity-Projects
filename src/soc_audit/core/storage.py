"""Persistence layer for alerts, incidents, and timeline.

This module provides storage backends (SQLite and JSON) for persisting
SOC workflow data including alerts, incidents, and timeline events.
"""
from __future__ import annotations

import json
import sqlite3
from abc import ABC, abstractmethod
from datetime import datetime
from pathlib import Path
from typing import Any

from soc_audit.core.models import AlertEvent, Incident


class Storage(ABC):
    """Abstract base class for storage backends."""

    @abstractmethod
    def init(self) -> None:
        """Initialize the storage backend (create tables/files)."""
        pass

    @abstractmethod
    def save_alert(self, event: AlertEvent) -> None:
        """Save an alert event."""
        pass

    @abstractmethod
    def save_incident(self, incident: Incident) -> None:
        """Save an incident."""
        pass

    @abstractmethod
    def append_timeline(
        self,
        ts: datetime,
        message: str,
        level: str,
        source: str,
        module: str,
        alert_id: str | None = None,
        incident_id: str | None = None,
    ) -> None:
        """Append an entry to the timeline."""
        pass

    @abstractmethod
    def load_recent_alerts(self, limit: int = 500) -> list[AlertEvent]:
        """Load recent alerts."""
        pass

    @abstractmethod
    def load_open_incidents(self) -> list[Incident]:
        """Load open incidents."""
        pass

    @abstractmethod
    def update_ack(self, alert_id: str, acked: bool) -> None:
        """Update acknowledgement status of an alert."""
        pass

    @abstractmethod
    def set_suppressed(self, alert_id: str, suppressed: bool) -> None:
        """Set suppression status of an alert."""
        pass


class SQLiteStorage(Storage):
    """SQLite-based storage backend."""

    def __init__(self, db_path: str | Path):
        """
        Initialize SQLite storage.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None

    def _get_connection(self) -> sqlite3.Connection:
        """Get or create database connection."""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
            self._conn.row_factory = sqlite3.Row
        return self._conn

    def init(self) -> None:
        """Initialize database schema."""
        conn = self._get_connection()
        cursor = conn.cursor()

        # Alerts table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                ts TEXT NOT NULL,
                severity TEXT NOT NULL,
                module TEXT NOT NULL,
                title TEXT NOT NULL,
                source TEXT NOT NULL,
                evidence_json TEXT NOT NULL,
                mitre_json TEXT NOT NULL,
                rba INTEGER,
                entities_json TEXT NOT NULL,
                acked INTEGER NOT NULL DEFAULT 0,
                suppressed INTEGER NOT NULL DEFAULT 0,
                incident_id TEXT
            )
        """
        )

        # Incidents table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS incidents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                status TEXT NOT NULL,
                created_ts TEXT NOT NULL,
                updated_ts TEXT NOT NULL,
                severity_max TEXT NOT NULL,
                rba_max INTEGER,
                entity_summary_json TEXT NOT NULL,
                alert_count INTEGER NOT NULL DEFAULT 0,
                notes TEXT
            )
        """
        )

        # Timeline table
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS timeline (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                message TEXT NOT NULL,
                level TEXT NOT NULL,
                source TEXT NOT NULL,
                module TEXT NOT NULL,
                alert_id TEXT,
                incident_id TEXT
            )
        """
        )

        # Indexes
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_alerts_incident ON alerts(incident_id)")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_timeline_ts ON timeline(ts)")

        conn.commit()

    def save_alert(self, event: AlertEvent) -> None:
        """Save an alert event."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO alerts
            (id, ts, severity, module, title, source, evidence_json, mitre_json, rba, entities_json, acked, suppressed, incident_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                event.id,
                event.timestamp.isoformat(),
                event.severity,
                event.module,
                event.title,
                event.source,
                json.dumps(event.evidence),
                json.dumps(event.mitre_ids),
                event.rba_score,
                json.dumps(event.entity_keys),
                1 if event.acked else 0,
                1 if event.suppressed else 0,
                event.incident_id,
            ),
        )

        conn.commit()

    def save_incident(self, incident: Incident) -> None:
        """Save an incident."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT OR REPLACE INTO incidents
            (id, title, status, created_ts, updated_ts, severity_max, rba_max, entity_summary_json, alert_count, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
            (
                incident.id,
                incident.title,
                incident.status,
                incident.created_ts.isoformat(),
                incident.updated_ts.isoformat(),
                incident.severity_max,
                incident.rba_max,
                json.dumps(incident.entity_summary),
                incident.alert_count,
                incident.notes,
            ),
        )

        conn.commit()

    def append_timeline(
        self,
        ts: datetime,
        message: str,
        level: str,
        source: str,
        module: str,
        alert_id: str | None = None,
        incident_id: str | None = None,
    ) -> None:
        """Append an entry to the timeline."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            INSERT INTO timeline (ts, message, level, source, module, alert_id, incident_id)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (
                ts.isoformat(),
                message,
                level,
                source,
                module,
                alert_id,
                incident_id,
            ),
        )

        conn.commit()

    def load_recent_alerts(self, limit: int = 500) -> list[AlertEvent]:
        """Load recent alerts."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM alerts
            ORDER BY ts DESC
            LIMIT ?
        """,
            (limit,),
        )

        events = []
        for row in cursor.fetchall():
            try:
                event = AlertEvent(
                    id=row["id"],
                    timestamp=datetime.fromisoformat(row["ts"]),
                    severity=row["severity"],
                    module=row["module"],
                    title=row["title"],
                    source=row["source"],
                    evidence=json.loads(row["evidence_json"]),
                    mitre_ids=json.loads(row["mitre_json"]),
                    rba_score=row["rba"],
                    entity_keys=json.loads(row["entities_json"]),
                    acked=bool(row["acked"]),
                    suppressed=bool(row["suppressed"]),
                    incident_id=row["incident_id"],
                )
                events.append(event)
            except Exception:
                continue  # Skip malformed rows

        return events

    def load_open_incidents(self) -> list[Incident]:
        """Load open incidents."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM incidents
            WHERE status = 'open'
            ORDER BY updated_ts DESC
        """
        )

        incidents = []
        for row in cursor.fetchall():
            try:
                incident = Incident(
                    id=row["id"],
                    title=row["title"],
                    status=row["status"],
                    created_ts=datetime.fromisoformat(row["created_ts"]),
                    updated_ts=datetime.fromisoformat(row["updated_ts"]),
                    severity_max=row["severity_max"],
                    rba_max=row["rba_max"],
                    entity_summary=json.loads(row["entity_summary_json"]),
                    alert_count=row["alert_count"],
                    notes=row["notes"],
                )
                incidents.append(incident)
            except Exception:
                continue  # Skip malformed rows

        return incidents

    def load_all_incidents(self) -> list[Incident]:
        """Load all incidents."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            """
            SELECT * FROM incidents
            ORDER BY updated_ts DESC
        """
        )

        incidents = []
        for row in cursor.fetchall():
            try:
                incident = Incident(
                    id=row["id"],
                    title=row["title"],
                    status=row["status"],
                    created_ts=datetime.fromisoformat(row["created_ts"]),
                    updated_ts=datetime.fromisoformat(row["updated_ts"]),
                    severity_max=row["severity_max"],
                    rba_max=row["rba_max"],
                    entity_summary=json.loads(row["entity_summary_json"]),
                    alert_count=row["alert_count"],
                    notes=row["notes"],
                )
                incidents.append(incident)
            except Exception:
                continue

        return incidents

    def update_ack(self, alert_id: str, acked: bool) -> None:
        """Update acknowledgement status of an alert."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE alerts SET acked = ? WHERE id = ?",
            (1 if acked else 0, alert_id),
        )

        conn.commit()

    def set_suppressed(self, alert_id: str, suppressed: bool) -> None:
        """Set suppression status of an alert."""
        conn = self._get_connection()
        cursor = conn.cursor()

        cursor.execute(
            "UPDATE alerts SET suppressed = ? WHERE id = ?",
            (1 if suppressed else 0, alert_id),
        )

        conn.commit()

    def close(self) -> None:
        """Close the database connection."""
        if self._conn:
            self._conn.close()
            self._conn = None


class JSONStorage(Storage):
    """JSON-based storage backend (fallback)."""

    def __init__(self, json_path: str | Path):
        """
        Initialize JSON storage.

        Args:
            json_path: Path to the JSON storage file.
        """
        self.json_path = Path(json_path)
        self.json_path.parent.mkdir(parents=True, exist_ok=True)
        self._data: dict[str, Any] = {}

    def init(self) -> None:
        """Initialize JSON storage (load existing if present)."""
        if self.json_path.exists():
            try:
                with self.json_path.open("r", encoding="utf-8") as f:
                    self._data = json.load(f)
            except Exception:
                self._data = {}

        if "alerts" not in self._data:
            self._data["alerts"] = []
        if "incidents" not in self._data:
            self._data["incidents"] = []
        if "timeline" not in self._data:
            self._data["timeline"] = []

    def _save(self) -> None:
        """Save data to JSON file."""
        with self.json_path.open("w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, default=str)

    def save_alert(self, event: AlertEvent) -> None:
        """Save an alert event."""
        # Remove existing if present
        self._data["alerts"] = [
            a for a in self._data["alerts"] if a.get("id") != event.id
        ]
        # Add new
        self._data["alerts"].append(event.to_dict())
        self._save()

    def save_incident(self, incident: Incident) -> None:
        """Save an incident."""
        # Remove existing if present
        self._data["incidents"] = [
            i for i in self._data["incidents"] if i.get("id") != incident.id
        ]
        # Add new
        self._data["incidents"].append(incident.to_dict())
        self._save()

    def append_timeline(
        self,
        ts: datetime,
        message: str,
        level: str,
        source: str,
        module: str,
        alert_id: str | None = None,
        incident_id: str | None = None,
    ) -> None:
        """Append an entry to the timeline."""
        entry = {
            "ts": ts.isoformat(),
            "message": message,
            "level": level,
            "source": source,
            "module": module,
            "alert_id": alert_id,
            "incident_id": incident_id,
        }
        self._data["timeline"].append(entry)
        # Keep only last 1000 entries
        if len(self._data["timeline"]) > 1000:
            self._data["timeline"] = self._data["timeline"][-1000:]
        self._save()

    def load_recent_alerts(self, limit: int = 500) -> list[AlertEvent]:
        """Load recent alerts."""
        alerts = self._data.get("alerts", [])
        # Sort by timestamp descending
        alerts.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
        return [AlertEvent.from_dict(a) for a in alerts[:limit]]

    def load_open_incidents(self) -> list[Incident]:
        """Load open incidents."""
        incidents = self._data.get("incidents", [])
        open_incidents = [i for i in incidents if i.get("status") == "open"]
        return [Incident.from_dict(i) for i in open_incidents]

    def load_all_incidents(self) -> list[Incident]:
        """Load all incidents."""
        incidents = self._data.get("incidents", [])
        return [Incident.from_dict(i) for i in incidents]

    def update_ack(self, alert_id: str, acked: bool) -> None:
        """Update acknowledgement status of an alert."""
        for alert in self._data.get("alerts", []):
            if alert.get("id") == alert_id:
                alert["acked"] = acked
                self._save()
                break

    def set_suppressed(self, alert_id: str, suppressed: bool) -> None:
        """Set suppression status of an alert."""
        for alert in self._data.get("alerts", []):
            if alert.get("id") == alert_id:
                alert["suppressed"] = suppressed
                self._save()
                break
